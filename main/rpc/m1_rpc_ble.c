/**
 * M1 RPC — BLE handler.
 *
 * Provides a small dedicated NimBLE control path for binary RPC commands while
 * reusing the custom HID service implementation already present in this tree.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "m1_rpc.h"
#include "m1_rpc_ble.h"
#include "m1_rpc_proto.h"

#include "at_custom_hid_cmd.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "host/ble_hs_adv.h"
#include "host/ble_store.h"
#include "host/ble_uuid.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"

static const char *TAG = "M1_BLE";

#define BLE_SCAN_MAX_RESULTS 16
#define BLE_SCAN_NAME_MAX    31

typedef struct {
    uint8_t addr[6];
    uint8_t addr_type;
    int8_t rssi;
    uint8_t name_len;
    uint8_t name[BLE_SCAN_NAME_MAX];
} ble_scan_result_t;

static bool s_ble_started = false;
static bool s_ble_synced = false;
static uint8_t s_ble_addr_type = BLE_OWN_ADDR_PUBLIC;
static uint8_t s_ble_mode = 0;
static bool s_ble_scan_active = false;
static bool s_ble_adv_active = false;
static uint16_t s_ble_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static ble_scan_result_t s_ble_scan_results[BLE_SCAN_MAX_RESULTS];
static uint16_t s_ble_scan_count = 0;
static char s_adv_name[BLE_SCAN_NAME_MAX + 1] = "M1-BLE";

void ble_store_config_init(void);

static int ble_gap_event_cb(struct ble_gap_event *event, void *arg);

static void ble_host_task(void *param)
{
    (void)param;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static m1_status_t ble_status_from_err(esp_err_t err)
{
    switch (err) {
    case ESP_OK:
        return M1_OK;
    case ESP_ERR_INVALID_ARG:
        return M1_ERR_INVALID_ARGS;
    case ESP_ERR_INVALID_STATE:
        return M1_ERR_NOT_INIT;
    case ESP_ERR_NO_MEM:
        return M1_ERR_NO_MEM;
    case ESP_ERR_TIMEOUT:
        return M1_ERR_TIMEOUT;
    default:
        return M1_ERR_HARDWARE;
    }
}

static void ble_scan_results_reset(void)
{
    s_ble_scan_count = 0;
    memset(s_ble_scan_results, 0, sizeof(s_ble_scan_results));
}

static void ble_send_scan_event(const ble_scan_result_t *result)
{
    uint8_t evt[6 + 1 + 1 + 1 + BLE_SCAN_NAME_MAX];
    uint16_t evt_len = 0;

    memcpy(evt + evt_len, result->addr, sizeof(result->addr));
    evt_len += sizeof(result->addr);
    evt[evt_len++] = result->addr_type;
    evt[evt_len++] = (uint8_t)result->rssi;
    evt[evt_len++] = result->name_len;
    if (result->name_len > 0) {
        memcpy(evt + evt_len, result->name, result->name_len);
        evt_len += result->name_len;
    }

    m1_rpc_send_event(M1_EVT_BLE_SCAN_RESULT, evt, evt_len);
}

static void ble_store_scan_result(const struct ble_gap_disc_desc *disc)
{
    struct ble_hs_adv_fields fields;
    ble_scan_result_t result = {0};
    int idx = -1;

    memcpy(result.addr, disc->addr.val, sizeof(result.addr));
    result.addr_type = disc->addr.type;
    result.rssi = disc->rssi;

    if (ble_hs_adv_parse_fields(&fields, disc->data, disc->length_data) == 0 &&
        fields.name && fields.name_len > 0) {
        result.name_len = fields.name_len > BLE_SCAN_NAME_MAX
            ? BLE_SCAN_NAME_MAX
            : fields.name_len;
        memcpy(result.name, fields.name, result.name_len);
    }

    for (uint16_t i = 0; i < s_ble_scan_count; i++) {
        if (memcmp(s_ble_scan_results[i].addr, result.addr, sizeof(result.addr)) == 0 &&
            s_ble_scan_results[i].addr_type == result.addr_type) {
            idx = (int)i;
            break;
        }
    }

    if (idx < 0) {
        if (s_ble_scan_count >= BLE_SCAN_MAX_RESULTS) {
            return;
        }
        idx = (int)s_ble_scan_count++;
    }

    s_ble_scan_results[idx] = result;
    ble_send_scan_event(&s_ble_scan_results[idx]);
}

static void ble_advertise_start_locked(void)
{
    struct ble_gap_adv_params adv_params = {0};
    struct ble_hs_adv_fields fields = {0};
    ble_uuid16_t hid_uuid = BLE_UUID16_INIT(0x1812);
    int rc;

    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.tx_pwr_lvl_is_present = 1;
    fields.tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;
    fields.name = (uint8_t *)s_adv_name;
    fields.name_len = strlen(s_adv_name);
    fields.name_is_complete = 1;

    if (m1_ble_hid_is_ready()) {
        fields.uuids16 = &hid_uuid;
        fields.num_uuids16 = 1;
        fields.uuids16_is_complete = 1;
    }

    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: %d", rc);
        return;
    }

    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    rc = ble_gap_adv_start(s_ble_addr_type, NULL, BLE_HS_FOREVER, &adv_params,
                           ble_gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_start failed: %d", rc);
        return;
    }

    s_ble_adv_active = true;
}

static int ble_gap_event_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;

    switch (event->type) {
    case BLE_GAP_EVENT_DISC:
        ble_store_scan_result(&event->disc);
        return 0;
    case BLE_GAP_EVENT_DISC_COMPLETE:
        s_ble_scan_active = false;
        return 0;
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_ble_conn_handle = event->connect.conn_handle;
        } else {
            s_ble_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        }
        return 0;
    case BLE_GAP_EVENT_DISCONNECT:
        s_ble_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        return 0;
    case BLE_GAP_EVENT_ADV_COMPLETE:
        s_ble_adv_active = false;
        return 0;
    default:
        return 0;
    }
}

static void ble_on_sync(void)
{
    int rc = ble_hs_id_infer_auto(0, &s_ble_addr_type);
    if (rc == 0) {
        s_ble_synced = true;
    }
}

static void ble_on_reset(int reason)
{
    ESP_LOGW(TAG, "BLE reset; reason=%d", reason);
    s_ble_synced = false;
    s_ble_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    s_ble_scan_active = false;
    s_ble_adv_active = false;
}

static m1_status_t ensure_ble_ready(void)
{
    int waited_ms = 0;

    if (ble_hs_is_enabled() && ble_hs_synced()) {
        ble_hs_id_infer_auto(0, &s_ble_addr_type);
        s_ble_started = true;
        s_ble_synced = true;
        return M1_OK;
    }

    if (!s_ble_started) {
        esp_err_t err = nimble_port_init();
        if (err != ESP_OK) {
            if (!ble_hs_is_enabled()) {
                ESP_LOGE(TAG, "nimble_port_init failed: %s", esp_err_to_name(err));
                return ble_status_from_err(err);
            }
        } else {
            ble_hs_cfg.reset_cb = ble_on_reset;
            ble_hs_cfg.sync_cb = ble_on_sync;
            ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
            ble_store_config_init();
            ble_svc_gap_device_name_set(s_adv_name);
            nimble_port_freertos_init(ble_host_task);
        }
        s_ble_started = true;
    }

    while (!ble_hs_synced() && waited_ms < 5000) {
        vTaskDelay(pdMS_TO_TICKS(50));
        waited_ms += 50;
    }

    if (!ble_hs_synced()) {
        return M1_ERR_TIMEOUT;
    }

    s_ble_synced = true;
    ble_hs_id_infer_auto(0, &s_ble_addr_type);
    return M1_OK;
}

static m1_status_t cmd_ble_init(const uint8_t *payload, uint16_t len)
{
    if (len < 1) {
        return M1_ERR_INVALID_ARGS;
    }

    if (payload[0] == 0) {
        if (s_ble_scan_active) {
            ble_gap_disc_cancel();
            s_ble_scan_active = false;
        }
        if (s_ble_adv_active) {
            ble_gap_adv_stop();
            s_ble_adv_active = false;
        }
        if (s_ble_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
            ble_gap_terminate(s_ble_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            s_ble_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        }
        s_ble_mode = 0;
        return M1_OK;
    }

    m1_status_t status = ensure_ble_ready();
    if (status != M1_OK) {
        return status;
    }

    s_ble_mode = payload[0];
    return M1_OK;
}

static m1_status_t cmd_ble_scan_start(const uint8_t *payload, uint16_t len)
{
    uint8_t duration_sec = 5;
    struct ble_gap_disc_params params = {0};
    int rc;

    if (len >= 1 && payload[0] != 0) {
        duration_sec = payload[0];
    }

    m1_status_t status = ensure_ble_ready();
    if (status != M1_OK) {
        return status;
    }
    if (s_ble_scan_active) {
        return M1_ERR_ALREADY_RUNNING;
    }

    ble_scan_results_reset();
    params.filter_duplicates = 1;
    params.passive = 0;

    rc = ble_gap_disc(s_ble_addr_type, (int32_t)duration_sec * 1000, &params,
                      ble_gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_disc failed: %d", rc);
        return M1_ERR_HARDWARE;
    }

    s_ble_scan_active = true;
    return M1_ERR_PENDING;
}

static m1_status_t cmd_ble_scan_results(uint8_t *resp, uint16_t *resp_len)
{
    uint16_t total = 2;

    for (uint16_t i = 0; i < s_ble_scan_count; i++) {
        total += 6 + 1 + 1 + 1 + s_ble_scan_results[i].name_len;
        if (total > M1_RPC_MAX_PAYLOAD) {
            return M1_ERR_NO_MEM;
        }
    }

    resp[0] = (uint8_t)(s_ble_scan_count & 0xFF);
    resp[1] = (uint8_t)(s_ble_scan_count >> 8);
    total = 2;

    for (uint16_t i = 0; i < s_ble_scan_count; i++) {
        const ble_scan_result_t *result = &s_ble_scan_results[i];
        memcpy(resp + total, result->addr, sizeof(result->addr));
        total += sizeof(result->addr);
        resp[total++] = result->addr_type;
        resp[total++] = (uint8_t)result->rssi;
        resp[total++] = result->name_len;
        if (result->name_len > 0) {
            memcpy(resp + total, result->name, result->name_len);
            total += result->name_len;
        }
    }

    *resp_len = total;
    return M1_OK;
}

static m1_status_t cmd_ble_adv_start(const uint8_t *payload, uint16_t len)
{
    m1_status_t status = ensure_ble_ready();
    if (status != M1_OK) {
        return status;
    }

    if (len > 0) {
        uint8_t name_len = payload[0];
        if ((uint16_t)name_len + 1 > len) {
            return M1_ERR_INVALID_ARGS;
        }
        if (name_len > BLE_SCAN_NAME_MAX) {
            name_len = BLE_SCAN_NAME_MAX;
        }
        memcpy(s_adv_name, payload + 1, name_len);
        s_adv_name[name_len] = '\0';
        ble_svc_gap_device_name_set(s_adv_name);
    }

    if (s_ble_adv_active) {
        return M1_ERR_ALREADY_RUNNING;
    }

    ble_advertise_start_locked();
    return s_ble_adv_active ? M1_OK : M1_ERR_HARDWARE;
}

static m1_status_t cmd_ble_adv_stop(void)
{
    if (!s_ble_adv_active) {
        return M1_ERR_NOT_RUNNING;
    }
    return (ble_gap_adv_stop() == 0) ? M1_OK : M1_ERR_HARDWARE;
}

static m1_status_t cmd_ble_hid_init(const uint8_t *payload, uint16_t len)
{
    if (len < 1) {
        return M1_ERR_INVALID_ARGS;
    }

    m1_status_t status = ensure_ble_ready();
    if (status != M1_OK) {
        return status;
    }

    return ble_status_from_err(m1_ble_hid_init(payload[0] != 0));
}

static m1_status_t cmd_ble_hid_keypress(const uint8_t *payload, uint16_t len)
{
    uint8_t key_count;
    if (len < 2) {
        return M1_ERR_INVALID_ARGS;
    }

    key_count = payload[1];
    if ((uint16_t)key_count + 2 > len || key_count > 6) {
        return M1_ERR_INVALID_ARGS;
    }

    return ble_status_from_err(
        m1_ble_hid_send_keyboard_report(payload[0], payload + 2, key_count));
}

static m1_status_t cmd_ble_connect(const uint8_t *payload, uint16_t len)
{
    ble_addr_t peer_addr;
    int rc;

    if (len < 7) {
        return M1_ERR_INVALID_ARGS;
    }

    m1_status_t status = ensure_ble_ready();
    if (status != M1_OK) {
        return status;
    }

    if (s_ble_scan_active) {
        ble_gap_disc_cancel();
        s_ble_scan_active = false;
    }

    peer_addr.type = payload[6];
    memcpy(peer_addr.val, payload, 6);
    rc = ble_gap_connect(s_ble_addr_type, &peer_addr, 30000, NULL,
                         ble_gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_connect failed: %d", rc);
        return M1_ERR_HARDWARE;
    }

    return M1_ERR_PENDING;
}

static m1_status_t cmd_ble_disconnect(const uint8_t *payload, uint16_t len)
{
    struct ble_gap_conn_desc desc;

    if (s_ble_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        return (ble_gap_terminate(s_ble_conn_handle, BLE_ERR_REM_USER_CONN_TERM) == 0)
            ? M1_OK
            : M1_ERR_HARDWARE;
    }

    if (len < 6) {
        return M1_ERR_INVALID_ARGS;
    }

    for (uint16_t handle = 0; handle < CONFIG_BT_NIMBLE_MAX_CONNECTIONS; handle++) {
        if (ble_gap_conn_find(handle, &desc) == 0 &&
            memcmp(desc.peer_ota_addr.val, payload, 6) == 0) {
            return (ble_gap_terminate(handle, BLE_ERR_REM_USER_CONN_TERM) == 0)
                ? M1_OK
                : M1_ERR_HARDWARE;
        }
    }

    return M1_ERR_NOT_RUNNING;
}

m1_status_t m1_rpc_ble_handler(uint16_t msg_id,
                               const uint8_t *payload,
                               uint16_t payload_len,
                               uint8_t *resp_buf,
                               uint16_t *resp_len)
{
    switch (msg_id) {
    case M1_MSG_BLE_INIT:
        *resp_len = 0;
        return cmd_ble_init(payload, payload_len);
    case M1_MSG_BLE_SCAN_START:
        *resp_len = 0;
        return cmd_ble_scan_start(payload, payload_len);
    case M1_MSG_BLE_SCAN_RESULTS:
        return cmd_ble_scan_results(resp_buf, resp_len);
    case M1_MSG_BLE_ADV_START:
        *resp_len = 0;
        return cmd_ble_adv_start(payload, payload_len);
    case M1_MSG_BLE_ADV_STOP:
        *resp_len = 0;
        return cmd_ble_adv_stop();
    case M1_MSG_BLE_HID_INIT:
        *resp_len = 0;
        return cmd_ble_hid_init(payload, payload_len);
    case M1_MSG_BLE_HID_KEYPRESS:
        *resp_len = 0;
        return cmd_ble_hid_keypress(payload, payload_len);
    case M1_MSG_BLE_CONNECT:
        *resp_len = 0;
        return cmd_ble_connect(payload, payload_len);
    case M1_MSG_BLE_DISCONNECT:
        *resp_len = 0;
        return cmd_ble_disconnect(payload, payload_len);
    default:
        *resp_len = 0;
        return M1_ERR_UNSUPPORTED;
    }
}
