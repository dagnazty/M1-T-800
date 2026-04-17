/**
 * M1 RPC — WiFi STA + SoftAP command handler.
 *
 * Implements message IDs 0x0100–0x01FF (STA) and 0x0200–0x02FF (SoftAP).
 * Ported from the AT command set; binary params replace ASCII strings.
 */

#include <string.h>
#include "m1_rpc.h"
#include "m1_rpc_proto.h"
#include "m1_rpc_wifi.h"

#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

static const char *TAG = "M1_WiFi";

/* ── WiFi event bits ───────────────────────────────────────────── */

#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT        BIT1

static EventGroupHandle_t s_wifi_event_group;
static bool s_wifi_initialized = false;
static int s_retry_count = 0;
#define MAX_RETRY 5

/* ── WiFi event handler ───────────────────────────────────────── */

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
        case WIFI_EVENT_STA_START:
            esp_wifi_connect();
            break;
        case WIFI_EVENT_STA_CONNECTED:
            break;
        case WIFI_EVENT_STA_DISCONNECTED:
            s_retry_count++;
            if (s_retry_count < MAX_RETRY) {
                esp_wifi_connect();
            } else {
                if (s_wifi_event_group) {
                    xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
                }
            }
            /* Notify STM32 */
            m1_rpc_send_event(M1_EVT_WIFI_DISCONNECTED, NULL, 0);
            break;
        case WIFI_EVENT_AP_STACONNECTED: {
            wifi_event_ap_staconnected_t *ev = event_data;
            uint8_t evt[7];
            memcpy(evt, ev->mac, 6);
            evt[6] = ev->aid & 0xFF;
            m1_rpc_send_event(M1_EVT_STA_CONNECTED, evt, 7);
            break;
        }
        case WIFI_EVENT_AP_STADISCONNECTED: {
            wifi_event_ap_stadisconnected_t *ev = event_data;
            uint8_t evt[7];
            memcpy(evt, ev->mac, 6);
            evt[6] = ev->aid & 0xFF;
            m1_rpc_send_event(M1_EVT_STA_DISCONNECTED, evt, 7);
            break;
        }
        default:
            break;
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = event_data;
        uint8_t evt[4];
        memcpy(evt, &ev->ip_info.ip, 4);
        m1_rpc_send_event(M1_EVT_WIFI_CONNECTED, evt, 4);
        s_retry_count = 0;
        if (s_wifi_event_group) {
            xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        }
    }
}

/* ── Ensure WiFi is initialized ───────────────────────────────── */

static m1_status_t ensure_wifi_init(void)
{
    if (s_wifi_initialized) return M1_OK;

    esp_netif_create_default_wifi_sta();
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t err = esp_wifi_init(&cfg);
    if (err != ESP_OK) return M1_ERR_HARDWARE;

    esp_wifi_set_mode(WIFI_MODE_STA);

    s_wifi_event_group = xEventGroupCreate();
    if (!s_wifi_event_group) return M1_ERR_NO_MEM;

    esp_event_handler_instance_t inst_wifi, inst_ip;
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                         &wifi_event_handler, NULL, &inst_wifi);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                         &wifi_event_handler, NULL, &inst_ip);

    s_wifi_initialized = true;
    return M1_OK;
}

/* ── STA commands ─────────────────────────────────────────────── */

/**
 * 0x0100 WIFI_GET_MODE
 * Response: 1 byte wifi_mode_t
 */
static m1_status_t cmd_wifi_get_mode(const uint8_t *payload, uint16_t len,
                                      uint8_t *resp, uint16_t *resp_len)
{
    wifi_mode_t mode;
    esp_err_t err = esp_wifi_get_mode(&mode);
    if (err != ESP_OK) return M1_ERR_HARDWARE;
    resp[0] = (uint8_t)mode;
    *resp_len = 1;
    return M1_OK;
}

/**
 * 0x0101 WIFI_SET_MODE
 * Payload: 1 byte wifi_mode_t
 */
static m1_status_t cmd_wifi_set_mode(const uint8_t *payload, uint16_t len,
                                      uint8_t *resp, uint16_t *resp_len)
{
    if (len < 1) return M1_ERR_INVALID_ARGS;
    m1_status_t init_err = ensure_wifi_init();
    if (init_err != M1_OK) return init_err;

    wifi_mode_t mode = (wifi_mode_t)payload[0];
    esp_err_t err = esp_wifi_set_mode(mode);
    if (err != ESP_OK) return M1_ERR_HARDWARE;
    err = esp_wifi_start();
    if (err != ESP_OK) return M1_ERR_HARDWARE;
    return M1_OK;
}

/**
 * 0x0102 WIFI_GET_MAC
 * Payload: 1 byte interface (0=STA, 1=AP)
 * Response: 6 bytes MAC
 */
static m1_status_t cmd_wifi_get_mac(const uint8_t *payload, uint16_t len,
                                     uint8_t *resp, uint16_t *resp_len)
{
    if (len < 1) return M1_ERR_INVALID_ARGS;
    m1_status_t init_err = ensure_wifi_init();
    if (init_err != M1_OK) return init_err;

    wifi_interface_t ifx = (payload[0] == 1) ? WIFI_IF_AP : WIFI_IF_STA;
    esp_err_t err = esp_wifi_get_mac(ifx, resp);
    if (err != ESP_OK) return M1_ERR_HARDWARE;
    *resp_len = 6;
    return M1_OK;
}

/**
 * 0x0103 WIFI_SCAN
 * No payload needed (blocking scan).
 * Sends M1_EVT_WIFI_SCAN_DONE on completion with count.
 * Response: 2 bytes (number of APs found, LE)
 */
static m1_status_t cmd_wifi_scan(const uint8_t *payload, uint16_t len,
                                  uint8_t *resp, uint16_t *resp_len)
{
    m1_status_t init_err = ensure_wifi_init();
    if (init_err != M1_OK) return init_err;

    /* Make sure STA mode is active */
    wifi_mode_t cur_mode;
    esp_wifi_get_mode(&cur_mode);
    if (cur_mode == WIFI_MODE_AP) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        esp_wifi_start();
    }

    esp_err_t err = esp_wifi_scan_start(NULL, true); /* blocking */
    if (err != ESP_OK) return M1_ERR_HARDWARE;

    uint16_t ap_count = 0;
    esp_wifi_scan_get_ap_num(&ap_count);

    resp[0] = ap_count & 0xFF;
    resp[1] = (ap_count >> 8) & 0xFF;
    *resp_len = 2;

    /* Send scan-done event */
    m1_rpc_send_event(M1_EVT_WIFI_SCAN_DONE, resp, 2);

    return M1_OK;
}

/**
 * 0x0104 WIFI_CONNECT
 * Payload: [1 byte ssid_len][ssid][1 byte pass_len][password]
 * Response blocks until connected or timeout.
 */
static m1_status_t cmd_wifi_connect(const uint8_t *payload, uint16_t len,
                                     uint8_t *resp, uint16_t *resp_len)
{
    if (len < 2) return M1_ERR_INVALID_ARGS;
    m1_status_t init_err = ensure_wifi_init();
    if (init_err != M1_OK) return init_err;

    uint8_t ssid_len = payload[0];
    if (1 + ssid_len >= len) return M1_ERR_INVALID_ARGS;
    uint8_t pass_len = payload[1 + ssid_len];

    char ssid[33] = {0};
    char pass[65] = {0};

    if (ssid_len > 32 || pass_len > 64) return M1_ERR_INVALID_ARGS;
    if (1 + ssid_len + 1 + pass_len > len) return M1_ERR_INVALID_ARGS;

    memcpy(ssid, payload + 1, ssid_len);
    if (pass_len > 0) {
        memcpy(pass, payload + 1 + ssid_len + 1, pass_len);
    }

    wifi_config_t cfg = {0};
    memcpy((char *)cfg.sta.ssid, ssid, ssid_len);
    memcpy((char *)cfg.sta.password, pass, pass_len);

    /* Ensure STA mode */
    wifi_mode_t cur_mode;
    esp_wifi_get_mode(&cur_mode);
    if (cur_mode == WIFI_MODE_AP) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
    }

    esp_wifi_set_config(WIFI_IF_STA, &cfg);
    esp_wifi_start();

    s_retry_count = 0;
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                            pdFALSE, pdFALSE,
                                            pdMS_TO_TICKS(15000));

    if (bits & WIFI_CONNECTED_BIT) {
        return M1_OK;
    }
    return M1_ERR_TIMEOUT;
}

/**
 * 0x0105 WIFI_DISCONNECT
 */
static m1_status_t cmd_wifi_disconnect(const uint8_t *payload, uint16_t len,
                                       uint8_t *resp, uint16_t *resp_len)
{
    esp_err_t err = esp_wifi_disconnect();
    return (err == ESP_OK) ? M1_OK : M1_ERR_HARDWARE;
}

/**
 * 0x0106 WIFI_GET_STATUS
 * Response: 1 byte status (0=disconnected, 1=connecting, 2=connected, 3=got_ip)
 */
static m1_status_t cmd_wifi_get_status(const uint8_t *payload, uint16_t len,
                                       uint8_t *resp, uint16_t *resp_len)
{
    if (!s_wifi_initialized) {
        resp[0] = 0;
        *resp_len = 1;
        return M1_OK;
    }

    wifi_mode_t mode;
    if (esp_wifi_get_mode(&mode) != ESP_OK) {
        resp[0] = 0;
        *resp_len = 1;
        return M1_OK;
    }

    /* Check if STA is active in mode */
    if (mode == WIFI_MODE_AP) {
        resp[0] = 0; /* AP-only, no STA */
        *resp_len = 1;
        return M1_OK;
    }

    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            resp[0] = 3; /* got IP */
            *resp_len = 1;
            return M1_OK;
        }
    }

    wifi_ap_record_t ap;
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        resp[0] = 2; /* connected */
    } else {
        resp[0] = 0; /* disconnected */
    }
    *resp_len = 1;
    return M1_OK;
}

/* ── SoftAP commands ──────────────────────────────────────────── */

/**
 * 0x0200 SOFTAP_START
 * Payload: [1 byte ssid_len][ssid][1 byte pass_len][password][1 byte channel][1 byte auth_mode][1 byte max_conn]
 *   auth_mode: 0=OPEN, 1=WPA2_PSK, etc. (wifi_auth_mode_t)
 *   max_conn: max stations (default 4)
 */
static m1_status_t cmd_softap_start(const uint8_t *payload, uint16_t len,
                                     uint8_t *resp, uint16_t *resp_len)
{
    if (len < 3) return M1_ERR_INVALID_ARGS;
    m1_status_t init_err = ensure_wifi_init();
    if (init_err != M1_OK) return init_err;

    uint8_t ssid_len = payload[0];
    if (1 + ssid_len >= len) return M1_ERR_INVALID_ARGS;
    uint8_t pass_len = payload[1 + ssid_len];
    uint8_t header_size = 1 + ssid_len + 1 + pass_len;

    if (header_size > len) return M1_ERR_INVALID_ARGS;
    if (ssid_len > 32 || pass_len > 64) return M1_ERR_INVALID_ARGS;

    char ssid[33] = {0};
    char pass[65] = {0};
    memcpy(ssid, payload + 1, ssid_len);
    if (pass_len > 0) {
        memcpy(pass, payload + 1 + ssid_len + 1, pass_len);
    }

    uint8_t channel = 1;
    wifi_auth_mode_t auth = WIFI_AUTH_WPA2_PSK;
    uint8_t max_conn = 4;

    if (header_size < len) channel = payload[header_size];
    if (header_size + 1 < len) auth = (wifi_auth_mode_t)payload[header_size + 1];
    if (header_size + 2 < len) max_conn = payload[header_size + 2];

    if (pass_len == 0) auth = WIFI_AUTH_OPEN;

    wifi_config_t cfg = {0};
    memcpy((char *)cfg.ap.ssid, ssid, ssid_len);
    cfg.ap.ssid_len = ssid_len;
    if (pass_len > 0) {
        memcpy((char *)cfg.ap.password, pass, pass_len);
    }
    cfg.ap.channel = channel;
    cfg.ap.authmode = auth;
    cfg.ap.max_connection = max_conn;

    /* Ensure AP mode */
    wifi_mode_t cur_mode;
    esp_wifi_get_mode(&cur_mode);
    if (cur_mode == WIFI_MODE_STA) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
    } else if (cur_mode == WIFI_MODE_NULL) {
        esp_wifi_set_mode(WIFI_MODE_AP);
    }

    esp_wifi_set_config(WIFI_IF_AP, &cfg);
    esp_err_t err = esp_wifi_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "SoftAP start failed: %s", esp_err_to_name(err));
        return M1_ERR_HARDWARE;
    }

    return M1_OK;
}

/**
 * 0x0201 SOFTAP_STOP
 */
static m1_status_t cmd_softap_stop(const uint8_t *payload, uint16_t len,
                                    uint8_t *resp, uint16_t *resp_len)
{
    wifi_mode_t cur_mode;
    esp_wifi_get_mode(&cur_mode);

    if (cur_mode == WIFI_MODE_AP) {
        esp_wifi_set_mode(WIFI_MODE_NULL);
    } else if (cur_mode == WIFI_MODE_APSTA) {
        esp_wifi_set_mode(WIFI_MODE_STA);
    }

    esp_wifi_stop();
    return M1_OK;
}

/**
 * 0x0202 SOFTAP_GET_STA_LIST
 * Response: [1 byte count] then per-station: [6 bytes MAC][1 byte rssi]
 * Max 16 stations (max 113 bytes response).
 */
static m1_status_t cmd_softap_get_sta_list(const uint8_t *payload, uint16_t len,
                                             uint8_t *resp, uint16_t *resp_len)
{
    wifi_sta_list_t sta_list;
    esp_err_t err = esp_wifi_ap_get_sta_list(&sta_list);
    if (err != ESP_OK) return M1_ERR_HARDWARE;

    uint8_t count = (sta_list.num > 16) ? 16 : sta_list.num;
    resp[0] = count;

    for (int i = 0; i < count; i++) {
        memcpy(resp + 1 + i * 7, sta_list.sta[i].mac, 6);
        resp[1 + i * 7 + 6] = sta_list.sta[i].rssi;
    }

    *resp_len = 1 + count * 7;
    return M1_OK;
}

/* ── Combined dispatcher ──────────────────────────────────────── */

m1_status_t m1_rpc_wifi_sta_handler(uint16_t msg_id,
                                      const uint8_t *payload,
                                      uint16_t payload_len,
                                      uint8_t *resp_buf,
                                      uint16_t *resp_len)
{
    switch (msg_id) {
        case M1_MSG_WIFI_GET_MODE:   return cmd_wifi_get_mode(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_WIFI_SET_MODE:   return cmd_wifi_set_mode(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_WIFI_GET_MAC:    return cmd_wifi_get_mac(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_WIFI_SCAN:       return cmd_wifi_scan(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_WIFI_CONNECT:    return cmd_wifi_connect(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_WIFI_DISCONNECT: return cmd_wifi_disconnect(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_WIFI_GET_STATUS: return cmd_wifi_get_status(payload, payload_len, resp_buf, resp_len);
        default:                     return M1_ERR_UNSUPPORTED;
    }
}

m1_status_t m1_rpc_softap_handler(uint16_t msg_id,
                                    const uint8_t *payload,
                                    uint16_t payload_len,
                                    uint8_t *resp_buf,
                                    uint16_t *resp_len)
{
    switch (msg_id) {
        case M1_MSG_SOFTAP_START:        return cmd_softap_start(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_SOFTAP_STOP:         return cmd_softap_stop(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_SOFTAP_GET_STA_LIST: return cmd_softap_get_sta_list(payload, payload_len, resp_buf, resp_len);
        default:                          return M1_ERR_UNSUPPORTED;
    }
}
