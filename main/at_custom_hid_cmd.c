/*
 * at_custom_hid_cmd.c — BLE HID Keyboard AT Commands for ESP32-C6
 *
 * Custom AT commands:
 *   AT+BLEHIDINIT=1  — Register HID GATT service (call after AT+BLEINIT=2)
 *   AT+BLEHIDKB=<mod>,<k1>,...,<k6> — Send keyboard report notification
 *
 * Advertising is handled by stock AT+BLEADVDATAEX from the M1 side.
 * HID GATT service is registered via NimBLE dynamic service API (not CSV)
 * to avoid attribute count limits in the precompiled AT library and to
 * ensure services are visible to remote BLE clients.
 *
 * HID GATT services are registered via ble_gatts_add_dynamic_svcs()
 * (requires CONFIG_BT_NIMBLE_DYNAMIC_SERVICE=y). Called after AT+BLEINIT=2
 * but before advertising starts.
 *
 * Flow:
 *   1. AT+BLEINIT=2
 *   2. AT+HIDKBINIT=1          — dynamically registers DIS+Battery+HID
 *   3. AT+BLEADVDATAEX=...     — advertise with HID UUID 0x1812
 *   4. Host connects, pairs
 *   5. AT+BLEHIDKB=...         — send keystrokes
 */

#include <string.h>
#include <stdio.h>

#include "esp_at.h"
#include "esp_log.h"

#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_uuid.h"
#include "os/os_mbuf.h"

#include "at_custom_hid_cmd.h"
#include "services/gap/ble_svc_gap.h"

#define TAG "HID_KB"

/* ========================================================================
 * HID Data
 * ======================================================================== */

/* Standard keyboard Report Map descriptor (no Report ID) */
static const uint8_t hid_report_map[] = {
    0x05, 0x01,       /* Usage Page (Generic Desktop)       */
    0x09, 0x06,       /* Usage (Keyboard)                   */
    0xA1, 0x01,       /* Collection (Application)           */
    0x05, 0x07,       /*   Usage Page (Key Codes)           */
    0x19, 0xE0,       /*   Usage Min (224 = Left Control)   */
    0x29, 0xE7,       /*   Usage Max (231 = Right GUI)      */
    0x15, 0x00,       /*   Logical Min (0)                  */
    0x25, 0x01,       /*   Logical Max (1)                  */
    0x75, 0x01,       /*   Report Size (1)                  */
    0x95, 0x08,       /*   Report Count (8)                 */
    0x81, 0x02,       /*   Input (Data, Var, Abs) — Mods    */
    0x95, 0x01,       /*   Report Count (1)                 */
    0x75, 0x08,       /*   Report Size (8)                  */
    0x81, 0x01,       /*   Input (Const) — Reserved         */
    0x95, 0x06,       /*   Report Count (6)                 */
    0x75, 0x08,       /*   Report Size (8)                  */
    0x15, 0x00,       /*   Logical Min (0)                  */
    0x25, 0x65,       /*   Logical Max (101)                */
    0x19, 0x00,       /*   Usage Min (0)                    */
    0x29, 0x65,       /*   Usage Max (101)                  */
    0x81, 0x00,       /*   Input (Data, Array) — Keys       */
    0x95, 0x05,       /*   Report Count (5)                 */
    0x75, 0x01,       /*   Report Size (1)                  */
    0x05, 0x08,       /*   Usage Page (LEDs)                */
    0x19, 0x01,       /*   Usage Min (1 = Num Lock)         */
    0x29, 0x05,       /*   Usage Max (5 = Kana)             */
    0x91, 0x02,       /*   Output (Data, Var, Abs) — LEDs   */
    0x95, 0x01,       /*   Report Count (1)                 */
    0x75, 0x03,       /*   Report Size (3)                  */
    0x91, 0x01,       /*   Output (Const) — Padding         */
    0xC0              /* End Collection                      */
};

/* HID Information: v1.11, country=0, flags=0x02 (normally connectable) */
static const uint8_t hid_info[] = { 0x11, 0x01, 0x00, 0x02 };

/* Protocol Mode: 1 = Report Protocol */
static uint8_t protocol_mode = 0x01;

/* Report Reference descriptors — ID=0 since Report Map has no Report ID */
static const uint8_t report_ref_input[]  = { 0x00, 0x01 }; /* ID=0, Type=Input  */
static const uint8_t report_ref_output[] = { 0x00, 0x02 }; /* ID=0, Type=Output */

/* Characteristic value handles (populated by NimBLE during registration) */
static uint16_t s_report_input_handle  = 0;
static uint16_t s_report_output_handle = 0;

/* Live values */
static uint8_t keyboard_report[8] = {0};
static uint8_t led_report = 0;

/* Registration state */
static bool s_hid_registered = false;

/* Device Information Service data */
/* PnP ID: USB vendor source, Espressif VID 0x02E5, PID 1, version 1.0 */
static const uint8_t pnp_id[] = {
    0x02,       /* Vendor ID Source: USB Implementer's Forum */
    0xE5, 0x02, /* Vendor ID: 0x02E5 (Espressif) LE */
    0x01, 0x00, /* Product ID: 1 LE */
    0x00, 0x01  /* Product Version: 1.0.0 LE */
};

/* Battery level — static 100% */
static uint8_t battery_level = 100;

/* ========================================================================
 * GATT Callbacks
 * ======================================================================== */

static int
hid_chr_access(uint16_t conn_handle, uint16_t attr_handle,
               struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    uint16_t uuid16 = ble_uuid_u16(ctxt->chr->uuid);

    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        switch (uuid16) {
        case 0x2A4A: /* HID Information */
            os_mbuf_append(ctxt->om, hid_info, sizeof(hid_info));
            return 0;
        case 0x2A4B: /* Report Map */
            os_mbuf_append(ctxt->om, hid_report_map, sizeof(hid_report_map));
            return 0;
        case 0x2A4E: /* Protocol Mode */
            os_mbuf_append(ctxt->om, &protocol_mode, 1);
            return 0;
        case 0x2A4D: /* Report (Input or Output — distinguish by handle) */
            if (attr_handle == s_report_input_handle)
                os_mbuf_append(ctxt->om, keyboard_report, sizeof(keyboard_report));
            else
                os_mbuf_append(ctxt->om, &led_report, 1);
            return 0;
        }
    }

    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
        switch (uuid16) {
        case 0x2A4C: /* HID Control Point — accept silently */
            return 0;
        case 0x2A4E: /* Protocol Mode */
            if (OS_MBUF_PKTLEN(ctxt->om) >= 1)
                os_mbuf_copydata(ctxt->om, 0, 1, &protocol_mode);
            return 0;
        case 0x2A4D: /* Report Output (LED) */
            if (OS_MBUF_PKTLEN(ctxt->om) >= 1)
                os_mbuf_copydata(ctxt->om, 0, 1, &led_report);
            return 0;
        }
    }

    return 0;
}

static int
hid_dsc_access(uint16_t conn_handle, uint16_t attr_handle,
               struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_DSC) {
        const uint8_t *ref = (const uint8_t *)arg;
        os_mbuf_append(ctxt->om, ref, 2);
    }
    return 0;
}

/* ========================================================================
 * Device Information Service Callback
 * ======================================================================== */

static int
dis_chr_access(uint16_t conn_handle, uint16_t attr_handle,
               struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    uint16_t uuid16 = ble_uuid_u16(ctxt->chr->uuid);

    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        if (uuid16 == 0x2A50) { /* PnP ID */
            os_mbuf_append(ctxt->om, pnp_id, sizeof(pnp_id));
            return 0;
        }
        if (uuid16 == 0x2A29) { /* Manufacturer Name */
            const char *name = "Monstatek";
            os_mbuf_append(ctxt->om, name, strlen(name));
            return 0;
        }
    }
    return 0;
}

/* ========================================================================
 * Battery Service Callback
 * ======================================================================== */

static int
bas_chr_access(uint16_t conn_handle, uint16_t attr_handle,
               struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        os_mbuf_append(ctxt->om, &battery_level, 1);
    }
    return 0;
}

/* ========================================================================
 * GATT Service Definitions (DIS + Battery + HID)
 * ======================================================================== */

static const struct ble_gatt_svc_def hid_svcs[] = {
    /* Device Information Service (0x180A) — required by HOGP for Windows */
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(0x180A),
        .characteristics = (struct ble_gatt_chr_def[]) {
            /* PnP ID (0x2A50) — required for Windows HID driver binding */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A50),
                .access_cb = dis_chr_access,
                .flags = BLE_GATT_CHR_F_READ,
            },
            /* Manufacturer Name (0x2A29) */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A29),
                .access_cb = dis_chr_access,
                .flags = BLE_GATT_CHR_F_READ,
            },
            { 0 }
        },
    },
    /* Battery Service (0x180F) — required by HOGP */
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(0x180F),
        .characteristics = (struct ble_gatt_chr_def[]) {
            /* Battery Level (0x2A19) — Read + Notify, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A19),
                .access_cb = bas_chr_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY
                       | BLE_GATT_CHR_F_READ_ENC,
            },
            { 0 }
        },
    },
    /* HID Service (0x1812) */
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(0x1812),
        .characteristics = (struct ble_gatt_chr_def[]) {
            /* HID Information (0x2A4A) — Read, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4A),
                .access_cb = hid_chr_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            },
            /* Report Map (0x2A4B) — Read, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4B),
                .access_cb = hid_chr_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            },
            /* HID Control Point (0x2A4C) — Write No Response, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4C),
                .access_cb = hid_chr_access,
                .flags = BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_WRITE_ENC,
            },
            /* Protocol Mode (0x2A4E) — Read + Write No Response, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4E),
                .access_cb = hid_chr_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE_NO_RSP
                       | BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_WRITE_ENC,
            },
            /* Report Input (0x2A4D) — Read + Notify, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4D),
                .access_cb = hid_chr_access,
                .val_handle = &s_report_input_handle,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY
                       | BLE_GATT_CHR_F_READ_ENC,
                .descriptors = (struct ble_gatt_dsc_def[]) {
                    {
                        .uuid = BLE_UUID16_DECLARE(0x2908),
                        .access_cb = hid_dsc_access,
                        .att_flags = BLE_ATT_F_READ | BLE_ATT_F_READ_ENC,
                        .arg = (void *)report_ref_input,
                    },
                    { 0 }
                },
            },
            /* Report Output (0x2A4D) — Read + Write + Write No Response, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4D),
                .access_cb = hid_chr_access,
                .val_handle = &s_report_output_handle,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE
                       | BLE_GATT_CHR_F_WRITE_NO_RSP
                       | BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_WRITE_ENC,
                .descriptors = (struct ble_gatt_dsc_def[]) {
                    {
                        .uuid = BLE_UUID16_DECLARE(0x2908),
                        .access_cb = hid_dsc_access,
                        .att_flags = BLE_ATT_F_READ | BLE_ATT_F_READ_ENC,
                        .arg = (void *)report_ref_output,
                    },
                    { 0 }
                },
            },
            { 0 }  /* End of characteristics */
        },
    },
    { 0 }  /* End of services */
};

/* ========================================================================
 * Shared helpers
 * ======================================================================== */

bool m1_ble_hid_is_ready(void)
{
    return s_hid_registered && s_report_input_handle != 0;
}

esp_err_t m1_ble_hid_init(bool enable)
{
    if (!enable) {
        ESP_LOGI(TAG, "HID state reset");
        s_hid_registered = false;
        s_report_input_handle = 0;
        s_report_output_handle = 0;
        return ESP_OK;
    }

    if (s_hid_registered) {
        ESP_LOGI(TAG, "HID already registered, input_handle=%d", s_report_input_handle);
        return ESP_OK;
    }

    ble_svc_gap_device_appearance_set(0x03C1);

    int rc = ble_gatts_add_dynamic_svcs(hid_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_add_dynamic_svcs failed: %d", rc);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "HID services registered, input_handle=%d", s_report_input_handle);

    if (s_report_input_handle == 0) {
        ESP_LOGE(TAG, "input handle not populated by NimBLE");
        return ESP_ERR_INVALID_STATE;
    }

    s_hid_registered = true;
    return ESP_OK;
}

esp_err_t m1_ble_hid_send_keyboard_report(uint8_t modifier,
                                          const uint8_t *keys,
                                          uint8_t key_count)
{
    if (key_count > 6) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!m1_ble_hid_is_ready()) {
        ESP_LOGE(TAG, "HID not registered");
        return ESP_ERR_INVALID_STATE;
    }

    struct ble_gap_conn_desc desc;
    uint16_t conn = BLE_HS_CONN_HANDLE_NONE;
    for (uint16_t h = 0; h < 10; h++) {
        if (ble_gap_conn_find(h, &desc) == 0) {
            conn = h;
            break;
        }
    }
    if (conn == BLE_HS_CONN_HANDLE_NONE) {
        ESP_LOGE(TAG, "No BLE connection");
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t report[8] = {0};
    report[0] = modifier;
    for (uint8_t i = 0; i < key_count; i++) {
        report[2 + i] = keys[i];
    }

    struct os_mbuf *om = ble_hs_mbuf_from_flat(report, sizeof(report));
    if (om == NULL) {
        ESP_LOGE(TAG, "mbuf alloc failed");
        return ESP_ERR_NO_MEM;
    }

    int rc = ble_gatts_notify_custom(conn, s_report_input_handle, om);
    if (rc != 0) {
        ESP_LOGE(TAG, "notify failed: %d", rc);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/* ========================================================================
 * AT Command Handlers
 * ======================================================================== */

/*
 * AT+BLEHIDINIT=<enable>
 *   1 = Register HID GATT service via NimBLE API.
 *   Must be called after AT+BLEINIT=2 (NimBLE running).
 *   Idempotent — safe to call multiple times.
 */
static uint8_t
at_setup_cmd_blehidinit(uint8_t para_num)
{
    int32_t enable;
    if (esp_at_get_para_as_digit(0, &enable) != ESP_AT_PARA_PARSE_RESULT_OK)
        return ESP_AT_RESULT_CODE_ERROR;

    if (enable != 0 && enable != 1)
        return ESP_AT_RESULT_CODE_ERROR;

    return (m1_ble_hid_init(enable == 1) == ESP_OK)
        ? ESP_AT_RESULT_CODE_OK
        : ESP_AT_RESULT_CODE_ERROR;
}

/*
 * AT+BLEHIDKB=<modifier>,<key1>,<key2>,<key3>,<key4>,<key5>,<key6>
 *   Sends an 8-byte keyboard HID report via notification.
 *   All values are decimal 0-255.  Key codes use USB HID usage table.
 *   To release all keys: AT+BLEHIDKB=0,0,0,0,0,0,0
 */
static uint8_t
at_setup_cmd_blehidkb(uint8_t para_num)
{
    if (para_num < 7)
        return ESP_AT_RESULT_CODE_ERROR;

    int32_t vals[7];
    for (int i = 0; i < 7; i++) {
        if (esp_at_get_para_as_digit(i, &vals[i]) != ESP_AT_PARA_PARSE_RESULT_OK)
            return ESP_AT_RESULT_CODE_ERROR;
    }

    uint8_t keys[6];
    for (int i = 0; i < 6; i++) {
        keys[i] = (uint8_t)vals[1 + i];
    }

    return (m1_ble_hid_send_keyboard_report((uint8_t)vals[0], keys, 6) == ESP_OK)
        ? ESP_AT_RESULT_CODE_OK
        : ESP_AT_RESULT_CODE_ERROR;
}

/* ========================================================================
 * AT Command Registration
 * ======================================================================== */

static const esp_at_cmd_struct s_hid_cmd_list[] = {
    {"+HIDKBINIT", NULL, NULL, at_setup_cmd_blehidinit, NULL},
    {"+HIDKBSEND", NULL, NULL, at_setup_cmd_blehidkb,   NULL},
};

bool esp_at_custom_hid_cmd_register(void)
{
    return esp_at_custom_cmd_array_regist(
        s_hid_cmd_list,
        sizeof(s_hid_cmd_list) / sizeof(s_hid_cmd_list[0]));
}
