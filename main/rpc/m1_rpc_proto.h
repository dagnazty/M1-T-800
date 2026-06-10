#pragma once
/**
 * M1 Binary RPC Protocol — shared constants and types.
 * Included by both ESP32 firmware and STM32 host code.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Wire format ─────────────────────────────────────────────── */

#define M1_RPC_MAGIC        0x4D31   /* "M1" little-endian */
#define M1_RPC_VERSION      0x01
#define M1_RPC_HEADER_LEN   8
#define M1_RPC_CRC_LEN      2
#define M1_RPC_MAX_PAYLOAD  4084    /* 4092 SPI_DMA_MAX_LEN - 8 header */

/* ── Message types ────────────────────────────────────────────── */

typedef enum __attribute__((packed)) {
    M1_MSG_REQ   = 0x01,
    M1_MSG_RESP  = 0x02,
    M1_MSG_EVENT = 0x03,
    M1_MSG_FRAG  = 0x04,
} m1_msg_type_t;

/* ── Frame header ──────────────────────────────────────────────── */

typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint8_t  version;
    uint8_t  msg_type;
    uint16_t msg_id;
    uint16_t payload_len;
} m1_rpc_header_t;

/* ── Status codes ─────────────────────────────────────────────── */

typedef enum {
    M1_OK                = 0x00,
    M1_ERR_UNKNOWN       = 0x01,
    M1_ERR_INVALID_ARGS  = 0x02,
    M1_ERR_BUSY          = 0x03,
    M1_ERR_TIMEOUT       = 0x04,
    M1_ERR_NO_MEM        = 0x05,
    M1_ERR_NOT_INIT      = 0x06,
    M1_ERR_ALREADY_RUNNING = 0x07,
    M1_ERR_NOT_RUNNING   = 0x08,
    M1_ERR_HARDWARE      = 0x09,
    M1_ERR_UNSUPPORTED   = 0x0A,
    M1_ERR_PENDING       = 0xFF,
} m1_status_t;

/* ── Message IDs ──────────────────────────────────────────────── */

/* WiFi Station 0x0100–0x01FF */
#define M1_MSG_WIFI_GET_MODE       0x0100
#define M1_MSG_WIFI_SET_MODE       0x0101
#define M1_MSG_WIFI_GET_MAC        0x0102
#define M1_MSG_WIFI_SCAN           0x0103
#define M1_MSG_WIFI_CONNECT        0x0104
#define M1_MSG_WIFI_DISCONNECT     0x0105
#define M1_MSG_WIFI_GET_STATUS     0x0106
#define M1_MSG_WIFI_SCAN_RESULTS   0x0107

/* WiFi AP 0x0200–0x02FF */
#define M1_MSG_SOFTAP_START        0x0200
#define M1_MSG_SOFTAP_STOP         0x0201
#define M1_MSG_SOFTAP_GET_STA_LIST 0x0202

/* Offensive WiFi 0x0300–0x03FF */
#define M1_MSG_OFF_MONITOR_START   0x0300
#define M1_MSG_OFF_MONITOR_STOP    0x0301
#define M1_MSG_OFF_DEAUTH_START   0x0302
#define M1_MSG_OFF_DEAUTH_STOP    0x0303
#define M1_MSG_OFF_BEACON_START   0x0304
#define M1_MSG_OFF_BEACON_STOP    0x0305
#define M1_MSG_OFF_PROBE_SNIFF    0x0306
#define M1_MSG_OFF_PROBE_STOP     0x0307
#define M1_MSG_OFF_PMKID_CAPTURE  0x0308
#define M1_MSG_OFF_KARMA_START    0x0309
#define M1_MSG_OFF_KARMA_STOP     0x030A
#define M1_MSG_OFF_HSCAPTURE      0x030B
#define M1_MSG_OFF_RAW_TX         0x030C
#define M1_MSG_OFF_DEAUTH_STATUS  0x030D
#define M1_MSG_OFF_DEAUTH_ALL     0x030E
#define M1_MSG_OFF_EVILTWIN_START 0x030F
#define M1_MSG_OFF_EVILTWIN_STOP  0x0310

/* BLE 0x0400–0x04FF */
#define M1_MSG_BLE_INIT            0x0400
#define M1_MSG_BLE_SCAN_START      0x0401
#define M1_MSG_BLE_SCAN_RESULTS    0x0402
#define M1_MSG_BLE_ADV_START       0x0403
#define M1_MSG_BLE_ADV_STOP        0x0404
#define M1_MSG_BLE_HID_INIT        0x0405
#define M1_MSG_BLE_HID_KEYPRESS    0x0406
#define M1_MSG_BLE_CONNECT         0x0407
#define M1_MSG_BLE_DISCONNECT      0x0408
#define M1_MSG_BLE_SPAM_START      0x0409
#define M1_MSG_BLE_SPAM_STOP       0x040A

/* Zigbee 0x0500–0x05FF */
#define M1_MSG_ZB_INIT             0x0500
#define M1_MSG_ZB_SCAN             0x0501
#define M1_MSG_ZB_SNIFF_START      0x0502
#define M1_MSG_ZB_SNIFF_STOP       0x0503

/* System 0x0600–0x06FF */
#define M1_MSG_SYS_PING            0x0600
#define M1_MSG_SYS_GET_FW_VERSION  0x0601
#define M1_MSG_SYS_GET_HEAP        0x0602
#define M1_MSG_SYS_RESET           0x0603
#define M1_MSG_SYS_OTA_BEGIN       0x0604
#define M1_MSG_SYS_OTA_DATA        0x0605
#define M1_MSG_SYS_OTA_END         0x0606

/* Events 0xE000–0xEFFF */
#define M1_EVT_WIFI_SCAN_DONE      0xE001
#define M1_EVT_WIFI_CONNECTED      0xE002
#define M1_EVT_WIFI_DISCONNECTED   0xE003
#define M1_EVT_MONITOR_PACKET      0xE010
#define M1_EVT_MONITOR_DEAUTH      0xE011
#define M1_EVT_PMKID_RESULT        0xE020
#define M1_EVT_HANDSHAKE_RESULT    0xE021
#define M1_EVT_KARMA_PROBE_REQ     0xE030
#define M1_EVT_BLE_SCAN_RESULT     0xE040
#define M1_EVT_ZB_FRAME            0xE050
#define M1_EVT_STA_CONNECTED       0xE060
#define M1_EVT_STA_DISCONNECTED    0xE061
#define M1_EVT_EVILTWIN_CREDS      0xE070
#define M1_EVT_ERROR               0xE0FF

#ifdef __cplusplus
}
#endif
