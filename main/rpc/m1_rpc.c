/**
 * M1 RPC — ESP32-side core implementation.
 *
 * Receives bytes from SPI, parses binary frames, dispatches to handlers,
 * and sends responses/events back through the SPI TX ring buffer.
 */

#include <string.h>
#include "m1_rpc.h"
#include "m1_rpc_proto.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

static const char *TAG = "M1_RPC";

/* ── Handler table ─────────────────────────────────────────────── */

#define MAX_HANDLERS 16

typedef struct {
    uint16_t id_start;
    uint16_t id_end;
    m1_rpc_handler_t handler;
} handler_entry_t;

static handler_entry_t s_handlers[MAX_HANDLERS];
static uint8_t s_handler_count = 0;

/* ── Reassembly state ──────────────────────────────────────────── */

#define MAX_FRAME_SIZE (M1_RPC_HEADER_LEN + M1_RPC_MAX_PAYLOAD + M1_RPC_CRC_LEN)

static uint8_t s_frame_buf[MAX_FRAME_SIZE];
static uint16_t s_frame_pos = 0;
static bool s_frame_active = false;

/* ── CRC16-CCITT ──────────────────────────────────────────────── */

static uint16_t crc16_ccitt(const uint8_t *data, uint16_t len)
{
    uint16_t crc = 0xFFFF;
    for (uint16_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000)
                crc = (crc << 1) ^ 0x1021;
            else
                crc <<= 1;
        }
    }
    return crc;
}

/* ── Send frame back through AT write path ────────────────────── */
/* In phase 1, we use the existing at_spi_write_data to push bytes. */

extern int32_t at_spi_write_data(uint8_t *buf, int32_t len);

static m1_status_t send_frame(m1_msg_type_t msg_type, uint16_t msg_id,
                               const uint8_t *payload, uint16_t payload_len)
{
    if (payload_len > M1_RPC_MAX_PAYLOAD) {
        ESP_LOGE(TAG, "Payload too large: %d", payload_len);
        return M1_ERR_NO_MEM;
    }

    uint8_t buf[M1_RPC_HEADER_LEN + M1_RPC_MAX_PAYLOAD + M1_RPC_CRC_LEN];
    m1_rpc_header_t hdr = {
        .magic       = M1_RPC_MAGIC,
        .version     = M1_RPC_VERSION,
        .msg_type    = msg_type,
        .msg_id      = msg_id,
        .payload_len = payload_len,
    };

    memcpy(buf, &hdr, M1_RPC_HEADER_LEN);
    if (payload_len > 0 && payload) {
        memcpy(buf + M1_RPC_HEADER_LEN, payload, payload_len);
    }

    uint16_t crc = crc16_ccitt(buf, M1_RPC_HEADER_LEN + payload_len);
    buf[M1_RPC_HEADER_LEN + payload_len]     = crc & 0xFF;
    buf[M1_RPC_HEADER_LEN + payload_len + 1] = (crc >> 8) & 0xFF;

    uint16_t total = M1_RPC_HEADER_LEN + payload_len + M1_RPC_CRC_LEN;
    int32_t written = at_spi_write_data(buf, total);
    return (written == total) ? M1_OK : M1_ERR_HARDWARE;
}

/* ── Dispatch ─────────────────────────────────────────────────── */

static m1_status_t dispatch_request(uint16_t msg_id,
                                     const uint8_t *payload,
                                     uint16_t payload_len)
{
    uint8_t resp_buf[M1_RPC_MAX_PAYLOAD];
    uint16_t resp_len = sizeof(resp_buf);
    m1_status_t status = M1_ERR_UNSUPPORTED;

    for (int i = 0; i < s_handler_count; i++) {
        if (msg_id >= s_handlers[i].id_start && msg_id <= s_handlers[i].id_end) {
            status = s_handlers[i].handler(msg_id, payload, payload_len,
                                           resp_buf, &resp_len);
            break;
        }
    }

    /* Send response — always respond, even on error */
    uint8_t resp_payload[M1_RPC_MAX_PAYLOAD];
    uint16_t resp_payload_len = 0;

    if (status == M1_OK && resp_len > 0) {
        /* Handler wrote a full response payload (including status byte) */
        memcpy(resp_payload, resp_buf, resp_len);
        resp_payload_len = resp_len;
    } else {
        /* Minimal response: just the status byte */
        resp_payload[0] = (uint8_t)status;
        resp_payload_len = 1;
    }

    return send_frame(M1_MSG_RESP, msg_id, resp_payload, resp_payload_len);
}

/* ── Public API ───────────────────────────────────────────────── */

void m1_rpc_init(void)
{
    s_handler_count = 0;
    s_frame_pos = 0;
    s_frame_active = false;
    ESP_LOGI(TAG, "M1 RPC initialized");
}

void m1_rpc_register_handler(uint16_t msg_id_start, uint16_t msg_id_end,
                              m1_rpc_handler_t handler)
{
    if (s_handler_count >= MAX_HANDLERS) {
        ESP_LOGE(TAG, "Handler table full");
        return;
    }
    s_handlers[s_handler_count++] = (handler_entry_t){
        .id_start = msg_id_start,
        .id_end   = msg_id_end,
        .handler  = handler,
    };
    ESP_LOGI(TAG, "Registered handler for 0x%04X–0x%04X", msg_id_start, msg_id_end);
}

m1_status_t m1_rpc_send_event(uint16_t event_id,
                               const uint8_t *payload,
                               uint16_t payload_len)
{
    return send_frame(M1_MSG_EVENT, event_id, payload, payload_len);
}

void m1_rpc_feed(const uint8_t *data, uint16_t len)
{
    /* Phase 1: detect AT vs binary */
    if (len >= 2 && m1_rpc_is_binary_frame(data, len)) {
        /* Binary frame — accumulate and process */
        for (uint16_t i = 0; i < len; i++) {
            if (s_frame_pos < MAX_FRAME_SIZE) {
                s_frame_buf[s_frame_pos++] = data[i];
            }
        }

        /* Try to parse a complete frame */
        while (s_frame_pos >= M1_RPC_HEADER_LEN + M1_RPC_CRC_LEN) {
            m1_rpc_header_t hdr;
            memcpy(&hdr, s_frame_buf, M1_RPC_HEADER_LEN);

            if (hdr.magic != M1_RPC_MAGIC || hdr.version != M1_RPC_VERSION) {
                /* Bad frame — reset */
                ESP_LOGW(TAG, "Bad frame magic/version, discarding %d bytes", s_frame_pos);
                s_frame_pos = 0;
                break;
            }

            uint16_t frame_total = M1_RPC_HEADER_LEN + hdr.payload_len + M1_RPC_CRC_LEN;
            if (s_frame_pos < frame_total) {
                break;  /* incomplete, wait for more data */
            }

            /* Verify CRC */
            uint16_t calc_crc = crc16_ccitt(s_frame_buf, M1_RPC_HEADER_LEN + hdr.payload_len);
            uint16_t rx_crc = s_frame_buf[M1_RPC_HEADER_LEN + hdr.payload_len]
                           | (s_frame_buf[M1_RPC_HEADER_LEN + hdr.payload_len + 1] << 8);

            if (calc_crc != rx_crc) {
                ESP_LOGW(TAG, "CRC mismatch: calc=0x%04X rx=0x%04X", calc_crc, rx_crc);
                s_frame_pos = 0;
                break;
            }

            /* Dispatch */
            if (hdr.msg_type == M1_MSG_REQ) {
                dispatch_request(hdr.msg_id,
                                 s_frame_buf + M1_RPC_HEADER_LEN,
                                 hdr.payload_len);
            }

            /* Consume this frame */
            uint16_t remaining = s_frame_pos - frame_total;
            if (remaining > 0) {
                memmove(s_frame_buf, s_frame_buf + frame_total, remaining);
            }
            s_frame_pos = remaining;
        }
    } else {
        /* Should not happen: the SPI intercept only routes binary frames
         * to m1_rpc_feed(). AT strings go straight to the AT parser's ring
         * buffer. If we get here, drop the data. */
        ESP_LOGW(TAG, "m1_rpc_feed called with non-binary data, %d bytes dropped", len);
    }
}
