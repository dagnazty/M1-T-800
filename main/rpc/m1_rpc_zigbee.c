/**
 * M1 RPC — Zigbee / 802.15.4 handler.
 *
 * Reuses the existing 802.15.4 sniffer service from the AT command layer and
 * forwards captured frames to the STM32 as binary events.
 */

#include <string.h>

#include "m1_rpc.h"
#include "m1_rpc_proto.h"
#include "m1_rpc_zigbee.h"

#include "at_custom_zigbee_cmd.h"
#include "esp_err.h"

static m1_status_t zigbee_status_from_err(esp_err_t err)
{
    switch (err) {
    case ESP_OK:
        return M1_OK;
    case ESP_ERR_INVALID_ARG:
        return M1_ERR_INVALID_ARGS;
    case ESP_ERR_NO_MEM:
        return M1_ERR_NO_MEM;
    default:
        return M1_ERR_HARDWARE;
    }
}

static void zigbee_frame_event_cb(const uint8_t *frame,
                                  uint8_t len,
                                  uint8_t channel,
                                  int8_t rssi,
                                  uint8_t lqi,
                                  void *ctx)
{
    (void)rssi;
    (void)lqi;
    (void)ctx;

    uint8_t evt[M1_RPC_MAX_PAYLOAD];
    uint16_t evt_len = (uint16_t)len + 3;
    if (evt_len > sizeof(evt)) {
        return;
    }

    evt[0] = channel;
    evt[1] = (uint8_t)(len & 0xFF);
    evt[2] = (uint8_t)((uint16_t)len >> 8);
    memcpy(evt + 3, frame, len);
    m1_rpc_send_event(M1_EVT_ZB_FRAME, evt, evt_len);
}

static m1_status_t cmd_zb_init(const uint8_t *payload, uint16_t len)
{
    if (len < 1) {
        return M1_ERR_INVALID_ARGS;
    }
    return zigbee_status_from_err(m1_zigbee_init(payload[0] != 0));
}

static m1_status_t cmd_zb_scan(const uint8_t *payload, uint16_t len)
{
    (void)payload;
    (void)len;
    return M1_ERR_UNSUPPORTED;
}

static m1_status_t cmd_zb_sniff_start(const uint8_t *payload, uint16_t len)
{
    if (len < 1) {
        return M1_ERR_INVALID_ARGS;
    }

    m1_zigbee_set_frame_callback(zigbee_frame_event_cb, NULL);
    return zigbee_status_from_err(m1_zigbee_sniffer_start(payload[0]));
}

static m1_status_t cmd_zb_sniff_stop(void)
{
    m1_zigbee_set_frame_callback(NULL, NULL);
    return zigbee_status_from_err(m1_zigbee_sniffer_stop());
}

m1_status_t m1_rpc_zigbee_handler(uint16_t msg_id,
                                  const uint8_t *payload,
                                  uint16_t payload_len,
                                  uint8_t *resp_buf,
                                  uint16_t *resp_len)
{
    (void)resp_buf;
    *resp_len = 0;

    switch (msg_id) {
    case M1_MSG_ZB_INIT:
        return cmd_zb_init(payload, payload_len);
    case M1_MSG_ZB_SCAN:
        return cmd_zb_scan(payload, payload_len);
    case M1_MSG_ZB_SNIFF_START:
        return cmd_zb_sniff_start(payload, payload_len);
    case M1_MSG_ZB_SNIFF_STOP:
        return cmd_zb_sniff_stop();
    default:
        return M1_ERR_UNSUPPORTED;
    }
}
