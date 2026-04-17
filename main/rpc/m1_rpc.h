#pragma once
/**
 * M1 RPC — ESP32-side dispatcher and handler interface.
 */

#include "m1_rpc_proto.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Handler callback signature ───────────────────────────────── */

/**
 * Called when a REQ frame arrives for msg_id.
 *   msg_id     — the request message ID
 *   payload    — payload bytes (payload_len)
 *   resp_buf   — buffer to write response payload into
 *   resp_len   — IN: max size of resp_buf; OUT: actual response bytes written
 * Returns: status code (0 = OK)
 */
typedef m1_status_t (*m1_rpc_handler_t)(
    uint16_t msg_id,
    const uint8_t *payload,
    uint16_t payload_len,
    uint8_t *resp_buf,
    uint16_t *resp_len
);

/* ── Public API ───────────────────────────────────────────────── */

/** Initialize the RPC subsystem. Call once from app_main. */
void m1_rpc_init(void);

/** Register a handler for a range of message IDs. */
void m1_rpc_register_handler(uint16_t msg_id_start, uint16_t msg_id_end,
                              m1_rpc_handler_t handler);

/** Send an async event to the STM32. */
m1_status_t m1_rpc_send_event(uint16_t event_id,
                               const uint8_t *payload,
                               uint16_t payload_len);

/** Feed incoming SPI bytes into the RPC parser.
 *  Called by the SPI slave task when data arrives.
 *  Automatically detects AT vs binary (dual-mode phase 1).
 */
void m1_rpc_feed(const uint8_t *data, uint16_t len);

/** Check if a byte buffer looks like a binary RPC frame. */
static inline bool m1_rpc_is_binary_frame(const uint8_t *data, uint16_t len) {
    return (len >= 2 && data[0] == 0x31 && data[1] == 0x4D);  /* M1 LE */
}

#ifdef __cplusplus
}
#endif
