#pragma once

/**
 * M1 RPC — Top-level initialization.
 * Call m1_rpc_setup() from app_main after WiFi/NVS init.
 * Registers all handlers and hooks into the SPI data path.
 */

void m1_rpc_setup(void);
