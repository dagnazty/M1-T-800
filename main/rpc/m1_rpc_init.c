/**
 * M1 RPC — Top-level setup.
 *
 * Registers all command handlers and provides the hook
 * that intercepts SPI data before the AT parser.
 */

#include "m1_rpc.h"
#include "m1_rpc_proto.h"
#include "m1_rpc_offensive.h"
#include "m1_rpc_system.h"
#include "m1_rpc_wifi.h"
#include "m1_rpc_ble.h"
#include "m1_rpc_zigbee.h"
#include "m1_rpc_init.h"

#include "esp_log.h"

static const char *TAG = "M1_RPC_Init";

void m1_rpc_setup(void)
{
    ESP_LOGI(TAG, "Setting up M1 binary RPC");

    /* Initialize core */
    m1_rpc_init();

    /* Register handlers by ID range */
    m1_rpc_register_handler(0x0300, 0x03FF, m1_rpc_off_wifi_handler);
    m1_rpc_register_handler(0x0600, 0x06FF, m1_rpc_sys_handler);

    m1_rpc_register_handler(0x0100, 0x01FF, m1_rpc_wifi_sta_handler);
    m1_rpc_register_handler(0x0200, 0x02FF, m1_rpc_softap_handler);
    m1_rpc_register_handler(0x0400, 0x04FF, m1_rpc_ble_handler);
    m1_rpc_register_handler(0x0500, 0x05FF, m1_rpc_zigbee_handler);

    ESP_LOGI(TAG, "M1 binary RPC ready (phase 1: dual-mode with AT fallback)");
}

/* ── SPI intercept (phase 1) ────────────────────────────────────── */

/**
 * To be called from at_spi_read_data() in the SPI slave task.
 *
 * Before feeding bytes to the AT parser, check if they're a binary frame.
 * If so, route to m1_rpc_feed(). Otherwise, let AT handle them.
 *
 * Patch at_spi_slave_task() in at_spi_task_esp32_series.c:
 *
 *   // After xStreamBufferReceive into data_buf:
 *   if (m1_rpc_is_binary_frame(data_buf, ret_trans->trans_len)) {
 *       m1_rpc_feed(data_buf, ret_trans->trans_len);
 *   } else {
 *       xStreamBufferSend(spi_slave_rx_ring_buf, data_buf, ret_trans->trans_len, portMAX_DELAY);
 *       esp_at_port_recv_data_notify(ret_trans->trans_len, portMAX_DELAY);
 *   }
 */
