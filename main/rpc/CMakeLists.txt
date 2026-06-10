idf_component_register(
    SRCS "m1_rpc.c"
         "m1_rpc_ble.c"
         "m1_rpc_offensive.c"
         "m1_rpc_eviltwin.c"
         "m1_rpc_system.c"
         "m1_rpc_init.c"
         "m1_rpc_wifi.c"
         "m1_rpc_zigbee.c"
    INCLUDE_DIRS "."
    REQUIRES bt esp_wifi esp_event esp_log esp_ota nvs_flash esp_netif
             esp_http_server lwip
)
