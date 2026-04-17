
file(GLOB_RECURSE srcs *.c)
list(APPEND srcs
    rpc/m1_rpc_ble.c
    rpc/m1_rpc_zigbee.c
)

idf_component_register(SRCS ${srcs}
                    INCLUDE_DIRS "include" "rpc")
