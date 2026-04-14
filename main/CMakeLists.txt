
file(GLOB_RECURSE srcs *.c)
list(APPEND srcs at_custom_wifi_cmd.c)

idf_component_register(SRCS ${srcs}
                    INCLUDE_DIRS "include")
