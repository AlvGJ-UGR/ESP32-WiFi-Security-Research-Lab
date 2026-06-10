idf_component_register(
    SRCS
        "main.c"
        "wifi_manager.c"
        "web_server.c"
        "pcap_writer.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_wifi
        esp_http_server
        nvs_flash
        esp_netif
        frame_analyzer
        pcap_serializer
)
