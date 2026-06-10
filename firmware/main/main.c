/**
 * @file main.c
 * @brief ESP32 Wi-Fi Research Lab – firmware entry point.
 *
 * Initialises NVS, Wi-Fi (AP + monitor mode), the HTTP control interface,
 * and the passive packet-capture pipeline.
 *
 * Build:   idf.py build
 * Flash:   idf.py flash
 * Monitor: idf.py monitor
 */

#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"

#include "wifi_manager.h"
#include "web_server.h"
#include "pcap_writer.h"

static const char *TAG = "main";

/* ── configuration (override via sdkconfig / menuconfig) ──────────────────── */
#define AP_SSID      "ESP32-ResearchLab"
#define AP_PASSWORD  "research1234"
#define AP_CHANNEL   1
#define AP_MAX_CONN  4

/* ─────────────────────────────────────────────────────────────────────────── */

void app_main(void)
{
    ESP_LOGI(TAG, "ESP32 Wi-Fi Research Lab – firmware starting");

    /* Non-volatile storage (required by Wi-Fi driver) */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Network / event loop */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* Wi-Fi: soft-AP for control interface + monitor mode for capture */
    wifi_manager_init(AP_SSID, AP_PASSWORD, AP_CHANNEL, AP_MAX_CONN);
    ESP_LOGI(TAG, "Soft-AP started  SSID='%s'  CH=%d", AP_SSID, AP_CHANNEL);

    /* HTTP control interface (reachable at 192.168.4.1) */
    web_server_start();
    ESP_LOGI(TAG, "Web server running at http://192.168.4.1");

    /* PCAP writer: buffers captured frames for HTTP export */
    pcap_writer_init();

    /* Enable passive monitor-mode sniffer */
    wifi_manager_enable_sniffer();
    ESP_LOGI(TAG, "Packet sniffer active – monitor mode enabled");

    /* Main loop: heartbeat log every 30 s */
    while (1) {
        ESP_LOGI(TAG, "Uptime – captured frames: %lu", pcap_writer_frame_count());
        vTaskDelay(pdMS_TO_TICKS(30000));
    }
}
