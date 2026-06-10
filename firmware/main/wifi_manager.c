/**
 * @file wifi_manager.c
 * @brief Wi-Fi manager – soft-AP, monitor mode, promiscuous sniffer.
 */

#include "wifi_manager.h"
#include "pcap_writer.h"

#include <string.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"

static const char *TAG = "wifi_manager";

/* ── promiscuous callback ──────────────────────────────────────────────────── */

static void _sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type == WIFI_PKT_MISC) return;  /* skip control frames noise */

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_pkt_rx_ctrl_t    *rx   = &pkt->rx_ctrl;

    /* Forward raw frame to PCAP writer */
    pcap_writer_write_frame(pkt->payload, rx->sig_len, (uint32_t)rx->timestamp);
}

/* ── public API ────────────────────────────────────────────────────────────── */

void wifi_manager_init(const char *ssid, const char *password,
                       uint8_t channel, uint8_t max_conn)
{
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    wifi_config_t ap_cfg = {
        .ap = {
            .channel        = channel,
            .max_connection = max_conn,
            .authmode       = (password && strlen(password) >= 8)
                                ? WIFI_AUTH_WPA2_PSK
                                : WIFI_AUTH_OPEN,
        },
    };
    strlcpy((char *)ap_cfg.ap.ssid,     ssid,     sizeof(ap_cfg.ap.ssid));
    strlcpy((char *)ap_cfg.ap.password, password ? password : "",
            sizeof(ap_cfg.ap.password));

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
}

void wifi_manager_enable_sniffer(void)
{
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                       WIFI_PROMIS_FILTER_MASK_DATA,
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&_sniffer_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_LOGI(TAG, "Promiscuous sniffer enabled");
}

void wifi_manager_disable_sniffer(void)
{
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
    ESP_LOGI(TAG, "Promiscuous sniffer disabled");
}

esp_err_t wifi_manager_scan(void)
{
    wifi_scan_config_t scan_cfg = {
        .ssid        = NULL,
        .bssid       = NULL,
        .channel     = 0,
        .show_hidden = true,
        .scan_type   = WIFI_SCAN_TYPE_ACTIVE,
    };
    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true /* block */);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Scan failed: %s", esp_err_to_name(err));
    }
    return err;
}
