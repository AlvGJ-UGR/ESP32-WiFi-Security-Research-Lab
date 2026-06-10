/**
 * @file wifi_manager.h
 * @brief Wi-Fi initialisation and monitor-mode sniffer API.
 */

#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialise Wi-Fi in combined AP + STA mode and start the soft-AP.
 *
 * @param ssid      Soft-AP SSID (max 32 chars).
 * @param password  WPA2 passphrase (min 8 chars, NULL for open network).
 * @param channel   802.11 channel for the AP (1–13).
 * @param max_conn  Maximum simultaneous AP connections.
 */
void wifi_manager_init(const char *ssid, const char *password,
                       uint8_t channel, uint8_t max_conn);

/**
 * @brief Enable passive monitor mode on the current AP channel.
 *
 * Registers an ESP-IDF promiscuous callback that forwards every captured
 * frame to the pcap_writer for storage.
 */
void wifi_manager_enable_sniffer(void);

/**
 * @brief Disable monitor mode sniffer.
 */
void wifi_manager_disable_sniffer(void);

/**
 * @brief Scan for nearby APs and return results via callback.
 *
 * @return ESP_OK on success.
 */
esp_err_t wifi_manager_scan(void);

#ifdef __cplusplus
}
#endif
