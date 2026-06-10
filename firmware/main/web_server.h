/**
 * @file web_server.h
 * @brief Lightweight HTTP control interface (ESP-IDF esp_http_server).
 *
 * Endpoints
 * ---------
 *  GET  /              → HTML dashboard
 *  GET  /api/status    → JSON: frame count, uptime, channel
 *  GET  /api/pcap/download  → .pcap binary download
 *  POST /api/pcap/reset     → clear PCAP buffer
 *  POST /api/scan      → trigger AP scan, returns JSON
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Start the HTTP server on port 80.
 */
void web_server_start(void);

/**
 * @brief Stop the HTTP server and free resources.
 */
void web_server_stop(void);

#ifdef __cplusplus
}
#endif
