/**
 * @file web_server.c
 * @brief HTTP control interface implementation.
 */

#include "web_server.h"
#include "pcap_writer.h"
#include "wifi_manager.h"

#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_timer.h"

static const char *TAG = "web_server";
static httpd_handle_t _server = NULL;

/* ── HTML dashboard (minimal, served from flash) ───────────────────────────── */
static const char _HTML[] =
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<title>ESP32 Research Lab</title>"
    "<style>body{font-family:monospace;background:#0d0d1a;color:#e0e0e0;padding:2rem}"
    "h1{color:#00b4d8}a.btn{display:inline-block;margin:.5rem;padding:.6rem 1.2rem;"
    "background:#7b61ff;color:#fff;text-decoration:none;border-radius:4px}"
    "pre{background:#1a1a2e;padding:1rem;border-radius:6px}"
    "</style></head><body>"
    "<h1>📡 ESP32 Wi-Fi Research Lab</h1>"
    "<p>Control interface for passive 802.11 capture.</p>"
    "<a class='btn' href='/api/status'>Status JSON</a>"
    "<a class='btn' href='/api/pcap/download'>Download PCAP</a>"
    "<a class='btn' href='/api/scan'>Scan APs</a>"
    "<hr><pre>POST /api/pcap/reset  → clear buffer\n"
    "GET  /api/status       → JSON status</pre>"
    "</body></html>";

/* ── handlers ──────────────────────────────────────────────────────────────── */

static esp_err_t _handle_root(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, _HTML, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t _handle_status(httpd_req_t *req)
{
    char buf[256];
    int64_t uptime_s = esp_timer_get_time() / 1000000;
    snprintf(buf, sizeof(buf),
        "{\"frames\":%lu,\"uptime_s\":%lld,\"buf_kb\":%d}",
        (unsigned long)pcap_writer_frame_count(),
        (long long)uptime_s,
        512
    );
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t _handle_pcap_download(httpd_req_t *req)
{
    static uint8_t tmp[64 * 1024];
    size_t len = pcap_writer_get_buffer(tmp, sizeof(tmp));

    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=\"capture.pcap\"");
    return httpd_resp_send(req, (char *)tmp, (ssize_t)len);
}

static esp_err_t _handle_pcap_reset(httpd_req_t *req)
{
    pcap_writer_reset();
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"status\":\"ok\",\"msg\":\"buffer cleared\"}",
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t _handle_scan(httpd_req_t *req)
{
    esp_err_t err = wifi_manager_scan();
    httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        return httpd_resp_send(req, "{\"status\":\"ok\",\"msg\":\"scan complete\"}",
                               HTTPD_RESP_USE_STRLEN);
    }
    return httpd_resp_send_500(req);
}

/* ── registration ──────────────────────────────────────────────────────────── */

static const httpd_uri_t _routes[] = {
    { .uri = "/",                  .method = HTTP_GET,  .handler = _handle_root          },
    { .uri = "/api/status",        .method = HTTP_GET,  .handler = _handle_status        },
    { .uri = "/api/pcap/download", .method = HTTP_GET,  .handler = _handle_pcap_download },
    { .uri = "/api/pcap/reset",    .method = HTTP_POST, .handler = _handle_pcap_reset    },
    { .uri = "/api/scan",          .method = HTTP_GET,  .handler = _handle_scan          },
};

void web_server_start(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.lru_purge_enable = true;

    if (httpd_start(&_server, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return;
    }

    for (size_t i = 0; i < sizeof(_routes) / sizeof(_routes[0]); i++) {
        httpd_register_uri_handler(_server, &_routes[i]);
    }
    ESP_LOGI(TAG, "HTTP server started — %d endpoints registered",
             (int)(sizeof(_routes) / sizeof(_routes[0])));
}

void web_server_stop(void)
{
    if (_server) {
        httpd_stop(_server);
        _server = NULL;
    }
}
