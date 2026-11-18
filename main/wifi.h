#ifndef WIFI_H
#define WIFI_H

#include "esp_err.h"

/* 启动 STA 并按 config.h 的 SSID/PASS 连接，阻塞直至拿到 IP 或超时。
 * timeout_sec：等待 IP_EVENT_STA_GOT_IP 的秒数。
 * 成功 ESP_OK；超时 ESP_ERR_TIMEOUT。 */
esp_err_t wifi_sta_connect(int timeout_sec);

#endif /* WIFI_H */
