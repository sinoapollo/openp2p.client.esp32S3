/*
 * OpenP2P ESP32-S3 客户端 —— 入口
 *
 * NVS 初始化 + WiFi STA 连接 + 控制面（手写 WSS 登录 + 心跳保活）。
 * 凭据目前编译期占位（见 config.h），运行期改由 NVS 读取。
 */
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "oplog.h"                                                                	/* 编译期日志开关（config.h OPENP2P_LOG_ON）——必须在 esp_log.h 之后 */
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"

#include "p2p/p2p_protocol.h"
#include "config.h"
#include "wifi.h"
#include "cfg_store.h"
#include "http_cfg.h"
#include "openp2p.h"

static const char *TAG = "app";

void app_main(void)
{
	ESP_LOGI(TAG, "OpenP2P ESP32-S3 client starting (v%s)", OPENP2P_CLIENT_VERSION);

	/* NVS（token/SSID/PASS 存放处；运行期改用 NVS 读取） */
	esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	ESP_ERROR_CHECK(ret);
	ESP_LOGI(TAG, "NVS ready");
	cfg_init();                                                                       /* 载入 NVS 运行配置（空/损坏=config.h 编译期默认=现网固化态） */

	/* WiFi STA 连接（阻塞等待 IP） */
	ESP_LOGI(TAG, "连接 WiFi \"%s\" …", OPENP2P_WIFI_SSID);
	if (wifi_sta_connect(30) != ESP_OK) {
		ESP_LOGE(TAG, "WiFi 首次连接失败；openp2p 任务将因无网失败并循环重试");
	}

	/* 控制面：登录 + 心跳保活（独立任务，断开自动重连） */
	ESP_LOGI(TAG, "启动 openp2p 控制面任务（WSS 登录 + 心跳）");
	http_cfg_start();                                                                 /* 网页配置台（80）：WiFi 此前成败都起，连通即达 */
	openp2p_start();

	/* 主任务让出，控制面在 openp2p 任务里运行 */
#if OPENP2P_DIAG_ON                                                                  	/* 纯观测（行为监听）：堆打印环仅取证编译时在场 */
	for (;;) {
		vTaskDelay(pdMS_TO_TICKS(5000));
		ESP_LOGI(TAG, "idle free_heap=%u", (unsigned)esp_get_free_heap_size());
	}
#else
	for (;;) {
		vTaskDelay(pdMS_TO_TICKS(60000));                                                	/* 静默让出：实际功能全在连接环/控制面/rebuild 环等独立任务 */
	}
#endif
}
