/*
   * WiFi STA 连接环（2026-11-07 用户令：多 SSID 配置，IP 策略跟着 SSID 走）。
   * 全通道 active 扫描 → 按 g_cfg 优先级表序命中第一档 → 连接 → GOT_IP 后按该档
   * 应用 IP 策略（static=先停 dhcpc 再 set，定案语义；dhcp=幂等 dhcpc 恢复）。
   * 断开不再直接 esp_wifi_connect，而是置 BIT_RESCAN 唤醒连接环重扫（AP 消失自动改连其他命中档）。
   * 注意：`GOT IP ... (STA 已获取 IPv4)` 日志行格式被外部取证脚本解析，禁改格式。
   */
#include "wifi.h"
#include "config.h"
#include "cfg_store.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "oplog.h"                                                                	/* 编译期日志开关（config.h OPENP2P_LOG_ON）——必须在 esp_log.h 之后 */
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_heap_caps.h"
#include "lwip/ip4_addr.h"                                                          /* ESP_IPADDR_TYPE_V4，手写 DNS 需要 */

static const char *TAG = "wifi";

#define BIT_GOT_IP   (1 << 1)
#define BIT_RESCAN   (1 << 2)                                                       /* 断开/换路 → 唤醒连接环重扫 */
#define SCAN_MAX_AP  24

static EventGroupHandle_t s_evt;
static esp_netif_t *s_nif;                                                          /* v6.1：create_default_wifi_sta 返回 esp_netif_t*（非 esp_err_t），直接保存 */
static char s_cur_ssid[CFG_SSID_LEN];                                               /* 本环正在连/已连的 SSID，GOT_IP 后据此查档 */

/* GOT_IP 后按当前 SSID 对应档应用 IP 策略（定案语义：dhcpc active 时 set_ip_info 被拒——先停客户端）。 */
static void apply_profile_ip(void)
{
	int idx = cfg_match_profile(s_cur_ssid);
	if (idx < 0) return;                                                            /* 无档（理论不达）：维持 DHCP 现址 */
	cfg_prof_t *pr = &g_cfg.prof[idx];
	if (pr->ipmode == 0) {
		esp_netif_dhcpc_start(s_nif);                                               /* 幂等：本就 active 则无副作用；static 档切来后靠此恢复 */
		ESP_LOGI(TAG, "SSID \"%s\" 档=DHCP（已确保 DHCP active）", pr->ssid);
		return;
		}
	if (pr->ip[0] == 0) return;
	esp_ip4_addr_t want;
	if (esp_netif_str_to_ip4(pr->ip, &want) != ESP_OK) { ESP_LOGE(TAG, "档静态 IP 解析失败：%s", pr->ip); return; }
	esp_netif_ip_info_t si; memset(&si, 0, sizeof(si));
	if (esp_netif_get_ip_info(s_nif, &si) != ESP_OK) return;
	if (pr->gw[0] && esp_netif_str_to_ip4(pr->gw, &si.gw) != ESP_OK)                /* 指定网关则覆盖 DHCP 派值；解析失败沿用 */
		ESP_LOGW(TAG, "网关解析失败，沿用 DHCP 值：%s", pr->gw);
	if (si.ip.addr == want.addr && !pr->gw[0]) return;                               /* 同址且未指定网关=无事（原 语义） */
	si.ip = want;                                                                    /* 关键：目标 IP 写进待设结构——缺此行则 set 回写 DHCP 现址且每次重发 GOT_IP（2026-11-07 真机 .188 风暴定罪） */                              /* 同址且未指定网关=无事（原 语义） */
	esp_netif_dhcpc_stop(s_nif);                                                    /* 真机定罪：不停 dhcpc 则 set_ip_info 直接拒绝 */
	if (esp_netif_set_ip_info(s_nif, &si) != ESP_OK) {                              /* 兜底：设不成恢复 DHCP 保连通，宁可漂移也别断网 */
		ESP_LOGW(TAG, "固定 IP 设置失败，回滚 DHCP");
		esp_netif_dhcpc_start(s_nif);
		return;
		}
	if (pr->dns[0]) {                                                               /* 空=沿用 DHCP 派 DNS；非空=强制（部分路由器派 0.0.0.0 毒 DNS 的对策） */
		esp_ip4_addr_t pdns; esp_netif_dns_info_t dns; memset(&dns, 0, sizeof(dns));
		if (esp_netif_str_to_ip4(pr->dns, &pdns) == ESP_OK) {
			dns.ip.u_addr.ip4 = pdns; dns.ip.type = ESP_IPADDR_TYPE_V4;             /* IDF v6.1：宏名带 ESP_ 前缀 */
			if (esp_netif_set_dns_info(s_nif, ESP_NETIF_DNS_MAIN, &dns) != ESP_OK)
				ESP_LOGW(TAG, "DNS %s 设置失败", pr->dns);
			} else ESP_LOGW(TAG, "DNS 解析失败：%s", pr->dns);
		}
	ESP_LOGI(TAG, "固定 IP 已上 " IPSTR "（gw " IPSTR "，DNS %s，DHCP 已停）",
			IP2STR(&si.ip), IP2STR(&si.gw), pr->dns[0] ? pr->dns : "沿用");
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
	if (base == WIFI_EVENT) {
		if (id == WIFI_EVENT_STA_CONNECTED) {
			ESP_LOGI(TAG, "STA 已关联 AP");
			} else if (id == WIFI_EVENT_STA_DISCONNECTED) {
			wifi_event_sta_disconnected_t *d = (wifi_event_sta_disconnected_t *)data;
			ESP_LOGW(TAG, "断开 reason=%d，重新扫描选路…", d->reason);              /* 不再裸 esp_wifi_connect：多 SSID 归环统一重扫 */
			xEventGroupClearBits(s_evt, BIT_GOT_IP);
			xEventGroupSetBits(s_evt, BIT_RESCAN);
			}
		} else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
		ip_event_got_ip_t *gi = (ip_event_got_ip_t *)data;                          /* 事件载荷含 IPv4 */
		ESP_LOGI(TAG, "GOT IP " IPSTR " (STA 已获取 IPv4)", IP2STR(&gi->ip_info.ip));      /* 验收脚本按此行解析 ESP32 实际 IP，格式勿改 */
		xEventGroupSetBits(s_evt, BIT_GOT_IP);
		apply_profile_ip();                                                         /* 按当前 SSID 档归位固定 IP / 确保 DHCP */
		}
}

/* 连接环：扫描→命中档→连→等断开→重扫。断开/连接失败都回到环顶重扫（AP 消失自动改连其他命中 SSID）。 */
static void conn_task(void *arg)
{
	wifi_ap_record_t *aps = heap_caps_malloc(SCAN_MAX_AP * sizeof(wifi_ap_record_t), MALLOC_CAP_SPIRAM);
	if (!aps) aps = malloc(SCAN_MAX_AP * sizeof(wifi_ap_record_t));
	for (;;) {
		if (!aps) { ESP_LOGE(TAG, "扫描缓冲分配失败，30s 后重试"); vTaskDelay(pdMS_TO_TICKS(30000)); continue; }
		xEventGroupClearBits(s_evt, BIT_RESCAN);
		wifi_scan_config_t sc; memset(&sc, 0, sizeof(sc));                          /* 全通道 active 扫描 */
		if (esp_wifi_scan_start(&sc, true) != ESP_OK) { ESP_LOGW(TAG, "扫描失败，10s 后重试"); vTaskDelay(pdMS_TO_TICKS(10000)); continue; }
		uint16_t n = SCAN_MAX_AP;
		if (esp_wifi_scan_get_ap_num(&n) != ESP_OK) n = 0;
		if (n > SCAN_MAX_AP) n = SCAN_MAX_AP;
		if (n && esp_wifi_scan_get_ap_records(&n, aps) != ESP_OK) n = 0;
		int pick = -1;
		for (int p = 0; p < g_cfg.nprof && pick < 0; p++) {                         /* 表序=优先级，命中第一个 */
			if (!g_cfg.prof[p].ssid[0]) continue;
			for (int j = 0; j < n; j++)
				if (strcmp((char *)aps[j].ssid, g_cfg.prof[p].ssid) == 0) { pick = p; break; }
			}
		if (pick < 0) { ESP_LOGW(TAG, "扫到 %d 个 AP，配置 SSID 未出现，10s 后重扫", n); vTaskDelay(pdMS_TO_TICKS(10000)); continue; }
		wifi_config_t wc; memset(&wc, 0, sizeof(wc));
		strncpy((char *)wc.sta.ssid, g_cfg.prof[pick].ssid, sizeof(wc.sta.ssid) - 1);
		strncpy((char *)wc.sta.password, g_cfg.prof[pick].pass, sizeof(wc.sta.password) - 1);
		wc.sta.threshold.authmode = g_cfg.prof[pick].pass[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
		if (esp_wifi_set_config(WIFI_IF_STA, &wc) != ESP_OK) { ESP_LOGE(TAG, "set_config 失败，3s 后重扫"); vTaskDelay(pdMS_TO_TICKS(3000)); continue; }
		strncpy(s_cur_ssid, g_cfg.prof[pick].ssid, sizeof(s_cur_ssid) - 1);
		s_cur_ssid[sizeof(s_cur_ssid) - 1] = 0;
		ESP_LOGI(TAG, "尝试连接 \"%s\"（第 %d 优先）", s_cur_ssid, pick + 1);
		if (esp_wifi_connect() != ESP_OK) { ESP_LOGW(TAG, "esp_wifi_connect 拒绝，3s 后重扫"); vTaskDelay(pdMS_TO_TICKS(3000)); continue; }
		EventBits_t b = xEventGroupWaitBits(s_evt, BIT_GOT_IP | BIT_RESCAN, pdFALSE, pdFALSE, portMAX_DELAY);
		if (b & BIT_RESCAN) { xEventGroupClearBits(s_evt, BIT_RESCAN); vTaskDelay(pdMS_TO_TICKS(3000)); continue; }   /* 关联失败/即断：回环顶重扫 */
		xEventGroupWaitBits(s_evt, BIT_RESCAN, pdTRUE, pdTRUE, portMAX_DELAY);      /* 在线：等断开事件置 RESCAN */
		}
}

esp_err_t wifi_sta_connect(int timeout_sec)
{
	s_evt = xEventGroupCreate();
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	s_nif = esp_netif_create_default_wifi_sta();                                    /* v6.1 教训：返回 esp_netif_t*，不可 ESP_ERROR_CHECK 包裹 */

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL);
	esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, NULL);

	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_start());
	ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));                                 /* 性能：默认省电 MIN_MODEM 按 DTIM 睡，下行包延迟最多信标×DTIM——关之 */
	xTaskCreate(conn_task, "wconn", 4096, NULL, 5, NULL);                           /* 连接环任务（含首扫，首连也归它） */

	EventBits_t b = xEventGroupWaitBits(s_evt, BIT_GOT_IP, pdFALSE, pdTRUE,
			pdMS_TO_TICKS(timeout_sec * 1000));
	if (!(b & BIT_GOT_IP)) {
		ESP_LOGE(TAG, "WiFi 连接超时（%ds；连接环仍在后台重扫）", timeout_sec);
		return ESP_ERR_TIMEOUT;
		}
	return ESP_OK;
}
