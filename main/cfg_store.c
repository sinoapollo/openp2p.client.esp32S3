/*
  * cfg_store 实现：NVS "cfg" 命名空间。键表：
  *   n=u8 档数；s<i>/p<i>/i<i>/g<i>/d<i>=字符串；m<i>=u8(0/1)；t22/t3389/t8080/t11434=映射。
  * 读取宽容（缺键回默认）、提交严格（先全写 NVS，commit 成功才改内存态）。
 */
#include "cfg_store.h"
#include "config.h"

#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "oplog.h"                                                                	/* 编译期日志开关（config.h OPENP2P_LOG_ON）——必须在 esp_log.h 之后 */
#include "nvs.h"

static const char *TAG = "cfg";

cfg_t g_cfg;

static void set_default(void)
{
	memset(&g_cfg, 0, sizeof(g_cfg));
	g_cfg.nprof = 1;
	strncpy(g_cfg.prof[0].ssid, OPENP2P_WIFI_SSID, CFG_SSID_LEN - 1);
	strncpy(g_cfg.prof[0].pass, OPENP2P_WIFI_PASS, CFG_PASS_LEN - 1);
	g_cfg.prof[0].ipmode = 1;                                           /* 现状=静态 */
	strncpy(g_cfg.prof[0].ip, OPENP2P_STA_IP, CFG_IPSTR - 1);
																		/* gw 留空=沿用 DHCP 派网关（实测语义） */
	strncpy(g_cfg.prof[0].dns, "223.5.5.5", CFG_IPSTR - 1);             /* 部分路由器 DHCP 派 DNS=0.0.0.0，默认强制公共 DNS 兜底（可经网页改） */
	strncpy(g_cfg.dst22, OPENP2P_DST_22, CFG_IPSTR - 1);
	strncpy(g_cfg.dst3389, OPENP2P_DST_3389, CFG_IPSTR - 1);
	strncpy(g_cfg.dst8080, OPENP2P_DST_8080, CFG_IPSTR - 1);
	strncpy(g_cfg.dst11434, OPENP2P_DST_11434, CFG_IPSTR - 1);
	strncpy(g_cfg.token, OPENP2P_TOKEN, CFG_TOKEN_LEN - 1);   /* NVS 空时兜底=编译期默认 token */
}

static void rd_str(nvs_handle_t h, const char *key, const char *def, char *out)
{
	size_t sz = CFG_IPSTR;                                              /* 仅用于 i/g/d 类短字段 */
	if (nvs_get_str(h, key, out, &sz) != ESP_OK) strncpy(out, def, CFG_IPSTR - 1);
	out[CFG_IPSTR - 1] = 0;
}

void cfg_init(void)
{
	set_default();
	nvs_handle_t h;
	if (nvs_open("cfg", NVS_READONLY, &h) != ESP_OK) {
		ESP_LOGW(TAG, "NVS 无配置，用 config.h 编译期默认（=现网固化态）");
		return;
	}
	uint8_t n = 0;
	if (nvs_get_u8(h, "n", &n) == ESP_OK && n >= 1 && n <= CFG_MAX_PROF) {
		cfg_t t;
		memset(&t, 0, sizeof(t));
		t.nprof = n;
		char key[8];
		int bad = 0;
		for (int i = 0; i < (int)n && !bad; i++) {
			size_t sz;
			snprintf(key, sizeof(key), "s%d", i);
			sz = sizeof(t.prof[i].ssid);
			if (nvs_get_str(h, key, t.prof[i].ssid, &sz) != ESP_OK || t.prof[i].ssid[0] == 0) { bad = 1; break; }
			snprintf(key, sizeof(key), "p%d", i);
			sz = sizeof(t.prof[i].pass);
			if (nvs_get_str(h, key, t.prof[i].pass, &sz) != ESP_OK) t.prof[i].pass[0] = 0;   /* 开放网络合法 */
			snprintf(key, sizeof(key), "m%d", i);
			uint8_t m = 0;
			if (nvs_get_u8(h, key, &m) != ESP_OK) m = 0;
			t.prof[i].ipmode = m ? 1 : 0;
			snprintf(key, sizeof(key), "i%d", i); rd_str(h, key, "", t.prof[i].ip);
			snprintf(key, sizeof(key), "g%d", i); rd_str(h, key, "", t.prof[i].gw);
			snprintf(key, sizeof(key), "d%d", i); rd_str(h, key, "", t.prof[i].dns);
			if (t.prof[i].ipmode == 1 && t.prof[i].ip[0] == 0) {        /* 静态但 IP 空=脏档，整表退默认 */
				bad = 1;
			}
		}
		if (!bad) g_cfg = t;
		else ESP_LOGW(TAG, "NVS SSID 表损坏，本段退默认");
	}
	rd_str(h, "t22", OPENP2P_DST_22, g_cfg.dst22);                 /* 键缺→编译期默认；键在(含空串)→原样采用（空=用兜底 dstIP） */
	rd_str(h, "t3389", OPENP2P_DST_3389, g_cfg.dst3389);
	rd_str(h, "t8080", OPENP2P_DST_8080, g_cfg.dst8080);
	rd_str(h, "t11434", OPENP2P_DST_11434, g_cfg.dst11434);
	{ size_t tsz = sizeof(g_cfg.token); if (nvs_get_str(h, "token", g_cfg.token, &tsz) != ESP_OK || g_cfg.token[0] == 0) strncpy(g_cfg.token, OPENP2P_TOKEN, CFG_TOKEN_LEN - 1); g_cfg.token[CFG_TOKEN_LEN - 1] = 0; }    /* 键缺/空→编译默认；非空→NVS 权威 */
	nvs_close(h);
	ESP_LOGI(TAG, "配置在用：SSID 档=%d，映射 22→%s 3389→%s 8080→%s 11434→%s",
				g_cfg.nprof, g_cfg.dst22, g_cfg.dst3389, g_cfg.dst8080, g_cfg.dst11434);
}

int cfg_match_profile(const char *ssid)
{
	if (!ssid || !ssid[0]) return -1;
	for (int i = 0; i < g_cfg.nprof; i++)
		if (g_cfg.prof[i].ssid[0] && strcmp(g_cfg.prof[i].ssid, ssid) == 0) return i;
	return -1;
}

esp_err_t cfg_store_commit(const cfg_t *c)
{
	if (c->nprof < 1 || c->nprof > CFG_MAX_PROF) return ESP_ERR_INVALID_ARG;
	nvs_handle_t h;
	if (nvs_open("cfg", NVS_READWRITE, &h) != ESP_OK) return ESP_FAIL;
	if (nvs_erase_all(h) != ESP_OK) { nvs_close(h); return ESP_FAIL; }
	char key[8];
	nvs_set_u8(h, "n", (uint8_t)c->nprof);
	for (int i = 0; i < c->nprof; i++) {
		snprintf(key, sizeof(key), "s%d", i); nvs_set_str(h, key, c->prof[i].ssid);
		snprintf(key, sizeof(key), "p%d", i); nvs_set_str(h, key, c->prof[i].pass);
		snprintf(key, sizeof(key), "m%d", i); nvs_set_u8(h, key, c->prof[i].ipmode);
		snprintf(key, sizeof(key), "i%d", i); nvs_set_str(h, key, c->prof[i].ip);
		snprintf(key, sizeof(key), "g%d", i); nvs_set_str(h, key, c->prof[i].gw);
		snprintf(key, sizeof(key), "d%d", i); nvs_set_str(h, key, c->prof[i].dns);
	}
	nvs_set_str(h, "t22", c->dst22);
	nvs_set_str(h, "t3389", c->dst3389);
	nvs_set_str(h, "t8080", c->dst8080);
	nvs_set_str(h, "t11434", c->dst11434);
	if (c->token[0]) nvs_set_str(h, "token", c->token);        /* token 非空才落盘（空=沿用编译默认） */
	if (nvs_commit(h) != ESP_OK) { nvs_close(h); return ESP_FAIL; }
	nvs_close(h);
	g_cfg = *c;                                                          /* NVS 完整落盘后才全局生效（提交点唯一） */
	ESP_LOGI(TAG, "配置落盘：档=%d 映射 22→%s 3389→%s 8080→%s 11434→%s",
				c->nprof, c->dst22, c->dst3389, c->dst8080, c->dst11434);
	return ESP_OK;
}
