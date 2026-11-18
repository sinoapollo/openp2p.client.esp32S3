/*
   * HTTP 网页配置台（2026-11-07 用户令）：80 端口手写 HTTP，单任务、每请求一连
    * （Connection: close），不引 esp_http_server、页面零 JS 依赖（仅"仅重启"按钮用 fetch）——省资源。
    * GET / → 配置表单；POST /save → 校验 + cfg_store_commit + 3s 后 esp_restart；POST /reboot → 立即重启。
    * 缓冲 PSRAM 优先（省内部 RAM），栈 6144。
    */
#include "http_cfg.h"
#include "cfg_store.h"
#include "openp2p.h"                    /* p2p_peer_snapshot：网页展示对等节点池+当前 dial 方（2026-11-18） */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "oplog.h"                                                                	/* 编译期日志开关（config.h OPENP2P_LOG_ON）——必须在 esp_log.h 之后 */
#include "esp_system.h"
#include "esp_netif.h"
#include "esp_heap_caps.h"
#include "lwip/sockets.h"

static const char *TAG = "hcfg";

#define REQ_HDR_CAP 1536
#define BODY_CAP     3072
#define PAGE_CAP     12288             /* 2026-11-18 加 token 区+对等节点池表，缓冲加大 */

static int send_all(int fd, const char *buf, int len)
{
	while (len > 0) {
		int w = send(fd, buf, len, 0);
		if (w <= 0) return -1;
		buf += w; len -= w;
	}
	return 0;
}

static void send_resp(int fd, int code, const char *ct, const char *body, int len)
{
	const char *st = code == 200 ? "OK" : code == 400 ? "Bad Request" : code == 404 ? "Not Found" : "Error";
	char hdr[256];
	int hl = snprintf(hdr, sizeof(hdr),
				"HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
			code, st, ct, len);
	send_all(fd, hdr, hl);
	if (len > 0) send_all(fd, body, len);
}

static void resp_msg(int fd, int code, const char *msg)
{
	char b[512];
	int l = snprintf(b, sizeof(b),
				"<!DOCTYPE html><meta charset='utf-8'><h3>%s</h3><p><a href='/'>返回配置页</a></p>", msg);
	send_resp(fd, code, "text/html; charset=utf-8", b, l);
}

static void urldecode(char *s)
{
	char *d = s, *p = s;
	while (*p) {
		if (*p == '%' && isxdigit((unsigned char)p[1]) && isxdigit((unsigned char)p[2])) {
			char hx[3] = { p[1], p[2], 0 };
			*d++ = (char)strtol(hx, NULL, 16);
			p += 3;
			} else if (*p == '+') { *d++ = ' '; p++; }
		else *d++ = *p++;
		}
	*d = 0;
}

static int form_get(const char *body, const char *key, char *out, int cap)
{
	int klen = (int)strlen(key);
	const char *p = body;
	while (p) {
		const char *amp = strchr(p, '&');
		int slen = amp ? (int)(amp - p) : (int)strlen(p);
		if (slen > klen && p[klen] == '=' && strncmp(p, key, klen) == 0) {
			int vl = slen - klen - 1;
			if (vl >= cap) vl = cap - 1;
			memcpy(out, p + klen + 1, vl);
			out[vl] = 0;
			urldecode(out);
			return 1;
			}
		p = amp ? amp + 1 : NULL;
		}
	out[0] = 0;
	return 0;
}

static const char *find_ci(const char *hay, const char *needle)
{
	int nl = (int)strlen(needle);
	for (const char *h = hay; *h; h++) {
		int i = 0;
		while (i < nl && h[i] && tolower((unsigned char)h[i]) == needle[i]) i++;
		if (i == nl) return h;
		}
	return NULL;
}

static void esc(char *dst, int cap, const char *src)
{
	int n = 0;
	for (const char *p = src; *p && n < cap - 1; p++) {
		const char *rep = NULL;
		switch (*p) {
		case '&': rep = "&amp;"; break;
		case '<': rep = "&lt;"; break;
		case '>': rep = "&gt;"; break;
		case '"': rep = "&quot;"; break;
		default: break;
			}
		if (rep) {
			int rl = (int)strlen(rep);
			if (n + rl >= cap - 1) break;
			memcpy(dst + n, rep, rl); n += rl;
			} else dst[n++] = *p;
		}
	dst[n] = 0;
}

static int ip_valid(const char *s)
{
	esp_ip4_addr_t a;
	return s && s[0] && esp_netif_str_to_ip4(s, &a) == ESP_OK;
}

static void emit(char **cur, char *end, const char *fmt, ...)
{
	if (*cur >= end) return;
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(*cur, (size_t)(end - *cur), fmt, ap);
	va_end(ap);
	if (n > 0) *cur += n;                                                            /* 超长时 cur 越过 end，后续 emit 由行首守卫吞掉 */
}

static void handle_page(int fd)
{
	char *pg = heap_caps_malloc(PAGE_CAP, MALLOC_CAP_SPIRAM);
	if (!pg) pg = malloc(PAGE_CAP);
	if (!pg) { resp_msg(fd, 400, "内存不足，页面无法生成"); return; }
	char *cur = pg, *end = pg + PAGE_CAP - 1;
	esp_netif_t *nif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
	esp_netif_ip_info_t ii; memset(&ii, 0, sizeof(ii));
	if (nif) esp_netif_get_ip_info(nif, &ii);

	emit(&cur, end, "<!DOCTYPE html><html><head><meta charset='utf-8'>"
			"<meta name='viewport' content='width=device-width,initial-scale=1'>"
			"<title>ESP32 OpenP2P 配置</title><style>"
			"body{font-family:sans-serif;margin:12px}"
			"table{border-collapse:collapse;margin:8px 0}"
			"td,th{border:1px solid #999;padding:3px 5px;font-size:14px}"
			"input{width:140px}h3{margin:14px 0 4px}"
			"</style></head><body>");
	emit(&cur, end, "<h2>ESP32 OpenP2P 配置台</h2>");
	emit(&cur, end, "<p>当前 IP：<b>" IPSTR "</b>　在用 SSID 档：%d<br>"
			"保存后约 3 秒自动重启（期间 3389/22/11434 会话会断）。</p>",
			IP2STR(&ii.ip), g_cfg.nprof);
	emit(&cur, end, "<form method='POST' action='/save'>");
	emit(&cur, end, "<h3>WiFi 档（第 1 行优先；能连哪个连哪个，断开自动重扫）</h3>"
			"<table><tr><th>#</th><th>SSID</th><th>密码</th><th>IP 获取</th>"
			"<th>静态 IP</th><th>网关(空=沿用)</th><th>DNS(空=沿用)</th></tr>");
	for (int i = 0; i < CFG_MAX_PROF; i++) {
		char e1[CFG_SSID_LEN * 6 + 1], e3[CFG_IPSTR * 6 + 1], e4[CFG_IPSTR * 6 + 1], e5[CFG_IPSTR * 6 + 1];
		esc(e1, sizeof(e1), g_cfg.prof[i].ssid);
		esc(e3, sizeof(e3), g_cfg.prof[i].ip);
		esc(e4, sizeof(e4), g_cfg.prof[i].gw);
		esc(e5, sizeof(e5), g_cfg.prof[i].dns);
		emit(&cur, end, "<tr><td>%d</td>"
				"<td><input name='s%d' value=\"%s\"></td>"
				"<td><input name='p%d' value=\"%s\" placeholder='********' title='8 个*=保留原密码，改动请清空重填'></td>"
				"<td><select name='m%d'><option value='0'>DHCP</option><option value='1'%s>静态</option></select></td>"
				"<td><input name='i%d' value=\"%s\" placeholder='192.168.1.50'></td>"
				"<td><input name='g%d' value=\"%s\" placeholder='空=沿用'></td>"
				"<td><input name='d%d' value=\"%s\" placeholder='223.5.5.5'></td></tr>",
				i + 1, i, e1, i, (g_cfg.prof[i].pass[0] ? "********" : ""), i, g_cfg.prof[i].ipmode == 1 ? " selected" : "", i, e3, i, e4, i, e5);
		}
	emit(&cur, end, "</table>");
	emit(&cur, end, "<h3>端口映射（对端目标 IP；空=用 OPENP2P_APP_DSTIP 兜底）</h3><table><tr><th>ESP32 端口</th><th>目标 IP</th></tr>");
	{
		char e1[CFG_IPSTR * 6 + 1];
		esc(e1, sizeof(e1), g_cfg.dst22);    emit(&cur, end, "<tr><td>22（SSH）</td><td><input name='t22' value=\"%s\"></td></tr>", e1);
		esc(e1, sizeof(e1), g_cfg.dst3389);  emit(&cur, end, "<tr><td>3389（RDP）</td><td><input name='t3389' value=\"%s\"></td></tr>", e1);
		esc(e1, sizeof(e1), g_cfg.dst8080);  emit(&cur, end, "<tr><td>8080（HTTP）</td><td><input name='t8080' value=\"%s\"></td></tr>", e1);
		esc(e1, sizeof(e1), g_cfg.dst11434); emit(&cur, end, "<tr><td>11434（ollama）</td><td><input name='t11434' value=\"%s\"></td></tr>", e1);
		}
	emit(&cur, end, "</table>");
	/* 登录凭据：token 只以等长 * 号呈现（不明文），保存时全 *=保留原值 */
	{
		char tokmask[CFG_TOKEN_LEN];
		int tl = (int)strlen(g_cfg.token);
		if (tl >= CFG_TOKEN_LEN) { tl = CFG_TOKEN_LEN - 1; }
		for (int m = 0; m < tl; m++) { tokmask[m] = '*'; }
		tokmask[tl] = 0;
		emit(&cur, end, "<h3>登录凭据（等长 * 号=保留当前值；改动请清空重填）</h3><table><tr><th>OpenP2P Token</th></tr>"
				"<tr><td><input name='tok' value=\"%s\" style='width:240px' placeholder='全*=保留当前 token'></td></tr></table>", tokmask);
	}
	/* 对等节点池（只读）：服务器下发的 Nodes[] + 各节点在线/NatType/成败 + 当前 dial 方 */
	{
		p2p_peer_info_t pi[8];
		int pn = p2p_peer_snapshot(pi, 8);
		emit(&cur, end, "<h3>对等节点池（服务器下发；★=当前 dial 方）</h3><table><tr><th>#</th><th>节点</th><th>在线</th><th>NatType</th><th>成功</th><th>失败</th><th>状态</th></tr>");
		if (pn == 0) emit(&cur, end, "<tr><td colspan='7'>尚未收到服务器 Nodes[]（未登录 / SDWANInfo 未到）</td></tr>");
		for (int i = 0; i < pn; i++) {
			char nm[48]; esc(nm, sizeof(nm), pi[i].name);
			const char *on = pi[i].online ? "在线" : "离线";
			const char *st = pi[i].active ? "★ 使用中" : "";
			emit(&cur, end, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td></tr>",
					i + 1, nm, on, pi[i].nattype, pi[i].ok, pi[i].fail, st);
		}
		emit(&cur, end, "</table>");
	}
	emit(&cur, end, "<p>"
			"<button type='submit'>保存并重启</button> "
			"<button type='button' onclick=\"fetch('/reboot',{method:'POST'})\">仅重启不保存</button></p>");
	emit(&cur, end, "</form></body></html>");
	*cur = 0;
	send_resp(fd, 200, "text/html; charset=utf-8", pg, (int)strlen(pg));
	free(pg);
}

static void handle_save(int fd, const char *body)
{
	cfg_t tmp = g_cfg;                                                               /* 以现态为底，逐行覆盖 */
	int n = 0;
	for (int i = 0; i < CFG_MAX_PROF; i++) {
		char key[4], ssid[CFG_SSID_LEN], pass[CFG_PASS_LEN], mv[4], ip[CFG_IPSTR], gw[CFG_IPSTR], dns[CFG_IPSTR];
		snprintf(key, sizeof(key), "s%d", i);
		if (!form_get(body, key, ssid, sizeof(ssid)) || !ssid[0]) continue;          /* SSID 空=该行停用 */
		snprintf(key, sizeof(key), "p%d", i); form_get(body, key, pass, sizeof(pass));
		snprintf(key, sizeof(key), "m%d", i); form_get(body, key, mv, sizeof(mv));
		snprintf(key, sizeof(key), "i%d", i); form_get(body, key, ip, sizeof(ip));
		snprintf(key, sizeof(key), "g%d", i); form_get(body, key, gw, sizeof(gw));
		snprintf(key, sizeof(key), "d%d", i); form_get(body, key, dns, sizeof(dns));
		int mode = mv[0] == '1' ? 1 : 0;
		if (mode == 1 && !ip_valid(ip)) { resp_msg(fd, 400, "静态模式必须填合法的本机静态 IP"); return; }
		if (gw[0] && !ip_valid(gw)) { resp_msg(fd, 400, "网关格式非法"); return; }
		if (dns[0] && !ip_valid(dns)) { resp_msg(fd, 400, "DNS 格式非法"); return; }
		cfg_prof_t *pr = &tmp.prof[n++];
		memset(pr, 0, sizeof(*pr));
		strncpy(pr->ssid, ssid, CFG_SSID_LEN - 1);
		if (pass[0] && strcmp(pass, "********") != 0) {
			strncpy(pr->pass, pass, CFG_PASS_LEN - 1);                                    /* 非 8 星=用户填的新密码 */
		} else if (pass[0] && strcmp(pass, "********") == 0) {
			int oi = cfg_match_profile(ssid);                                             /* 8 星=保留该 SSID 原档密码 */
			if (oi >= 0) strncpy(pr->pass, g_cfg.prof[oi].pass, CFG_PASS_LEN - 1);
			/* 新 SSID（oi<0）填 8 星=无原值可留，pass 留空（=开放网络） */
		}
		pr->ipmode = (uint8_t)mode;
		if (mode == 1) strncpy(pr->ip, ip, CFG_IPSTR - 1);                           /* DHCP 档的 ip 输入忽略 */
		strncpy(pr->gw, gw, CFG_IPSTR - 1);
		strncpy(pr->dns, dns, CFG_IPSTR - 1);
		}
	if (n == 0) { resp_msg(fd, 400, "至少需要一个 SSID"); return; }
	tmp.nprof = n;
	{
		char tok[CFG_TOKEN_LEN];
		if (form_get(body, "tok", tok, sizeof(tok))) {
			int any = 0, allstar = 1;
			for (char *q = tok; *q; q++) { any = 1; if (*q != '*') allstar = 0; }
			if (any && !allstar) { strncpy(tmp.token, tok, CFG_TOKEN_LEN - 1); tmp.token[CFG_TOKEN_LEN - 1] = 0; }   /* 全 *=保留原 token（tmp 已=g_cfg）；空=沿用原值 */
		}
	}
	char t[CFG_IPSTR];
	form_get(body, "t22", t, sizeof(t));    if (t[0] && !ip_valid(t)) { resp_msg(fd, 400, "22 映射目标 IP 格式非法"); return; } strncpy(tmp.dst22, t, CFG_IPSTR - 1);
	form_get(body, "t3389", t, sizeof(t));  if (t[0] && !ip_valid(t)) { resp_msg(fd, 400, "3389 映射目标 IP 格式非法"); return; } strncpy(tmp.dst3389, t, CFG_IPSTR - 1);
	form_get(body, "t8080", t, sizeof(t));  if (t[0] && !ip_valid(t)) { resp_msg(fd, 400, "8080 映射目标 IP 格式非法"); return; } strncpy(tmp.dst8080, t, CFG_IPSTR - 1);
	form_get(body, "t11434", t, sizeof(t)); if (t[0] && !ip_valid(t)) { resp_msg(fd, 400, "11434 映射目标 IP 格式非法"); return; } strncpy(tmp.dst11434, t, CFG_IPSTR - 1);
	if (cfg_store_commit(&tmp) != ESP_OK) { resp_msg(fd, 400, "保存失败（NVS 写入失败）"); return; }
	ESP_LOGI(TAG, "网页已保存配置，3 秒后重启");
	resp_msg(fd, 200, "已保存。3 秒后自动重启，请稍候重开本页面");
	vTaskDelay(pdMS_TO_TICKS(3000));
	esp_restart();                                                                   /* 干净重建：WiFi 连接环/四口隧道全按新配置起 */
}

static void handle_conn(int fd)
{
	struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	char *req = heap_caps_malloc(REQ_HDR_CAP, MALLOC_CAP_SPIRAM);
	if (!req) req = malloc(REQ_HDR_CAP);
	if (!req) return;
	int total = 0, hlen = -1;
	while (total < REQ_HDR_CAP - 1) {
		int r = recv(fd, req + total, REQ_HDR_CAP - 1 - total, 0);
		if (r <= 0) break;
		total += r;
		req[total] = 0;
		char *eoh = strstr(req, "\r\n\r\n");
		if (eoh) { hlen = (int)(eoh - req) + 4; break; }
		}
	if (hlen < 0) { free(req); return; }                                             /* 请求头都没收全 */
	char method[8], path[64];
	if (sscanf(req, "%7s %63s", method, path) != 2) { free(req); return; }
	ESP_LOGI(TAG, "%s %s", method, path);
	if (strcmp(method, "GET") == 0 && strcmp(path, "/") == 0) {
		handle_page(fd);
		free(req);
		} else if (strcmp(method, "POST") == 0 && strcmp(path, "/save") == 0) {
		const char *cl = find_ci(req, "content-length:");
		int clen = cl ? atoi(cl + 15) : 0;
		if (clen < 0) clen = 0;
		if (clen > BODY_CAP - 1) clen = BODY_CAP - 1;
		char *body = heap_caps_malloc(BODY_CAP, MALLOC_CAP_SPIRAM);
		if (!body) body = malloc(BODY_CAP);
		if (!body) { free(req); return; }
		int have = total - hlen;                                                     /* 头里已捎带的 body 片段 */
		if (have > clen) have = clen;
		if (have > 0) memcpy(body, req + hlen, have);
		while (have < clen) {
			int r = recv(fd, body + have, clen - have, 0);
			if (r <= 0) break;
			have += r;
			}
		free(req);
		body[have] = 0;                                          /* 收尾 NUL：末字段靠它终止，裸 malloc 不置=末字段吃进堆垃圾（2026-11-07 真机"t11434 格式非法"误杀定罪） */
		if (have < clen) resp_msg(fd, 400, "body 截断");
		else handle_save(fd, body);                                                  /* 成功路径内 esp_restart 不返回 */
		free(body);
		} else if (strcmp(method, "POST") == 0 && strcmp(path, "/reboot") == 0) {
		free(req);
		resp_msg(fd, 200, "重启中…");
		vTaskDelay(pdMS_TO_TICKS(500));
		esp_restart();
		} else {
		resp_msg(fd, 404, "没有这个页面");
		free(req);
		}
}

static void hcfg_task(void *arg)
{
	int srv = socket(AF_INET, SOCK_STREAM, 0);
	if (srv < 0) { ESP_LOGE(TAG, "socket 失败 errno=%d", errno); return; }
	int yes = 1;
	setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(80);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		ESP_LOGE(TAG, "80 端口 bind 失败 errno=%d，配置台未启动", errno);
		close(srv);
		return;
		}
	listen(srv, 2);
	ESP_LOGI(TAG, "HTTP 配置台就绪：http://<ESP32-IP>/（80 端口）");
	for (;;) {
		fd_set rs; FD_ZERO(&rs); FD_SET(srv, &rs);
		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
		int s = select(srv + 1, &rs, NULL, NULL, &tv);
		if (s <= 0) continue;
		int c = accept(srv, NULL, NULL);
		if (c < 0) continue;
		handle_conn(c);
		close(c);
		}
}

void http_cfg_start(void)
{
	xTaskCreate(hcfg_task, "hcfg", 6144, NULL, 5, NULL);
}
