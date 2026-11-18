#include "wss.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include "esp_log.h"
#include "oplog.h"                                                                	/* 编译期日志开关（config.h OPENP2P_LOG_ON）——必须在 esp_log.h 之后 */
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"    /* gethostbyname */
#include "lwip/sys.h"

#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "psa/crypto.h"   /* mbedTLS 4.0：SHA1/RNG 走 PSA；entropy/sha1/base64 头已移除 */

static const char *TAG = "wss";

static SemaphoreHandle_t s_ws_tx;     /* Go 控制面 writeMtx 对位(p2pnetwork.go:969/:1015)——同一 WSS conn 的一切写者(业务 send/push/send_heartbeat/pong)互斥；mbedTLS 记录层并发写=帧字节交织坏链 */

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define TLS_RECV_TIMEOUT_MS 40000    /* 对齐 Go readLoop 内层钟 :927 SetReadDeadline(NetworkHeartbeatTime+10=40s)——帧中途 40s 零新字节=字节流死；原 15s 无源码依据 */
#define TLS_SEND_TIMEOUT_MS 30000    /* 对齐 Go write() :971 SetWriteDeadline(NetworkHeartbeatTime=30s)——WANT_WRITE 假活封顶 */
#define TLS_RCV_GRAN_MS 1000         /* 应用数据期 recv 唤醒颗粒=1s，ctrl_rx 1s 片与 RPC 轮询的落地基础；握手期保持 15s 阻塞兜底（握手期若 1s，空口丢包重传窗会让 mbedtls_ssl_handshake 吃到 WANT_READ 直接散伙） */

/* ---------- 标准 base64 编码（避免 PSA base64 的 CONFIG 依赖） ---------- */

static const char s_b64tab[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode(const unsigned char *in, size_t inlen, char *out, size_t outsz)
{
	size_t o = 0;
	for (size_t i = 0; i < inlen; i += 3) {
		unsigned v = (unsigned)in[i] << 16;
		if (i + 1 < inlen) v |= (unsigned)in[i + 1] << 8;
		if (i + 2 < inlen) v |= (unsigned)in[i + 2];
		if (o + 1 < outsz) out[o++] = s_b64tab[(v >> 18) & 63];
		if (o + 1 < outsz) out[o++] = s_b64tab[(v >> 12) & 63];
		if (i + 1 < inlen && o + 1 < outsz) out[o++] = s_b64tab[(v >> 6) & 63];
		if (i + 2 < inlen && o + 1 < outsz) out[o++] = s_b64tab[v & 63];
	}
	if (inlen % 3) {
		if (o + 1 < outsz) out[o++] = '=';
		if (inlen % 3 == 1 && o + 1 < outsz) out[o++] = '=';
	}
	if (o + 1 < outsz) out[o] = 0;
	return o;
}

/* ---------- 自定义 bio（lwip socket 后端） ---------- */

static int my_send(void *ctx, const unsigned char *buf, size_t len)
{
	int fd = (int)(intptr_t)ctx;
	int n = send(fd, buf, len, 0);
	return (n < 0) ? -1 : n;
}

static int my_recv(void *ctx, unsigned char *buf, size_t len)
{
	int fd = (int)(intptr_t)ctx;
	int n = recv(fd, buf, len, 0);
	/* mbedTLS bio 语义：recv 无数据/超时(-1)→ 返回 WANT_READ 让上层重试；
	   只有 recv==0（对端关闭/EOF）才返回 0。返回 0 会被 mbedTLS 判为 CONN_EOF。 */
	if (n < 0) return MBEDTLS_ERR_SSL_WANT_READ;
	return n;
}

static int my_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout_ms)
{
	/* 不在此改 SO_RCVTIMEO：socket 已在 tcp_connect 设好 15s 阻塞超时。
	   mbedTLS 握手完成后调 f_recv_timeout 时传入 timeout = conf->read_timeout，
	   而本实现未设 read_timeout → timeout_ms 恒为 0。若据此 setsockopt(SO_RCVTIMEO,0)
	   会把 socket 变非阻塞、recv 立即返回，破坏对服务器 101 响应的阻塞等待
	   （握手阶段传的是 retransmit_timeout>0，故握手能过、一读应用数据就失败）。
	   因此直接复用 socket 的阻塞超时，委托 my_recv。 */
	(void)timeout_ms;
	return my_recv(ctx, buf, len);
}

static int tcp_connect(const char *host, int port)
{
	struct hostent *he = gethostbyname(host);
	if (!he || !he->h_addr_list[0]) {
		ESP_LOGE(TAG, "DNS 解析 %s 失败", host);
		return -1;
	}
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)port);
	memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof(addr.sin_addr));

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}
	/* 默认 recv 超时，保护阻塞式 recv（socket 级兜底） */
	struct timeval tv;
	tv.tv_sec = 15;                                  /* 握手期 15s 阻塞兜底——空口丢包 lwIP 重传窗不得提前触发 WANT_READ 打断 mbedtls_ssl_handshake（升级成功后 wss_connect 尾部改小颗粒） */
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	struct timeval sto;                              /* 对齐 Go write() :971 SetWriteDeadline(NetworkHeartbeatTime=30s)——sndbuf 满时 send 阻塞有界，非无限等 */
	sto.tv_sec = TLS_SEND_TIMEOUT_MS / 1000;
	sto.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &sto, sizeof(sto));
	return fd;
}

/* ---------- 底层 TLS 读写 ---------- */

static esp_err_t tls_write(wss_t *w, const unsigned char *buf, size_t len)
{
	mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)w->ssl;
	uint32_t t0 = xTaskGetTickCount();                /* 30s 发窗总钟基线 */
	uint32_t tmo_ticks = TLS_SEND_TIMEOUT_MS / portTICK_PERIOD_MS;
	while (len > 0) {
		int n = mbedtls_ssl_write(ssl, buf, len);
		if (n > 0) { buf += n; len -= n; continue; }
		if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
			if ((uint32_t)(xTaskGetTickCount() - t0) >= tmo_ticks) { ESP_LOGE(TAG, "tls_write 发窗30s超顶(Go write() :971-974 write deadline -> close 一票判死)"); return ESP_FAIL; }     /* Go write() 30s 死线对位——SO_SNDTIMEO 到点 send 报 EAGAIN 转 WANT，无总钟则 2ms 空转=假活 */
			vTaskDelay(pdMS_TO_TICKS(2));   /* 非阻塞写：让出 CPU 再重试 */
			continue;
		}
		ESP_LOGE(TAG, "tls_write rc=-0x%x", -n);
		return ESP_FAIL;
	}
	return ESP_OK;
}

/* 读最多 want 字节；got=0 表示对端关闭(EOF)。
   mbedTLS 语义：f_recv 无数据→ mbedtls_ssl_read 返回 WANT_READ/WANT_WRITE（负码），
   本函数须循环重试直到拿到数据或总超时（防死循环）；对端关闭(recv==0)→ 返回 0。 */
static esp_err_t tls_read(wss_t *w, unsigned char *buf, size_t want, size_t *got, uint32_t ms)     /* ms=本次等待总钟（首字节由 wss_recv_frame 传 timeout_ms 实现 1s 片；帧中段传 40s=Go :927 内层钟） */
{
	mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)w->ssl;
	size_t total = 0;
	uint32_t t0 = xTaskGetTickCount();
	uint32_t tmo_ticks = ms / portTICK_PERIOD_MS;
	while (total < want) {
		int n = mbedtls_ssl_read(ssl, buf + total, want - total);
		if (n > 0) { total += n; continue; }
		if (n == 0) { *got = total; return ESP_OK; }   /* EOF */
		if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
			if ((uint32_t)(xTaskGetTickCount() - t0) >= tmo_ticks) return ESP_ERR_TIMEOUT;
			vTaskDelay(pdMS_TO_TICKS(2));             /* 让网络栈收包，再重试 */
			continue;
		}
		if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) { *got = total; return ESP_OK; }
		char eb[96];
		mbedtls_strerror(n, eb, sizeof(eb));
		ESP_LOGE(TAG, "tls_read rc=-0x%x (%s)", -n, eb);
		return ESP_FAIL;                               /* 真错误不再折成 ESP_ERR_TIMEOUT——Go :927-931 ReadMessage 任何 err 都 close(false)；TIMEOUT 只留给本函数 WANT 钟到时 */
	}
	*got = total;
	return ESP_OK;
}

/* ---------- 连接 + 握手 + Upgrade ---------- */

esp_err_t wss_connect(wss_t *w, const char *host, int port,
		const char *path_and_query,
		const unsigned char *ca_pem, size_t ca_len)
{
	memset(w, 0, sizeof(*w));
	w->sock = -1;
	w->ssl  = calloc(1, sizeof(mbedtls_ssl_context));
	w->ca   = calloc(1, sizeof(mbedtls_x509_crt));
	w->conf = calloc(1, sizeof(mbedtls_ssl_config));
	if (!w->ssl || !w->ca || !w->conf) { wss_close(w); return ESP_ERR_NO_MEM; }

	mbedtls_ssl_context *ssl  = (mbedtls_ssl_context *)w->ssl;
	mbedtls_x509_crt    *ca   = (mbedtls_x509_crt    *)w->ca;
	mbedtls_ssl_config  *conf = (mbedtls_ssl_config  *)w->conf;

	if (psa_crypto_init() != PSA_SUCCESS) {
		ESP_LOGE(TAG, "PSA crypto 初始化失败");
		wss_close(w);
		return ESP_FAIL;
	}

	int fd = tcp_connect(host, port);
	if (fd < 0) {
		ESP_LOGE(TAG, "TCP 连接 %s:%d 失败", host, port);
		wss_close(w);
		return ESP_FAIL;
	}
	w->sock = fd;

	mbedtls_x509_crt_init(ca);
	mbedtls_ssl_init(ssl);
	int prc = mbedtls_x509_crt_parse(ca, ca_pem, ca_len);
	if (prc != 0) {
		char eb[64];
		mbedtls_strerror(prc, eb, sizeof(eb));
		ESP_LOGE(TAG, "CA 解析失败 rc=-0x%x (%s) len=%zu head=%.5s",
				(int)(-prc) & 0xffff, eb, ca_len, (const char *)ca_pem);
		wss_close(w);
		return ESP_FAIL;
	}
	mbedtls_ssl_config_init(conf);
	/* mbedTLS 4.0：config_init 只建空壳（无 RNG/entropy/密码套件），必须再调
	   config_defaults 接上 ESP-IDF 硬件随机源 + 默认套件，否则握手报
	   HMAC_DRBG file I/O error（DRBG 无随机源，回退读文件失败）。 */
	mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	/* 锁定 TLS 1.2：本构建 mbedTLS 4.0 对 TLS1.3 的 NewSessionTicket
	   post-handshake 消息处理是实验性的——服务器发 NewSessionTicket 时
	   mbedtls_ssl_read 返回 -0x7b00("Received NewSessionTicket")，打断读 101；
	   TLS1.2 无 NewSessionTicket 机制，握手后直接进应用数据，稳定。 */
	mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_max_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_setup(ssl, conf);
	/* mbedTLS 4.0：默认 RNG 走 PSA（esp32s3 硬件 RNG）；版本由编译配置决定（1.2/1.3 均开） */
	mbedtls_ssl_conf_ca_chain(conf, ca, NULL);
	mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_set_hostname(ssl, host);
	mbedtls_ssl_set_bio(ssl, (void *)(intptr_t)fd, my_send, my_recv, my_recv_timeout);

	int hr = mbedtls_ssl_handshake(ssl);
	if (hr != 0) {
		char eb[96];
		mbedtls_strerror(hr, eb, sizeof(eb));
		uint32_t vr = mbedtls_ssl_get_verify_result(ssl);
		ESP_LOGE(TAG, "TLS 握手失败 rc=-0x%04x (%s) verify=0x%08lx",
				(unsigned)(-hr) & 0xffff, eb, (unsigned long)vr);
		wss_close(w);
		return ESP_FAIL;
	}
	ESP_LOGI(TAG, "TLS 建立成功: %s", mbedtls_ssl_get_version(ssl));

	/* WebSocket Upgrade：随机 key → base64 */
	unsigned char key16[16];
	esp_fill_random(key16, sizeof(key16));
	char keyb64[32];
	b64_encode(key16, 16, keyb64, sizeof(keyb64));

	char req[600];
	int reqlen = snprintf(req, sizeof(req),
			"GET %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Upgrade: websocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Key: %s\r\n"
			"Sec-WebSocket-Version: 13\r\n"
			"\r\n",
			path_and_query, host, keyb64);
	if (tls_write(w, (unsigned char *)req, (size_t)reqlen) != ESP_OK) { wss_close(w); return ESP_FAIL; }

	/* 读 HTTP 响应头（到 \r\n\r\n） */
	unsigned char hdr[1024];
	size_t hdrlen = 0, got = 0;
	while (hdrlen < sizeof(hdr) - 1) {
		if (tls_read(w, hdr + hdrlen, 1, &got, TLS_RECV_TIMEOUT_MS) != ESP_OK) { wss_close(w); return ESP_FAIL; }
		if (got == 0) { ESP_LOGE(TAG, "响应流意外结束"); wss_close(w); return ESP_FAIL; }
		hdrlen += got;
		hdr[hdrlen] = 0;
		if (hdrlen >= 4 && memcmp(hdr + hdrlen - 4, "\r\n\r\n", 4) == 0) break;
	}
	ESP_LOGI(TAG, "HTTP 响应: %s", (char *)hdr);
	if (strncmp((char *)hdr, "HTTP/1.1 101", 12) != 0 &&
	    strncmp((char *)hdr, "HTTP/1.0 101", 12) != 0) {
		ESP_LOGE(TAG, "非 101，WebSocket 升级失败");
		wss_close(w);
		return ESP_FAIL;
	}

	/* 校验 Sec-WebSocket-Accept = base64(SHA1(key + GUID)) */
	char keyguid[64];
	size_t klen = strlen(keyb64);
	size_t glen = strlen(WS_GUID);   /* GUID 固定 36 字符，勿写死 32（会漏末尾 '5B11' → accept 算错） */
	memcpy(keyguid, keyb64, klen);
	memcpy(keyguid + klen, WS_GUID, glen);
	unsigned char sha1[20];
	size_t sha1len = sizeof(sha1);
	if (psa_hash_compute(PSA_ALG_SHA_1, (const uint8_t *)keyguid, klen + glen,
			sha1, sizeof(sha1), &sha1len) != PSA_SUCCESS) {
		ESP_LOGE(TAG, "SHA1 计算失败");
		wss_close(w);
		return ESP_FAIL;
	}
	char accept[32];
	b64_encode(sha1, 20, accept, sizeof(accept));
	if (strstr((char *)hdr, accept) == NULL) {
		ESP_LOGE(TAG, "Sec-WebSocket-Accept 不匹配（期望 %s）", accept);
		wss_close(w);
		return ESP_FAIL;
	}

	w->last_rx = time(NULL);                                                     /* 入口基线（服务器首字节到达前不给 rx-silence 可乘之机） */
	struct timeval gran;                              /* 进应用数据期——recv 颗粒 15s→1s，ctrl_rx 1s 片与 RPC 轮询据此落地（TCP 字节流由 lwIP 重传保证，不再需要 15s 阻塞兜底） */
	gran.tv_sec = TLS_RCV_GRAN_MS / 1000;
	gran.tv_usec = TLS_RCV_GRAN_MS % 1000;
	setsockopt(w->sock, SOL_SOCKET, SO_RCVTIMEO, &gran, sizeof(gran));
	ESP_LOGI(TAG, "WebSocket 升级成功（key=%s）recv颗粒1s", keyb64);
	return ESP_OK;
}

/* ---------- 帧发送（客户端→服务器，必须 mask） ---------- */

esp_err_t wss_send_binary(wss_t *w, const unsigned char *payload, uint16_t len)
{
	unsigned char hdr[14];
	int n = 0;
	hdr[n++] = 0x82; /* FIN=1, opcode=2(binary) */
	if (len < 126) {
		hdr[n++] = 0x80 | (unsigned char)len;
	} else {
		hdr[n++] = 0x80 | 126;
		hdr[n++] = (len >> 8) & 0xFF;
		hdr[n++] = len & 0xFF;
	}
	unsigned char mask[4];
	esp_fill_random(mask, 4);
	memcpy(hdr + n, mask, 4);
	n += 4;

	unsigned char *frame = malloc((size_t)n + len);
	if (!frame) return ESP_ERR_NO_MEM;
	memcpy(frame, hdr, n);
	for (int i = 0; i < len; i++)
		frame[n + i] = payload[i] ^ mask[i & 3];
	if (!s_ws_tx) s_ws_tx = xSemaphoreCreateMutex();               /* 同 Go writeMtx——业务三写者+pong 串行 */
	xSemaphoreTake(s_ws_tx, portMAX_DELAY);
	esp_err_t e = tls_write(w, frame, (size_t)n + len);
	xSemaphoreGive(s_ws_tx);
	free(frame);
	return e;
}

/* ---------- 帧接收（服务器→客户端，无 mask） ---------- */

esp_err_t wss_recv_frame(wss_t *w, unsigned char *out, size_t outsz,
		size_t *outlen, int *opcode, int timeout_ms)
{
	unsigned char acc[2048];
	size_t acclen = 0;
	int first_opcode = -1;

	for (;;) {
		size_t got = 0;
		unsigned char b0, b1;
		esp_err_t e0 = tls_read(w, &b0, 1, &got, (timeout_ms > 0) ? (uint32_t)timeout_ms : TLS_RECV_TIMEOUT_MS);      /* timeout_ms 首次真正生效=首字节等待片（ctrl_rx 1s 片落地） */
		if (e0 != ESP_OK || got != 1) {
			if (e0 == ESP_OK) return ESP_FAIL;                                        /* got==0=对端 FIN/close_notify（Go readLoop io.EOF -> close(false) 一票判死；旧折 TIMEOUT 让半死连假活到钟响） */
			return e0;                                                                /* WANT 钟到=ESP_ERR_TIMEOUT 正常空闲重试，死权归 ctrl_rx 60s 零帧钟 */
			}
			w->last_rx = time(NULL);                                                  /* 服务器来一字节即触钟（控制面 rx-silence 半死判定唯一钟源） */
		if (tls_read(w, &b1, 1, &got, TLS_RECV_TIMEOUT_MS) != ESP_OK || got != 1) return ESP_FAIL;      /* b0 已到手，此后任何半帧丢（超时/EOF/真错）=字节流断——Go ReadMessage 整帧读 err 一律 close(false) */

		int fin = (b0 >> 7) & 1;
		int op  = b0 & 0x0F;
		int masked = (b1 >> 7) & 1;
		unsigned long len = b1 & 0x7F;
		if (len == 126) {
			unsigned char ext[2];
			if (tls_read(w, ext, 2, &got, TLS_RECV_TIMEOUT_MS) != ESP_OK || got != 2) return ESP_FAIL;
			len = ((unsigned long)ext[0] << 8) | ext[1];
		} else if (len == 127) {
			unsigned char ext[8];
			if (tls_read(w, ext, 8, &got, TLS_RECV_TIMEOUT_MS) != ESP_OK || got != 8) return ESP_FAIL;
			len = 0;
			for (int i = 0; i < 8; i++)
				len = (len << 8) | ext[i];
		}

		unsigned char mask[4] = {0};
		if (masked) {
			if (tls_read(w, mask, 4, &got, TLS_RECV_TIMEOUT_MS) != ESP_OK || got != 4) return ESP_FAIL;
		}
		if (len > sizeof(acc)) return ESP_ERR_INVALID_SIZE;

		size_t off = 0;
		while (off < len) {
			size_t want = len - off;
			if (tls_read(w, acc + off, want, &got, TLS_RECV_TIMEOUT_MS) != ESP_OK) return ESP_FAIL;     /* 帧中途败=字节流断（Go ReadMessage 帧级 deadline，err 即 close） */
			if (got == 0) return ESP_FAIL;                                      /* 中途 EOF */
			off += got;
		}
		if (masked) {
			for (size_t i = 0; i < len; i++)
				acc[i] ^= mask[i & 3];
		}

		if (op == 9) { /* ping → 回空 pong（客户端帧需 mask，mask 全 0 合法） */
			unsigned char pong[6] = {0x8A, 0x80, 0, 0, 0, 0};
			if (s_ws_tx) xSemaphoreTake(s_ws_tx, portMAX_DELAY);   /* pong 写者与业务写者同锁——Go 侧 gorilla 自动 pong 在读协程内写、与 readLoop 天然串行；C 形 ctrl_rx 与 send_heartbeat/业务跨任务并发必须显式互斥 */
			tls_write(w, pong, sizeof(pong));
			if (s_ws_tx) xSemaphoreGive(s_ws_tx);
			continue;
		}
		if (op == 10) continue;               /* pong，忽略 */
		if (op == 8) { *opcode = 8; *outlen = 0; return ESP_OK; } /* close */

		if (first_opcode < 0) first_opcode = op;
		if (acclen + len > outsz) return ESP_ERR_INVALID_SIZE;
		memcpy(out + acclen, acc, len);
		acclen += len;
		if (fin) break;                       /* 完整应用帧 */
	}

	*opcode = first_opcode;
	*outlen = acclen;
	return ESP_OK;
}

/* ---------- 关闭 ---------- */

void wss_close(wss_t *w)
{
	if (!w) return;
	if (w->ssl) {
		mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)w->ssl;
		mbedtls_ssl_close_notify(ssl);
		mbedtls_ssl_free(ssl);
		free(w->ssl);
		w->ssl = NULL;
	}
	if (w->conf) {
		mbedtls_ssl_config_free((mbedtls_ssl_config *)w->conf);
		free(w->conf);
		w->conf = NULL;
	}
	if (w->sock >= 0) { close(w->sock); w->sock = -1; }
	if (w->ca) {
		mbedtls_x509_crt_free((mbedtls_x509_crt *)w->ca);
		free(w->ca);
		w->ca = NULL;
	}
}
