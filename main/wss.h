/*
 * 极简 WebSocket-over-TLS 客户端（RFC6455 客户端子集）。
 *
 * 只实现 OpenP2P 登录所需：HTTP/1.1 Upgrade、binary 帧收发、
 * ping/pong、close。不引入 esp_websocket_client 组件，固件体积最小。
 * 传输层用 mbedTLS 的 net + ssl（ESP-IDF 内建，esp-tls 依赖链里已带），
 * 随机数用硬件 RNG（esp_fill_random）。
 */
#ifndef WSS_H
#define WSS_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include "esp_err.h"

typedef struct {
	int sock;   /* lwip TCP fd；-1 表示未连接 */
	void *ssl;  /* mbedtls_ssl_context */
	void *conf; /* mbedtls_ssl_config */
	void *ca;   /* mbedtls_x509_crt（根证书池） */
	time_t last_rx;                                             /* 控制面收侧钟——Go readLoop lastActive 对位；服务器来一字节即触钟；60s 零收=半死连（服务器/NAT 静默拆，send 仍入缓冲假活），弃窗走重登录自愈 */
} wss_t;

/* TCP 连接 host:port + TLS 握手 + WebSocket Upgrade。
 * path_and_query：以 '/' 开头，含 query（如 "/api/v1/login?token=..."）。
 * ca_pem / ca_len：PEM 根证书（可多张拼接）。
 * 成功 ESP_OK；任一步失败返回错误码。 */
esp_err_t wss_connect(wss_t *w, const char *host, int port,
		const char *path_and_query,
		const unsigned char *ca_pem, size_t ca_len);

/* 发送一个 binary 帧（客户端侧，自动 mask）。payload <= 65535。 */
esp_err_t wss_send_binary(wss_t *w, const unsigned char *payload, uint16_t len);

/* 接收一个完整应用帧（拼 continuation），返回 payload（不含帧头）。
 * opcode 输出：2=binary 8=close 9=ping 10=pong（-1 未知）。
 * out 需足够大（建议 >= 2048）。timeout_ms 用于每次底层读。
 * 成功 ESP_OK；超时/错误返回错误码。 */
esp_err_t wss_recv_frame(wss_t *w, unsigned char *out, size_t outsz,
		size_t *outlen, int *opcode, int timeout_ms);

/* 关闭 TLS 并释放资源。 */
void wss_close(wss_t *w);

#endif /* WSS_H */
