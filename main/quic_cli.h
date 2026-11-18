#ifndef QUIC_CLI_H
#define QUIC_CLI_H
#include <stdint.h>

/* 自包含 QUIC v1 客户端（RFC 9000/9001 + TLS1.3 RFC 8446 + X25519 RFC 7748）。
 * 对齐 Go underlay_quic.go dialQuic：ALPN "openp2pv1"、InsecureSkipVerify（只验
 * server Finished，跳证书内容）、默认版本 v1、stream0 上跑 openp2p 裸帧。
 * 密码学全自写（SHA256/HMAC/HKDF/GHASH/GCM/X25519），复用 openp2p.c 的 AES 仅为其
 * 他模块保留，本文件内部零 mbedtls 依赖（规避 medium profile 禁解密的历史坑）。 */
typedef struct quic_conn quic_conn_t;

/* 完整建链：bind local_port → Initial(ClientHello,pad≥1200) → 收 Initial/Handshake →
 * 派生密钥 → 发 Finished → 1RTT stream0 发 [4/2][LE64 tid] → 等 [4/3] body。
 * 失败返回 NULL（内部已清理）。tid=relay 隧道 id（Go connectUnderlayUDP server 校验）。 */
quic_conn_t *quic_connect(int local_port, const char *peer_ip, int peer_port,
                          uint64_t tid, int timeout_ms);

/* stream0 写（自动切 STREAM 帧+封包+PN++）。返回 0 成功。 */
int quic_stream_write(quic_conn_t *c, const uint8_t *data, int len);

/* rxbuf 里已有缓存的 stream 字节（select 前置检查，避免缓存期 select 干等 UDP）。 */
int quic_rx_ready(quic_conn_t *c);

/* 精确读 need 字节（先尽 rxbuf 缓存，再收 UDP 解密补），超时返回 <0。 */
int quic_stream_read(quic_conn_t *c, uint8_t *dst, int need, int timeout_ms);

int quic_udp_fd(quic_conn_t *c);

/* 差分实验：非空则 quic_connect 无视 relay 地址、强拨该 ip:port（PC 侧 quicdbg 服务器验
   我方 Initial 能否被真 quic-go v0.34 接受）。实验后必须置回 NULL。 */
void quic_debug_peer(const char *ip, int port);          /* 底层 UDP fd（仅供 select 监视） */
void quic_close(quic_conn_t *c);
int quic_selftest(void);                  /* 全部原语 known-answer 自检，0=OK */

#endif
