/* quic_cli.c — 自包含 QUIC v1 客户端（RFC 9000 帧/包 + RFC 9001 密钥 + TLS1.3 + X25519）
 * 对齐 underlay_quic.go dialQuic：quic.DialContext(...,
 * tlsConf{InsecureSkipVerify:true, NextProtos:["openp2pv1"]},
 * &quic.Config{Versions:默认v1, DisablePathMTUDiscovery:true}) + OpenStreamSync；
 * stream0 裸帧 [4/2][LE64 relay_tid] ↔ [4/3]"OpenP2P,hello2"（connectUnderlayUDP client 时序）。
 * 密码学：AES-ECB 复用 openp2p.c aes_block_enc；SHA256/HMAC/HKDF/GHASH/GCM 自写；
 * X25519 走 PSA（PSA_ALG_ECDH 0x09020000 即 raw agreement，MONTGOMERY 族 0x41，已核头文件）。 */
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "esp_log.h"
#include "oplog.h"                                                                	/* 编译期日志开关（config.h OPENP2P_LOG_ON）——必须在 esp_log.h 之后 */
#include "esp_timer.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "psa/crypto.h"
#include "quic_cli.h"

static const char TAG[] = "QUIC";

extern void aes_block_enc(const uint8_t in[16], uint8_t out[16], const uint8_t key[16]);

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t  i64;

static inline i64 now_ms(void) { return esp_timer_get_time() / 1000; }

/* ============================ SHA-256（FIPS 180-4）============================ */
typedef struct { u32 h[8]; u64 bits; u8 blk[64]; u32 bl; } sha256_ctx;

static const u32 SHA_K[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_init(sha256_ctx *s)
{
	s->h[0]=0x6a09e667; s->h[1]=0xbb67ae85; s->h[2]=0x3c6ef372; s->h[3]=0xa54ff53a;
	s->h[4]=0x510e527f; s->h[5]=0x9b05688c; s->h[6]=0x1f83d9ab; s->h[7]=0x5be0cd19;
	s->bits = 0; s->bl = 0;
}
static void sha256_transform(sha256_ctx *s, const u8 *p)
{
	u32 w[64], a,b,c,d,e,f,g,h,t1,t2;
	for (int i = 0; i < 16; i++) w[i] = ((u32)p[i*4]<<24)|((u32)p[i*4+1]<<16)|((u32)p[i*4+2]<<8)|p[i*4+3];
	for (int i = 16; i < 64; i++) {
		u32 s0 = ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3);
		u32 s1 = ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10);
		w[i] = w[i-16]+s0+w[i-7]+s1;
	}
	a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
	for (int i = 0; i < 64; i++) {
		u32 S1 = ROR(e,6)^ROR(e,11)^ROR(e,25);
		u32 ch = (e&f)^((~e)&g);
		t1 = h+S1+ch+SHA_K[i]+w[i];
		u32 S0 = ROR(a,2)^ROR(a,13)^ROR(a,22);
		u32 mj = (a&b)^(a&c)^(b&c);
		t2 = S0+mj;
		h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
	}
	s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void sha256_update(sha256_ctx *s, const u8 *m, size_t n)
{
	if (!n) return;
	s->bits += (u64)n * 8;
	while (n) {
		u32 take = 64 - s->bl; if (take > n) take = (u32)n;
		memcpy(s->blk + s->bl, m, take); s->bl += take; m += take; n -= take;
		if (s->bl == 64) { sha256_transform(s, s->blk); s->bl = 0; }
	}
}
static void sha256_final(sha256_ctx s, u8 out[32])       /* 传值调用：fork transcript 用 */
{
	u8 pad[72]; u32 pl = 1;
	pad[0] = 0x80;
	while ((s.bl + pl) % 64 != 56) pad[pl++] = 0;
	for (int i = 0; i < 8; i++) pad[pl+i] = (u8)(s.bits >> (56 - 8*i));
	sha256_update(&s, pad, pl + 8);                                /* 必须含尾部 8B 长度字段：漏传则凑不满 64B 块、整块不 transform，摘要退化成 H0(6a09e667) */
	for (int i = 0; i < 8; i++) { out[i*4]=(u8)(s.h[i]>>24); out[i*4+1]=(u8)(s.h[i]>>16); out[i*4+2]=(u8)(s.h[i]>>8); out[i*4+3]=(u8)s.h[i]; }
}
static void sha256_1(const u8 *m, size_t n, u8 out[32]) { sha256_ctx s; sha256_init(&s); sha256_update(&s, m, n); sha256_final(s, out); }

/* ============================ HMAC-SHA256（RFC 2104）============================ */
static void hmac_sha256(const u8 *key, size_t klen, const u8 *msg, size_t mlen, u8 out[32])
{
	u8 k[64], ikey[64], okey[64], inner[32];
	memset(k, 0, 64);
	if (klen > 64) sha256_1(key, klen, k); else memcpy(k, key, klen);
	for (int i = 0; i < 64; i++) { ikey[i] = k[i]^0x36; okey[i] = k[i]^0x5c; }
	sha256_ctx s;
	sha256_init(&s); sha256_update(&s, ikey, 64); sha256_update(&s, msg, mlen); sha256_final(s, inner);
	sha256_init(&s); sha256_update(&s, okey, 64); sha256_update(&s, inner, 32); sha256_final(s, out);
}

/* ============================ HKDF（RFC 5869）+ Expand-Label（RFC 8446 §7.1）============================ */
static void hkdf_extract(const u8 *salt, size_t saltlen, const u8 *ikm, size_t ikmilen, u8 prk[32])
{
	static const u8 zeros[32];
	if (!salt || !saltlen) { salt = zeros; saltlen = 32; }
	hmac_sha256(salt, saltlen, ikm, ikmilen, prk);
}
static void hkdf_expand(const u8 prk[32], const u8 *info, size_t ilen, u8 *okm, size_t olen)
{
	u8 t[32], c = 1, buf[128]; size_t done = 0, hl = 0;                 /* 定罪修复：RFC5869 T(i)=HMAC-SHA256(PRK, T(i-1)||info||i)。原实现写成裸 SHA256、PRK 没参与 → Expand-Label 全退化成 label 常量（取证 PLAINSHA 假设 KEY/SEC/CI 三连命中；KEY 跨轮相同只是其表象） */
	while (done < olen) {
		if (ilen > 90) { memset(okm, 0, olen); return; }
		hl = 0;
		if (c > 1) { memcpy(buf, t, 32); hl = 32; }
		memcpy(buf + hl, info, ilen); hl += ilen;
		buf[hl++] = c;
		hmac_sha256(prk, 32, buf, hl, t);
		size_t take = olen - done; if (take > 32) take = 32;
		memcpy(okm + done, t, take);
		done += take; c++;
	}
}
/* TLS1.3 Expand-Label：Info = u8(len("tls13 "+label)) ‖ "tls13 "+label ‖ u8(len(ctx)) ‖ ctx */
static void el_label(const u8 secret[32], const char *label, const u8 *ctx, size_t ctxlen, u8 *out, size_t olen)
{
	u8 info[128]; size_t ll = 6 + strlen(label), p = 0;
	info[p++] = (u8)(olen >> 8); info[p++] = (u8)(olen & 0xff); info[p++] = (u8)ll;      /* G01：HkdfLabel 前缀=uint16 输出长度+uint8 label长 共3B（RFC8446 7.1/aioquic tls.py:179 struct.pack("!HB",length,len(full_label)) 双源定案）；旧两字节 [00][ll] 让 ll 占了 length 低字节、label 长字节丢失，info 整体错位一格=QUIC dial 恒 rx=0 真凶 */     /* HkdfLabel.length 是 uint16 大端两字节（RFC8446 7.1 / aioquic struct.pack("!H")）——原按 u8 单字节写 info 整体错位，client in/server in/quic key/iv/hp 派生全不匹配 */
	memcpy(info + p, "tls13 ", 6); p += 6;
	memcpy(info + p, label, ll - 6); p += ll - 6;
	info[p++] = (u8)ctxlen;
	if (ctxlen) { memcpy(info + p, ctx, ctxlen); p += ctxlen; }
	hkdf_expand(secret, info, p, out, olen);
}

/* ============================ GF(2^128) / GHASH / AES-GCM（SP800-38D）============================ */
static void gf_gmul(u8 y[16], const u8 h[16])            /* y ← y·h；反射域，R=0xE1 */
{
	u8 z[16], v[16];
	memset(z, 0, 16); memcpy(v, h, 16);
	for (int i = 0; i < 128; i++) {
		if ((y[i >> 3] >> (7 - (i & 7))) & 1) for (int j = 0; j < 16; j++) z[j] ^= v[j];
		int lsb = v[15] & 1;
		for (int j = 15; j > 0; j--) v[j] = (u8)((v[j] >> 1) | ((v[j-1] & 1) << 7));
		v[0] >>= 1;
		if (lsb) v[0] ^= 0xE1;
	}
	memcpy(y, z, 16);
}
static void ghash_blocks(u8 y[16], const u8 h[16], const u8 *p, size_t len)     /* 尾块零填充 */
{
	while (len >= 16) { for (int j = 0; j < 16; j++) y[j] ^= p[j]; gf_gmul(y, h); p += 16; len -= 16; }
	if (len) { u8 blk[16]; memset(blk, 0, 16); memcpy(blk, p, len); for (int j = 0; j < 16; j++) y[j] ^= blk[j]; gf_gmul(y, h); }
}
static void gcm_ctr(const u8 key[16], const u8 iv12[12], const u8 *in, size_t len, u8 *out)
{
	u8 ctr[16], ks[16];
	memcpy(ctr, iv12, 12);
	u32 c = 2;                                            /* J0=iv‖…01；首密文块计数器 J0+1 */
	while (len) {
		ctr[12]=(u8)(c>>24); ctr[13]=(u8)(c>>16); ctr[14]=(u8)(c>>8); ctr[15]=(u8)c; c++;
		aes_block_enc(ctr, ks, key);
		size_t take = len < 16 ? len : 16;
		for (size_t j = 0; j < take; j++) out[j] = in[j] ^ ks[j];
		in += take; out += take; len -= take;
	}
}
static void gcm_tag(const u8 key[16], const u8 iv12[12], const u8 *aad, size_t alen, const u8 *ct, size_t clen, u8 tag[16])
{
	u8 zero[16], h[16], y[16], last[16], s0[16];
	memset(zero, 0, 16);
	aes_block_enc(zero, h, key);                           /* H = E(K,0^16) */
	memset(y, 0, 16);
	ghash_blocks(y, h, aad, alen);
	ghash_blocks(y, h, ct, clen);
	memset(last, 0, 16);
	for (int i = 0; i < 8; i++) { last[i]=(u8)(((u64)alen*8) >> (56-8*i)); last[8+i]=(u8)(((u64)clen*8) >> (56-8*i)); }
	for (int j = 0; j < 16; j++) y[j] ^= last[j];
	gf_gmul(y, h);
	u8 j0[16];                                                    /* J0 = IV‖0^31‖1（SP800-38D）：12B iv 直传当 16B 块会 overread 且值错 */
	memcpy(j0, iv12, 12); j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
	aes_block_enc(j0, s0, key);                          /* E(K,J0) */
	for (int j = 0; j < 16; j++) tag[j] = y[j] ^ s0[j];
}
static void gcm_encrypt(const u8 key[16], const u8 iv12[12], const u8 *aad, size_t alen, const u8 *pt, size_t plen, u8 *ct, u8 tag[16])
{
	gcm_ctr(key, iv12, pt, plen, ct);
	gcm_tag(key, iv12, aad, alen, ct, plen, tag);
}
static int gcm_decrypt(const u8 key[16], const u8 iv12[12], const u8 *aad, size_t alen, const u8 *ct, size_t clen, u8 *pt, const u8 tag[16])
{
	u8 calc[16];
	gcm_tag(key, iv12, aad, alen, ct, clen, calc);         /* 先验 tag 再出明文 */
	for (int j = 0; j < 16; j++) if (calc[j] != tag[j]) return -1;
	gcm_ctr(key, iv12, ct, clen, pt);
	return 0;
}

/* ============================ X25519（PSA，MONTGOMERY 族 0x41）============================ */
static int psa_x_makekey(psa_key_id_t *key, u8 pub[32])
{
	psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_type(&at, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&at, 255);
	psa_set_key_usage_flags(&at, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&at, PSA_ALG_ECDH);              /* raw agreement 即此 alg */
	psa_status_t st = psa_generate_key(&at, key);
	if (st != PSA_SUCCESS) { ESP_LOGE(TAG, "psa_generate_key %d", (int)st); return -1; }
	size_t ol = 0;
	st = psa_export_public_key(*key, pub, 32, &ol);
	if (st != PSA_SUCCESS || ol != 32) { ESP_LOGE(TAG, "psa_export_public_key %d ol=%u", (int)st, (unsigned)ol); psa_destroy_key(*key); return -1; }
	return 0;
}
static int psa_x_shared(psa_key_id_t key, const u8 peer[32], u8 out[32])
{
	size_t ol = 0;
	psa_status_t st = psa_raw_key_agreement(PSA_ALG_ECDH, key, peer, 32, out, 32, &ol);
	if (st != PSA_SUCCESS || ol != 32) { ESP_LOGW(TAG, "psa_raw_key_agreement %d ol=%u", (int)st, (unsigned)ol); return -1; }
	return 0;
}

/* ============================ QUIC varint（RFC 9000 §16）============================ */
static int vi_enc(u8 *o, u64 v)
{
	if (v < 0x40) { o[0]=(u8)v; return 1; }
	if (v < 0x4000) { o[0]=(u8)(0x40|(v>>8)); o[1]=(u8)v; return 2; }
	if (v < 0x40000000) { o[0]=(u8)(0x80|(v>>24)); o[1]=(u8)(v>>16); o[2]=(u8)(v>>8); o[3]=(u8)v; return 4; }
	o[0]=(u8)(0xc0|(v>>56));
	for (int i = 1; i < 8; i++) o[i]=(u8)(v >> (56 - 8*i));
	return 8;
}
static int vi_dec(const u8 *p, const u8 *end, u64 *v)     /* 返回消耗字节数，0=越界 */
{
	if (p >= end) return 0;
	int n = 1 << (p[0] >> 6);
	if (p + n > end) return 0;
	u64 r = p[0] & 0x3f;
	for (int i = 1; i < n; i++) r = (r << 8) | p[i];
	*v = r; return n;
}

/* ============================ 连接状态 ============================ */
#define QSP_INIT 0                                         /* packet space：Initial */
#define QSP_HS   1                                         /* Handshake */
#define QSP_APP  2                                         /* 1-RTT */
#define QST_INIT 0                                         /* TLS 进度 */
#define QST_SH   1                                         /* 已收 ServerHello，HS 密钥就绪 */
#define QST_APP  2                                         /* 已验 server Finished，app 密钥就绪 */
#define QCRX_SZ   1600                                     /* 每 space CRYPTO 重组（cert≈400B） */
#define QRX_SZ    8192                                     /* stream0 接收缓存（单帧可到 4240B） */

struct quic_conn {
	int udp;
	struct sockaddr_in peer;
	/* 连接 ID */
	u8  dcid[20]; u8 dcid_len;                              /* 发往对端用（Retry/NCID 更新） */
	u8  odcid[20]; u8 odcid_len;                            /* 首挑 DCID = Initial 密钥盐（RFC 9001 5.2） */
	u8  scid[8];                                            /* 自报 SCID（对端回包 DCID 恒 8B） */
	u8  rtok[128]; u32 rtok_len;                            /* Retry token */
	/* 密钥：e=本端发送，d=解密对端 */
	u8  key_e[3][16], iv_e[3][12], hp_e[3][16];
	u8  key_d[3][16], iv_d[3][12], hp_d[3][16];
	int hp_ready[3];
	/* PN：pn_exp=连续收妥基（窗口解码基准），pnb=基上 64 位到达窗 */
	u64 pn_n[3];
	u64 pn_exp[3];
	u64 pnb[3];
	u64 ack_hi[3]; int ack_contig[3], ack_dirty[3];         /* 待 ACK：最高新包 + 是否 [0..hi] 连续 */
	/* TLS */
	sha256_ctx hs_sha;                                      /* transcript（CH 起累积） */
	psa_key_id_t xkey;
	u8  xpub[32];
	u8  peer_x[32];
	u8  fkey_s[32], fkey_c[32];
	u8  hs_sec[32];                                        /* handshake secret（app 密钥派生复用） */
	int st;
	/* 发送侧重传：最近数据报 FIFO + 对端 ACK 集 */
	u8 *sndbuf[8]; int sndlen[8]; u64 sndpn[8]; int snd_head, snd_cnt; i64 t_pend;
	u64 ack_base, ack_bits;                                /* pn<ack_base 已确认；bits=[base,base+63] */
	/* CRYPTO 重组 */
	u8  crx[3][QCRX_SZ]; u64 crx_next[3]; u32 crx_len[3];
	/* stream0 */
	u8  rxbuf[QRX_SZ]; u32 rx_len;
	u64 rx_off_next;
	u64 tx_off;
	/* 重传 */
	u8 *chmsg; u32 ch_len;                                  /* ClientHello 全文（重发复用） */
	u8  cfinmsg[36]; u32 cfin_len;                          /* 客户端 Finished */
	int init_sent, cfin_sent, hs42_sent;
	int got_server_init, got_app_rx, got_close;
	int rx_pkts, rx_bad;                    /* rx_pkts=收到任何 UDP 数据报数、rx_bad=AEAD tag 校验失败数：gi=0 定性（零回包 vs 收到解不开） */
	i64 t_init, t_fin, t_42;
	u64 tid;
};

/* ---------- AEAD nonce：iv ⊕ (0000‖PN 大端 8B) ---------- */
static void q_nonce(const u8 iv[12], u64 pn, u8 nonce[12])
{
	memcpy(nonce, iv, 12);
	for (int i = 0; i < 8; i++) nonce[4+i] ^= (u8)(pn >> (56 - 8*i));
}

/* ---------- PN 窗口解码（RFC 9000 A.3）---------- */
static u64 pn_decode(u64 exp, u64 trunc, int bits)
{
	u64 win = 1ULL << bits, half = win >> 1;
	u64 cand = (exp & ~(win - 1)) | trunc;
	if (cand < exp && (exp - cand) >= half) cand += win;
	if (cand > exp && (cand - exp) > half && cand >= win) cand -= win;
	return cand;
}

/* ---------- 收包登记 + ACK 帧构造（连续=[0..hi]；有洞=单包{hi}）---------- */
static void pn_mark_recv(quic_conn_t *c, int sp, u64 pn)
{
	int contig = 0;
	if (pn == c->pn_exp[sp]) {
		c->pn_exp[sp]++;
		while (c->pnb[sp] & 1) { c->pn_exp[sp]++; c->pnb[sp] >>= 1; }   /* 填洞推进连续基 */
		contig = 1;
	} else if (pn > c->pn_exp[sp]) {
		u64 off = pn - c->pn_exp[sp];
		if (off < 64) c->pnb[sp] |= 1ULL << off;
	}                                                          /* pn<基=重传，仍 ACK */
	if (c->ack_dirty[sp] && c->ack_hi[sp] >= pn) { }            /* 已有更高：保留 */
	else { c->ack_hi[sp] = pn; c->ack_contig[sp] = contig; c->ack_dirty[sp] = 1; }
}
static int pn_build_ack(u8 *o, u64 hi, int contig)
{
	int n = vi_enc(o, 0x02);
	n += vi_enc(o+n, hi);
	n += vi_enc(o+n, 0);                                        /* ack_delay */
	n += vi_enc(o+n, 0);                                        /* ack_range_count */
	n += vi_enc(o+n, contig ? hi : 0);                          /* first_ack_range */
	return n;
}

static void log_dump(const char *nm, const u8 *d, int n)             /* 串口取证：40B/行分块 hex，供 aioquic 离线对拍 */
{
	static const char X[] = "0123456789abcdef";
	char line[88];
	for (int off = 0; off < n; off += 40) {
		int m = n - off; if (m > 40) m = 40;
		int q = 0;
		for (int i = 0; i < m; i++) { line[q++] = X[d[off+i] >> 4]; line[q++] = X[d[off+i] & 15]; }
		line[q] = 0;
		ESP_LOGI(TAG, "DUMP %s %03d %s", nm, off, line);
		vTaskDelay(pdMS_TO_TICKS(2));                                 /* 逐行排空 UART 环形缓冲：WIRE 1202B 恒被截到 1000B(25行)，密文尾+GCM tag 正是取证最需要却全丢的段 */
	}
}
/* ---------- 发送一个包（长头/短头 + AEAD + header protection）---------- */
static int q_send(quic_conn_t *c, int sp, const u8 *frames, int flen, int pad_to, u8 *pkt_out, int pkt_cap, int *pkt_len)
{
	int pnlen = 2;
	u8 *fr = malloc(1500);
	u8 *b  = malloc(1600);
	if (!fr || !b) { free(fr); free(b); return -1; }
	int fn = 0;
	if (c->ack_dirty[sp]) {                                     /* ACK 前置 */
		fn = pn_build_ack(fr, c->ack_hi[sp], c->ack_contig[sp]);
		c->ack_dirty[sp] = 0;
	}
	if (flen) memcpy(fr + fn, frames, flen);
	int fpay = fn + flen;
	if (fpay < 20) { memset(fr + fpay, 0, 20 - fpay); fpay = 20; }     /* PADDING 凑 HP 采样位 */
	if (sp == QSP_INIT && pad_to >= 1200) {                     /* 首 Initial 数据报 ≥1200（RFC 8.1） */
		int est = 1+4+1+c->dcid_len+1+8+1+2+fpay+16;
		if (c->rtok_len) { u8 tb[4]; est += vi_enc(tb, (u64)c->rtok_len) + (int)c->rtok_len; }
		if (est < pad_to) { int add = pad_to - est; if (add > 0) { memset(fr + fpay, 0, add); fpay += add; } }     /* 原 -4 让整报文=1198<1200：quic-go v0.34 服务器对过短 Initial 静默丢弃零回包（rx=0 根因），est 少计 length varint 的 2 字节，去掉 -4 后 ≈1202 */
	}
	u64 pn = c->pn_n[sp];
	int p = 0, pn_off;
	if (sp <= QSP_HS) {
		b[p++] = (sp == QSP_HS ? 0xE0 : 0xC0) | (pnlen - 1);    /* 最终版长头（quic-go/aioquic encode_long_header_first_byte 实证）：bit7=1|bit6=fixed|bits5-4=type(INIT=00→0xCx，HS=10→0xE0|pn)；上一轮按 draft 布局改 0x9x/0xDx 反而错，aioquic 全量 [recv] 日志判死 */    /* 长头 1|TT|1|LL（RFC 9000 17.2）：Initial TT=00→0x9x，Handshake TT=10→0xDx；原 0xC0/0xE0 把 Initial 标成 TT=10（服务器读作 Handshake 静默丢）、Handshake 标成 TT=11（Retry）——relay rx=0 悬案根因，aioquic 差分实证 */
		b[p++]=0; b[p++]=0; b[p++]=0; b[p++]=1;                 /* version 1 */
		b[p++] = c->dcid_len; memcpy(b+p, c->dcid, c->dcid_len); p += c->dcid_len;
		b[p++] = 8; memcpy(b+p, c->scid, 8); p += 8;
		if (sp == QSP_INIT) {
			p += vi_enc(b+p, (u64)c->rtok_len);
			if (c->rtok_len) { memcpy(b+p, c->rtok, c->rtok_len); p += c->rtok_len; }
			}
		p += vi_enc(b+p, (u64)pnlen + fpay + 16);                /* length = PN+payload+tag */
		pn_off = p;
	} else {
		b[p++] = 0x40 | (pnlen - 1);                             /* 短头 fixed bit */
		memcpy(b+p, c->dcid, c->dcid_len); p += c->dcid_len;
		pn_off = p;
	}
	if (pn_off + pnlen > 64) { free(b); free(fr); return -1; }
	u8 aad[64];
	memcpy(aad, b, pn_off); for (int i = 0; i < pnlen; i++) aad[pn_off+i] = (u8)(pn >> (8*(pnlen-1-i)));      /* AAD=包头+真实 PN 字节（RFC9001 5.3）——原 memset 置零仅 pn=0 侥幸同值，pn>0 AEAD 全灭 */
	for (int i = 0; i < pnlen; i++) b[pn_off+i] = (u8)(pn >> (8*(pnlen-1-i)));
	u8 nonce[12]; q_nonce(c->iv_e[sp], pn, nonce);
	memcpy(b + pn_off + pnlen, fr, fpay);
	int total = pn_off + pnlen + fpay;
	gcm_encrypt(c->key_e[sp], nonce, aad, (u8)(pn_off + pnlen), fr, fpay, b + total - fpay, b + total);
	total += 16;
	if (total - (pn_off + 4) >= 16) {                            /* header protection（RFC 9001 5.4） */
		u8 mask[16]; aes_block_enc(b + pn_off + 4, mask, c->hp_e[sp]);
		b[0] ^= (sp <= QSP_HS) ? (mask[0] & 0x0f) : (mask[0] & 0x1f);     /* RFC9000 5.4.2 定案（aioquic 实测 head=c1^0x04 验证）：长头只翻 bits3-0（unused+pnlen），翻 0x1f 会把 bit4（type 高位）搅乱→Initial 被读作 0-RTT——d7 头实证 */                                  /* RFC9000 5.4.2：长头短头 HP 统一翻 bits4-0（含 fixed），对端 unmask 同 ^0x1f 还原 */
		for (int i = 0; i < pnlen; i++) b[pn_off+i] ^= mask[1+i];
	}
	free(fr);
	if (pkt_len) *pkt_len = 0;
	if (pkt_out && pkt_len && total <= pkt_cap) { memcpy(pkt_out, b, total); *pkt_len = total; }
	if (sp == QSP_INIT && c->init_sent == 0) {
			ESP_LOGI(TAG, "首 Initial 数据报 %d B（RFC 9000 §8.1 客户端 MUST ≥1200，quic-go 服务器对短包静默丢弃）", total);
			ESP_LOGI(TAG, "INITMETA pn=%u total=%d pn_off=%d fpay=%d pnlen=%d", (unsigned)pn, total, pn_off, fpay, pnlen);
			log_dump("NONCE", nonce, 12);
			log_dump("AAD", aad, pn_off + pnlen);
			log_dump("WIRE", b, total);                          /* HP 掩蔽后的线上字节，aioquic 离线解包定位 AEAD bug */
		}
	ssize_t w = sendto(c->udp, b, total, 0, (struct sockaddr *)&c->peer, sizeof(c->peer));
	free(b);
	if (w != total) { ESP_LOGW(TAG, "sendto %zd/%d errno=%d", w, total, errno); return -1; }
	c->pn_n[sp]++;
	return 0;
}

/* ============================ 密钥调度（RFC 9001 5.2 + RFC 8446 7.1）============================ */
static const u8 Q_SALT[20] = { 0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
                               0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a    /* RFC9001 5.2 v1 salt 全20字节，aioquic crypto.py:18 对账定案；原后8字节 64c398f27e74c3ea 手抄错=Initial AEAD 全灭 rx=0 根因 */ };

static void q_space_keys(const u8 secret[32], u8 key16[16], u8 iv12[12], u8 hp16[16])
{
	el_label(secret, "quic key", 0, 0, key16, 16);
	el_label(secret, "quic iv",  0, 0, iv12,  12);
	el_label(secret, "quic hp",  0, 0, hp16,  16);
}
static void q_initial_keys(quic_conn_t *c)
{
	u8 sec[32], ci[32], si[32];
	hkdf_extract(Q_SALT, 20, c->odcid, c->odcid_len, sec);      /* salt=Initial salt, ikm=odcid */
	el_label(sec, "client in", 0, 0, ci, 32);
	el_label(sec, "server in", 0, 0, si, 32);
	q_space_keys(ci, c->key_e[QSP_INIT], c->iv_e[QSP_INIT], c->hp_e[QSP_INIT]);
	q_space_keys(si, c->key_d[QSP_INIT], c->iv_d[QSP_INIT], c->hp_d[QSP_INIT]);
	c->hp_ready[QSP_INIT] = 1;
	log_dump("SEC", sec, 32);                                      /* 取证二分：SEC≠py(HMAC(salt,odcid))→ikm/HMAC层被劫持；SEC=py而KEY≠py→病灶在 el_label */
	log_dump("CI", ci, 32);
	log_dump("KEY",  c->key_e[QSP_INIT], 16);                     /* 我方从 odcid 派生的 client 密钥，与 aioquic derive_initial_secrets 对拍 */
	log_dump("IV",   c->iv_e[QSP_INIT], 12);
	log_dump("HPK",  c->hp_e[QSP_INIT], 16);
	log_dump("DCID", c->odcid, c->odcid_len);
}

/* ============================ ClientHello（TLS1.3 单组 x25519）============================ */
static u8 *put_ext(u8 *p, u32 et, const u8 *body, u32 blen)
{
	p[0] = (u8)(et >> 8); p[1] = (u8)et;
	p[2] = (u8)(blen >> 8); p[3] = (u8)blen;
	memcpy(p + 4, body, blen);
	return p + 4 + blen;
}
static int build_ch(quic_conn_t *c)                             /* 写入 c->chmsg，返回总长 */
{
	u8 *msg = c->chmsg;
	u8 *p = msg + 4;
	*p++ = 3; *p++ = 3;
	esp_fill_random(p, 32); p += 32;                             /* client_random */
	*p++ = 0;                                                    /* session id 空（不做 0-RTT/psk） */
	*p++ = 0; *p++ = 2; *p++ = 0x13; *p++ = 0x01;                /* TLS_AES_128_GCM_SHA256 */
	*p++ = 1; *p++ = 0;                                          /* compression: null */
	u8 *extp = p; p += 2;
	static const u8 EG[] = {0x00,0x02,0x00,0x1d};                /* supported_groups: x25519 */
	static const u8 ES[] = {0x00,0x06,0x04,0x01,0x04,0x03,0x08,0x04}; /* sigalg rsa/ecdsa/ed25519 */
	static const u8 EA[] = {0x00,0x0A,0x09,'o','p','e','n','p','2','p','v','1'}; /* alpn */
	static const u8 EV[] = {0x01,0x03,0x04};                     /* supported_versions: TLS1.3 */
	static const u8 EK[] = {0x00,0x24,0x00,0x1d,0x00,0x20}      /* key_share 列表长=36：条目 group2+kexlen2+pubkey32；原 0x0022=34 少 2B → 解析越界 */;      /* key_share 头（x25519,32B） */
	p = put_ext(p, 0x000a, EG, sizeof EG);
	p = put_ext(p, 0x000d, ES, sizeof ES);
	p = put_ext(p, 0x0010, EA, sizeof EA);
	p = put_ext(p, 0x002f, EV, sizeof EV);
	u8 kb[6 + 32]; memcpy(kb, EK, 6); memcpy(kb + 6, c->xpub, 32);
	p = put_ext(p, 0x0033, kb, 6 + 32);
	u8 tp[80]; int tn = 0;                                        /* transport params（varint 值手工编码） */
u8 t1m[4] = {0x80,0x10,0x00,0x00};                                        /* G02：1MB=0x100000 的 4B varint={0x80,0x10,0,0}（(0x80&0x3f)<<24|0x10<<16）；旧首字节 0x81 低6位多1 实值=17MB（注释"1<<24|0x10<<16 ✓"自证算错），偏大无害但钉正 */
	u8 t2i[4] = {0x80,0x00,0x75,0x30};       /* idle 30000=0x7530：4 字节式 4B varint（原 {0xF5,0x30} 中 0xF5=11 前缀是 8 字节式，2B 缓冲不够消费 → EOF ValueError）*/      /* 30000=0x7530 → (0x80|0x75)=0xF5,0x30（原 0xB5 解出 13616） */                                      /* idle 30000ms */
	u8 t3i[2] = {0x45,0xAC};                                      /* packet 1452 */
	u8 t16[1] = {0x10};                                           /* max_streams 16 */
	#define TPPUT(t, arr, n) do { tp[tn++] = (t); tp[tn++] = (n); memcpy(tp + tn, arr, n); tn += (n); } while (0)
	TPPUT(0x01, t2i, 4);                                                       /* G02：PARAMS 表 0x01=max_idle_timeout=30000ms（旧 draft-29 编号把 idle 放 0x02/把 1MB 灌进 0x01≈4.95h 被服务器 min 压住才没炸） */                                          /* initial_max_data */
	TPPUT(0x03, t3i, 2);                                          /* max_packet_size */
	TPPUT(0x04, t1m, 4);                                          /* bidi_local */
	TPPUT(0x05, t1m, 4);                                          /* bidi_remote */
	TPPUT(0x06, t1m, 4);                                          /* uni_local */
	TPPUT(0x07, t1m, 4);                                          /* uni_remote */
	TPPUT(0x08, t16, 1);                                          /* initial_max_streams_bidi */
	TPPUT(0x09, t16, 1);                                          /* uni */
	p = put_ext(p, 0x0039, tp, (u32)tn);
	u32 el = (u32)(p - (extp + 2));
	extp[0] = (u8)(el >> 8); extp[1] = (u8)el;
	u32 hl = (u32)(p - (msg + 4));
	msg[0] = 1; msg[1] = (u8)(hl >> 16); msg[2] = (u8)(hl >> 8); msg[3] = (u8)hl;
	return (int)(p - msg);
}

/* ============================ TLS 消息（SH→hs 密钥；sFin→app 密钥+cfin）============================ */
static void q_path_response(quic_conn_t *c, int sp, const u8 data[16])
{
	u8 fr[17]; fr[0] = 0x1b; memcpy(fr + 1, data, 16);
	q_send(c, sp, fr, 17, 0, 0, 0, 0);
}

static void crx_feed(quic_conn_t *c, int sp, u64 off, const u8 *data, u32 len)
{
	if (!len) return;
	u64 base = c->crx_next[sp] - c->crx_len[sp];                 /* 缓冲窗基 = 最高连续基 - 现有长 */
	if (off < base) { u64 skip = base - off; if (skip >= len) return; data += skip; len -= (u32)skip; off = base; }
	if (off + len > base + QCRX_SZ) { ESP_LOGW(TAG, "crx overflow sp%d off%llu+%u", sp, (unsigned long long)off, len); return; }
	memcpy(c->crx[sp] + (u32)(off - base), data, len);
	if (off + len > c->crx_next[sp]) { c->crx_len[sp] = (u32)(off + len - base); c->crx_next[sp] = off + len; }
}
static void q_tls_msg(quic_conn_t *c, int sp, const u8 *m, u32 ml);   /* 前置声明 */
static void crx_drain(quic_conn_t *c, int sp)
{
	for (;;) {
		u32 len = c->crx_len[sp];
		if (len < 4) return;
		u8 *m = c->crx[sp];
		u32 ml = 4 + ((((u32)m[1]) << 16) | (((u32)m[2]) << 8) | m[3]);
		if (ml > QCRX_SZ) { ESP_LOGE(TAG, "tls msg len %u", ml); c->crx_len[sp] = 0; c->got_close = 1; return; }
		if (len < ml) return;                                     /* 不完整：等缺段重传 */
		q_tls_msg(c, sp, m, ml);
		memmove(m, m + ml, len - ml);                             /* crx_next 不动=基自动前移 */
		c->crx_len[sp] = len - ml;
	}
}

static void parse_server_hello(quic_conn_t *c, const u8 *m, u32 ml)
{
	const u8 *p = m + 4, *mend = m + ml;
	if (ml < 4 + 2 + 32 + 2 + 1 + 2) return;
	p += 2 + 32;                                                  /* legacy_version + random */
	p += 2;                                                       /* cipher suite */
	if (p >= mend) return;
	u8 sl = *p++; if (p + sl > mend) return; p += sl;              /* session id */
	if (p + 2 > mend) return;
	u32 eln_t = ((u32)p[0] << 8) | p[1]; p += 2;
	if (p + eln_t > mend) return;
	int got_ks = 0;
	while (p + 4 <= mend) {
		u32 et  = ((u32)p[0] << 8) | p[1];
		u32 eln = ((u32)p[2] << 8) | p[3]; p += 4;
		if (p + eln > mend) return;
		if (et == 0x0033 && eln >= 4 + 32) {                       /* key_share */
			u32 grp = ((u32)p[0] << 8) | p[1];
			u32 kl  = ((u32)p[2] << 8) | p[3];
			if (grp == 0x001d && kl == 32) { memcpy(c->peer_x, p + 4, 32); got_ks = 1; }
			}
		p += eln;
	}
	if (!got_ks) { ESP_LOGE(TAG, "SH 无 x25519 key_share"); c->got_close = 1; return; }
	sha256_update(&c->hs_sha, m, ml);                              /* transcript = CH ‖ SH */
	static const u8 zeros[32];
	u8 shared[32];
	if (psa_x_shared(c->xkey, c->peer_x, shared) != 0) { ESP_LOGE(TAG, "X25519 ECDH 失败"); c->got_close = 1; return; }
	u8 early[32], der0[32], h_sh[32], h_e0[32];
	hkdf_extract(zeros, 32, zeros, 32, early);                  /* Derive-Secret(0,"derived",SHA256("")) */
	sha256_1(0, 0, h_e0);
	el_label(early, "derived", h_e0, 32, der0, 32);
	hkdf_extract(der0, 32, shared, 32, c->hs_sec);                      /* handshake secret：ikm=X25519 ECDHE 共享密钥（RFC8446 7.1） */
	sha256_ctx f = c->hs_sha; sha256_final(f, h_sh);               /* H(CH‖SH) */
	el_label(c->hs_sec, "finished", h_e0, 32, c->fkey_s, 32);     /* finished key ctx=SHA256("")（RFC8446 7.1，双向同值） */
	el_label(c->hs_sec, "finished", h_e0, 32, c->fkey_c, 32);
	u8 s_s[32], s_c[32];
	el_label(c->hs_sec, "s hs traffic", h_sh, 32, s_s, 32);
	el_label(c->hs_sec, "c hs traffic", h_sh, 32, s_c, 32);
	q_space_keys(s_c, c->key_e[QSP_HS], c->iv_e[QSP_HS], c->hp_e[QSP_HS]);
	q_space_keys(s_s, c->key_d[QSP_HS], c->iv_d[QSP_HS], c->hp_d[QSP_HS]);
	c->hp_ready[QSP_HS] = 1;
	c->st = QST_SH;
	ESP_LOGI(TAG, "ServerHello ok，HS 密钥就绪");
}

static void verify_server_fin(quic_conn_t *c, const u8 *m, u32 ml)
{
	static const u8 zeros[32];
	if (ml != 36) { ESP_LOGE(TAG, "sFinished 长度 %u", ml); c->got_close = 1; return; }
	u8 cv[4] = { 0x14, 0, 0, 0x20 };                               /* Finished 验证：HMAC(finished_key, H(transcript ‖ [0x14,0,0,0x20,32B零]))。
	  * finished_key = hs_sec+"finished"+空上下文（双向同值）；
	  * transcript 此时已含 CH‖SH‖Cert‖CertVerify（q_tls_msg 逐条入哈希）；
	  * 此处只补本 Finished 的零占位形式再哈希。 */
	sha256_ctx f = c->hs_sha;
	sha256_update(&f, cv, 4);
	sha256_update(&f, zeros, 32);
	u8 hh[32], expv[32];
	sha256_final(f, hh);
	hmac_sha256(c->fkey_s, 32, hh, 32, expv);
	if (memcmp(expv, m + 4, 32) != 0) { ESP_LOGE(TAG, "server Finished 验签失败"); c->got_close = 1; return; }
	sha256_update(&c->hs_sha, m, ml);                              /* transcript += 真 verify_data */
	u8 hf[32]; sha256_ctx g = c->hs_sha; sha256_final(g, hf);
	u8 der1[32], master[32], s_ca[32], s_sa[32];
	el_label(c->hs_sec, "derived", hf, 32, der1, 32);
	hkdf_extract(der1, 32, zeros, 32, master);
	el_label(master, "c app traffic", hf, 32, s_ca, 32);
	el_label(master, "s app traffic", hf, 32, s_sa, 32);
	q_space_keys(s_ca, c->key_e[QSP_APP], c->iv_e[QSP_APP], c->hp_e[QSP_APP]);
	q_space_keys(s_sa, c->key_d[QSP_APP], c->iv_d[QSP_APP], c->hp_d[QSP_APP]);
	c->hp_ready[QSP_APP] = 1;
	u8 vf[32];
	hmac_sha256(c->fkey_c, 32, hf, 32, vf);                        /* 我的 Finished verify_data */
	c->cfinmsg[0] = 0x14; c->cfinmsg[1] = 0; c->cfinmsg[2] = 0; c->cfinmsg[3] = 0x20;
	memcpy(c->cfinmsg + 4, vf, 32);
	c->cfin_len = 36;
	c->st = QST_APP;
	ESP_LOGI(TAG, "TLS1.3 完成，app 密钥就绪");
}

static void q_tls_msg(quic_conn_t *c, int sp, const u8 *m, u32 ml)
{
	if (!ml) return;
	if (m[0] == 0x01) return;                                      /* HRR 不会出现（单组 x25519） */
	if (sp == QSP_INIT && c->st == QST_INIT && m[0] == 0x02) { parse_server_hello(c, m, ml); return; }
	if (sp == QSP_HS && c->st >= QST_SH) {
		if (m[0] == 0x14 && c->st == QST_SH) { verify_server_fin(c, m, ml); return; }
		sha256_update(&c->hs_sha, m, ml);                          /* Cert/CertVerify/Ticket：入 transcript */
		return;
		}
	ESP_LOGD(TAG, "tls msg sp%d type 0x%02x 忽略", sp, m[0]);
}

/* ============================ 发送侧 ACK 跟踪 + 原样重传 ============================ */
static void sent_mark_ack(quic_conn_t *c, u64 pn)
{
	if (pn < c->ack_base) return;
	if (pn - c->ack_base >= 64) return;
	c->ack_bits |= 1ULL << (pn - c->ack_base);
	if (pn == c->ack_base) while (c->ack_bits & 1) { c->ack_base++; c->ack_bits >>= 1; }
}
static int sent_acked(quic_conn_t *c, u64 pn)
{
	if (pn < c->ack_base) return 1;
	if (pn - c->ack_base >= 64) return 0;
	return (int)((c->ack_bits >> (pn - c->ack_base)) & 1);
}
static void q_check_retrans(quic_conn_t *c)
{
	if (!c->snd_cnt) return;
	while (c->snd_cnt && sent_acked(c, c->sndpn[c->snd_head])) {   /* 收割已确认头部 */
		free(c->sndbuf[c->snd_head]); c->sndbuf[c->snd_head] = 0;
		c->snd_head = (c->snd_head + 1) % 8; c->snd_cnt--;
		}
	if (!c->snd_cnt) return;
	i64 now = now_ms();
	if (now - c->t_pend < 500) return;
	c->t_pend = now;
	for (int i = 0; i < c->snd_cnt; i++) {                          /* 未确认数据报原样重发（同 PN 同文，对端去重） */
		int idx = (c->snd_head + i) % 8;
		if (!c->sndbuf[idx]) continue;
		sendto(c->udp, c->sndbuf[idx], c->sndlen[idx], 0, (struct sockaddr *)&c->peer, sizeof(c->peer));
		}
}

/* ============================ 帧解析（RFC 9000 §19）============================ */
static void q_parse_frames(quic_conn_t *c, int sp, const u8 *p, const u8 *end)
{
	u64 v1, v2, v3, v4;
	int k;
	while (p < end) {
		u8 t = *p++;
		switch (t) {
		case 0x00: case 0x01: break;                                /* PADDING/PING */
		case 0x02: case 0x03: {                                     /* ACK/ACK_ECN：仅对我方 app 数据有意义 */
			if (sp != QSP_APP) break;
			if (!(k = vi_dec(p, end, &v1))) return;
				p += k;         /* largest acked */
			if (!(k = vi_dec(p, end, &v2))) return;
				p += k;         /* delay */
			if (!(k = vi_dec(p, end, &v3))) return;
				p += k;         /* range count */
			if (!(k = vi_dec(p, end, &v4))) return;
				p += k;         /* first range */
			if (v4 >= 0x4000) return;
			u64 hi = v1, lo = v1 - v4;
			for (u64 x = lo; x <= hi; x++) sent_mark_ack(c, x);
			for (u64 i = 0; i < v3 && i < 64; i++) {
				u64 gap, rng;
				if (!(k = vi_dec(p, end, &gap))) return;
				p += k;
				if (!(k = vi_dec(p, end, &rng))) return;
				p += k;
				if (lo < gap + 2) return;
				hi = lo - gap - 2; lo = hi - rng;
				for (u64 x = lo; x <= hi; x++) sent_mark_ack(c, x);
				}
			break;
			}
		case 0x06: {                                                /* CRYPTO → TLS 重组 */
			u64 off, len;
			if (!(k = vi_dec(p, end, &off))) return;
				p += k;
			if (!(k = vi_dec(p, end, &len))) return;
				p += k;
			if (len > (u64)(end - p)) return;
			crx_feed(c, sp, off, p, (u32)len);
			p += len;
			crx_drain(c, sp);
			break;
			}
		case 0x08 ... 0x0f: {                                       /* STREAM：只认 stream0，按 offset 顺序入 rxbuf */
			int lenbit = t & 2, offbit = t & 4;
			u64 sid, off = 0, len;
			if (!(k = vi_dec(p, end, &sid))) return;
				p += k;
			if (offbit) { if (!(k = vi_dec(p, end, &off))) return;
				p += k; }
			if (lenbit) { if (!(k = vi_dec(p, end, &len))) return;
				p += k; }
			else len = (u64)(end - p);
			if (len > (u64)(end - p)) return;
			if (sid == 0) {
				if (off == c->rx_off_next) {
					if (c->rx_len + len <= QRX_SZ) { memcpy(c->rxbuf + c->rx_len, p, (size_t)len); c->rx_len += (u32)len; }
					else ESP_LOGW(TAG, "rxbuf 满 %u+%llu", c->rx_len, (unsigned long long)len);
					c->rx_off_next += len;
					} else if (off > c->rx_off_next) {
					ESP_LOGD(TAG, "stream 洞 off%llu>%llu 等对端 PTO 重传", (unsigned long long)off, (unsigned long long)c->rx_off_next);
					}                                                      /* off<基=重传副本：跳过 */
				}
			p += len;
			break;
			}
		case 0x10 ... 0x17: {                                       /* 流量控制帧按类型跳 varint */
			static const u8 nvar[8] = {1,2,1,1,1,1,1,2};    /* 0x14/0x15 STREAMS_BLOCKED=1（原 2 多跳）；0x17 STREAM_DATA_BLOCKED=2（StreamID+Limit，原 1 少跳=帧流错位） */
			for (int i = 0; i < nvar[t - 0x10]; i++) { if (!(k = vi_dec(p, end, &v1))) return;
				p += k; }
			break;
			}
		case 0x18: {                                                /* NEW_CONNECTION_ID → 更新发往 dcid */
			if (!(k = vi_dec(p, end, &v1))) return;
				p += k;         /* seq */
			if (!(k = vi_dec(p, end, &v2))) return;
				p += k;         /* retire prio */
			if (p >= end) return;
			u8 l = *p++;
			if (l < 8 || l > 20 || p + l > end) return;
			memcpy(c->dcid, p, l); c->dcid_len = l; p += l;
			if (p + 16 > end) return;
				p += 16;                      /* reset token */
			ESP_LOGD(TAG, "NCID len=%u", l);
			break;
			}
		case 0x19: if (!(k = vi_dec(p, end, &v1))) return;
				p += k; break;
		case 0x1a:                                                  /* PATH_CHALLENGE → 立即 RESPONSE */
			if (p + 16 > end) return;
			q_path_response(c, sp, p);
			p += 16;
			break;
		case 0x1b: if (p + 16 > end) return;
				p += 16; break;
		case 0x1c:                                                  /* CONNECTION_CLOSE(transport) 软失败 */
			ESP_LOGW(TAG, "sp%d CONNECTION_CLOSE transport", sp);
			c->got_close = 1;
			return;
		case 0x1d: {                                                /* CONNECTION_CLOSE(app)：hello2 到手则不算失败 */
			if (!(k = vi_dec(p, end, &v1))) return;
				p += k;         /* app error code */
			u64 rl;
			if (!(k = vi_dec(p, end, &rl))) return;
				p += k;
			if (rl > 64 || p + rl > end) return;
			ESP_LOGW(TAG, "sp%d CLOSE app code=%llu reason=%.*s", sp, (unsigned long long)v1, (int)rl, p);
			c->got_close = 1;
			return;
			}
		case 0x1e: break;                                           /* HANDSHAKE_DONE（服务器方向帧，忽略） */
		default:
			ESP_LOGW(TAG, "sp%d 未知帧 0x%02x", sp, t);
			return;
			}
	}
}

/* ============================ 收一个数据报（多包 coalesce + HP + AEAD + 帧）============================ */
static int q_recv_once(quic_conn_t *c, int timeout_ms)
{
	fd_set r; FD_ZERO(&r); FD_SET(c->udp, &r);
	struct timeval tv; tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
	int sel = select(c->udp + 1, &r, 0, 0, &tv);
	if (sel <= 0) return 0;
	u8 *d = malloc(1500);
	if (!d) return -1;
	struct sockaddr_in from; socklen_t fl = sizeof from;
	ssize_t n = recvfrom(c->udp, (char *)d, 1500, 0, (struct sockaddr *)&from, &fl);
	if (n < 0) { free(d); return -1; }                           /* select 误报/读错：不计 rx */
	c->rx_pkts++;      /* 凡 relay 方向来的数据报都计数，含 <16B 短包 */
	if (n < 16) { ESP_LOGW(TAG, "收短报 n=%d", (int)n); free(d); return -1; }
	int k;
	u32 off = 0;
	while (off + 1 < (u32)n) {
		u8 *dat = d + off; u32 dl = (u32)n - off;
		if (dat[0] & 0x80) {
			u8 type = dat[0] & 0x30;                                 /* 最终版（aioquic pull_quic_header 实证）：type=(b&0x30)>>4 在 bits5-4，fixed 在 bit6 受 HP 扰动不参与判型 */   /* 长头 type 在 bits6-5（RFC9000 17.2 1|TT|F|LL）：长头 HP 只翻低4bits，bits7-5 先判不受扰。原 &0x30 取 bits5-4 → Initial(0x8x)误判0-RTT丢、Handshake(0xCx)误判Retry——rx=0 悬案收包侧根因 */                                       /* 类型在 bits 5-4（RFC 9000 17.2）：长头 HP 只翻低 4 bits（unused+pnlen），原 &0xFC 把受 HP 混淆的 bits 3-2 卷入比较 → 收包在 unmask 前约 3/4 概率被当"0-RTT"丢弃 */
			if (type == 0x30) {   /* Retry（0b111 前缀；Retry 无 HP，raw 位即可判） */                                    /* Retry（0b11<<4；Retry 无 HP，raw 位即可判） */                                    /* Retry：存 token+换新 dcid，Initial 密钥不变（odcid） */
				u32 i = 1 + 4;
				if (i + 1 > dl) break;
				int dl_ = dat[i++];
				if (dl_ < 8 || dl_ > 20 || i + dl_ > dl) break;
				memcpy(c->dcid, dat + i, dl_); c->dcid_len = dl_; i += dl_;
				if (i + 1 > dl) break;
				int sl_ = dat[i++]; if (i + sl_ > dl) break; i += sl_;
				u64 tok; k = vi_dec(dat + i, d + n, &tok); if (!k) break; i += k;
				if (tok == 0 || tok > sizeof c->rtok || i + tok > dl) break;
				memcpy(c->rtok, dat + i, (size_t)tok); c->rtok_len = (u32)tok;
				ESP_LOGI(TAG, "Retry token=%u（重发 Initial 带 token）", (unsigned)tok);
				break;                                             /* Retry 后不续解析 */
				}
			if (type == 0x10) break;    /* 0-RTT：不支持忽略 */   /* 0-RTT（0b101 前缀）：不支持忽略 */      /* 0-RTT(0b01<<4)：不支持忽略；0x00=Initial 0x20=Handshake 继续 */               /* 0-RTT 等：忽略 */
			int sp = (type == 0x00) ? QSP_INIT : QSP_HS;    /* Initial=00 / Handshake=10（bits5-4） */   /* Initial=0x8x / Handshake=0xCx（type=bits7-5） */      /* Initial=0x00 / Handshake=0x20（type 已只取 bits 5-4） */
			if (!c->hp_ready[sp]) break;                           /* 密钥未就绪（乱序早到）：整段丢弃 */
			u32 i = 1 + 4;
			if (i + 2 > dl) break;
			int dl_ = dat[i++]; if (i + dl_ > dl) break; i += dl_; /* DCID=我的 cid，内容不校验 */
			int sl_ = dat[i++]; if (i + sl_ > dl) break; i += sl_;
			if (sp == QSP_INIT) {
				u64 tok; k = vi_dec(dat + i, d + n, &tok); if (!k) break; i += k;
				if (tok > 0) { if (tok > sizeof c->rtok || i + tok > dl) break; i += (u32)tok; }
				}
			u64 L; k = vi_dec(dat + i, d + n, &L); if (!k) break; i += k;
			u32 pn_off = i;
			if (pn_off + 4 + 16 > dl) break;                       /* HP 采样 pn_off+4..+20 */
			u8 mask[16]; aes_block_enc(dat + pn_off + 4, mask, c->hp_d[sp]);
			dat[0] ^= mask[0] & 0x0f;                                         /* 长头 unmask 对称 ^0x0f：fixed/bit6-bit5 type 全程不扰动，无需 |0x40 修复 */                /* unmask 翻回 bits4-0 后强制 fixed=1：AAD 用去 HP 后首字节（quic-go restoreLongHeaderBits 同构） */
			int pnlen = (dat[0] & 3) + 1;
			if (pn_off + pnlen + 16 > dl) break;
			u64 trunc = 0;
			for (int x = 0; x < pnlen; x++) trunc = (trunc << 8) | (dat[pn_off + x] ^ mask[1 + x]);
			u64 pn = pn_decode(c->pn_exp[sp], trunc, pnlen * 8);
			if (L < (u64)pnlen + 16) break;
			u32 plen = (u32)(L - pnlen - 16);
			if (pn_off + pnlen + plen + 16 > dl) break;
			if (pn_off + pnlen > 64) break;
			u8 aad[64];
			memcpy(aad, dat, pn_off); memset(aad + pn_off, 0, pnlen);
			for (int x = 0; x < pnlen; x++) aad[pn_off + x] = (u8)(pn >> (8 * (pnlen - 1 - x)));
			u8 nonce[12]; q_nonce(c->iv_d[sp], pn, nonce);
			u8 *pt = malloc(plen ? plen : 1);
			if (!pt) break;
			if (gcm_decrypt(c->key_d[sp], nonce, aad, pn_off + pnlen, dat + pn_off + pnlen, plen, pt, dat + pn_off + pnlen + plen) != 0) {
				free(pt);
				c->rx_bad++;
				ESP_LOGW(TAG, "sp%d pn%llu 解密失败", sp, (unsigned long long)pn);     /* D→W：gi=0 时 INFO 级即分"零回包(rx=0)"与"收到 tag 不对(rx>0,bad>0)" */
				break;                                             /* tag 错：本数据报剩余丢弃 */
				}
			pn_mark_recv(c, sp, pn);
			if (sp == QSP_INIT) c->got_server_init = 1;
			q_parse_frames(c, sp, pt, pt + plen);
			free(pt);
			off += pn_off + (u32)L;                                /* 整包 = pn_off + (PN+payload+tag) */
			} else {
			if (!c->hp_ready[QSP_APP]) break;
			u32 pn_off = 1 + c->odcid_len;                         /* 服务器→我 DCID=我初挑 dcid 长 */
			if (pn_off + 4 + 16 > dl) break;
			u8 mask[16]; aes_block_enc(dat + pn_off + 4, mask, c->hp_d[QSP_APP]);
			dat[0] ^= mask[0] & 0x1f;
			int pnlen = (dat[0] & 3) + 1;
			if (pn_off + pnlen + 16 > dl) break;
			u64 trunc = 0;
			for (int x = 0; x < pnlen; x++) trunc = (trunc << 8) | (dat[pn_off + x] ^ mask[1 + x]);
			u64 pn = pn_decode(c->pn_exp[QSP_APP], trunc, pnlen * 8);
			u32 plen = dl - pn_off - pnlen - 16;
			if (pn_off + pnlen > 64) break;
			u8 aad[64];
			memcpy(aad, dat, pn_off); memset(aad + pn_off, 0, pnlen);
			for (int x = 0; x < pnlen; x++) aad[pn_off + x] = (u8)(pn >> (8 * (pnlen - 1 - x)));
			u8 nonce[12]; q_nonce(c->iv_d[QSP_APP], pn, nonce);
			u8 *pt = malloc(plen ? plen : 1);
			if (!pt) break;
			if (gcm_decrypt(c->key_d[QSP_APP], nonce, aad, pn_off + pnlen, dat + pn_off + pnlen, plen, pt, dat + pn_off + pnlen + plen) != 0) {
				free(pt);
				c->rx_bad++;
				ESP_LOGW(TAG, "app pn%llu 解密失败", (unsigned long long)pn);
				break;
				}
			pn_mark_recv(c, QSP_APP, pn);
			c->got_app_rx = 1;
			q_parse_frames(c, QSP_APP, pt, pt + plen);
			free(pt);
			break;                                                 /* 短头无 length：数据报最后一包 */
			}
		/* 短头分支已自行 break；长头 coalesce 由 off 前移续解 */
	}
	free(d);
	for (int sp = 0; sp < 3; sp++)                                  /* 收妥即回 ACK（纯 ACK 包，quic-go 每包必 ACK 同构） */
		if (c->ack_dirty[sp] && c->hp_ready[sp]) q_send(c, sp, 0, 0, 0, 0, 0, 0);
	return 0;
}

/* ============================ 完整建链 ============================ */
static const char *s_dbg_ip;                                       /* quicdbg 差分实验目标（非空=覆盖 relay 地址） */
static int s_dbg_port;
void quic_debug_peer(const char *ip, int port) { s_dbg_ip = ip; s_dbg_port = port; }

quic_conn_t *quic_connect(int local_port, const char *peer_ip, int peer_port, u64 tid, int timeout_ms)
{
	quic_conn_t *c = calloc(1, sizeof *c);
	if (!c) return NULL;
	c->udp = -1;
	static int psa_once = 0;
	if (!psa_once) {
		if (psa_crypto_init() != PSA_SUCCESS) { ESP_LOGE(TAG, "psa_crypto_init 失败"); quic_close(c); return NULL; }
		psa_once = 1;
		}
	c->tid = tid;
	c->udp = socket(AF_INET, SOCK_DGRAM, 0);
	if (c->udp < 0) { ESP_LOGE(TAG, "UDP socket 失败"); quic_close(c); return NULL; }
	int one = 1;
	setsockopt(c->udp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in la; memset(&la, 0, sizeof la);
	la.sin_family = AF_INET; la.sin_port = htons((u16)local_port);
	if (local_port <= 0 || bind(c->udp, (struct sockaddr *)&la, sizeof la) != 0) {
		la.sin_port = 0;                                           /* 探测口被占（lwIP 同口双绑受限）→ 随机源口 */
		if (bind(c->udp, (struct sockaddr *)&la, sizeof la) != 0) { ESP_LOGE(TAG, "bind 失败"); quic_close(c); return NULL; }
		}
	if (s_dbg_ip && s_dbg_ip[0]) { peer_ip = s_dbg_ip; peer_port = s_dbg_port; ESP_LOGW(TAG, "DEBUG peer 覆盖 → %s:%d（quicdbg 差分实验，不依赖 relay）", peer_ip, peer_port); }
	if (s_dbg_ip && s_dbg_ip[0]) {                                      /* 双向 UDP 探针：正式 dial 前判 ESP32<->PC 双向路径（服务器收得到但 ESP32 恒 rx=0，疑 PC 出站被拦） */
		int pdbg = socket(AF_INET, SOCK_DGRAM, 0);
		struct sockaddr_in pa; memset(&pa, 0, sizeof pa);
		pa.sin_family = AF_INET; pa.sin_port = htons(5301);
		if (bind(pdbg, (struct sockaddr *)&pa, sizeof pa) == 0) {
			struct sockaddr_in ta; memset(&ta, 0, sizeof ta);
			ta.sin_family = AF_INET; ta.sin_port = htons(5301); ta.sin_addr.s_addr = inet_addr(s_dbg_ip);
			for (int r = 0; r < 3; r++) {
				sendto(pdbg, "UDPDBG-PING", 11, 0, (struct sockaddr *)&ta, sizeof ta);
				fd_set rs; FD_ZERO(&rs); FD_SET(pdbg, &rs);
				struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
				int s = select(pdbg + 1, &rs, 0, 0, &tv);
				char rb[32]; ssize_t rn = s > 0 ? recv(pdbg, rb, sizeof rb - 1, 0) : -1;
				if (rn > 0) { rb[rn] = 0; ESP_LOGW(TAG, "probe udp5301 round=%d resp=\"%s\" 双向通", r, rb); break; }
				ESP_LOGW(TAG, "probe udp5301 round=%d resp=(none) PC 回程未到", r);
			}
		}
		close(pdbg);
	}    /* quicdbg 差分实验：强拨 PC 侧 quic-go 服务器 */
	memset(&c->peer, 0, sizeof c->peer);
	c->peer.sin_family = AF_INET;
	c->peer.sin_port = htons((u16)peer_port);
	c->peer.sin_addr.s_addr = inet_addr(peer_ip);
	if (c->peer.sin_addr.s_addr == INADDR_NONE) { ESP_LOGE(TAG, "peer ip 非法 %s", peer_ip); quic_close(c); return NULL; }
	esp_fill_random(c->scid, 8);
	esp_fill_random(c->odcid, 8);
	c->odcid_len = 8;
	memcpy(c->dcid, c->odcid, 8); c->dcid_len = 8;
	if (psa_x_makekey(&c->xkey, c->xpub)) { quic_close(c); return NULL; }
	c->chmsg = malloc(768);
	if (!c->chmsg) { quic_close(c); return NULL; }
	c->ch_len = (u32)build_ch(c);
	sha256_init(&c->hs_sha);
	sha256_update(&c->hs_sha, c->chmsg, c->ch_len);
	q_initial_keys(c);
	ESP_LOGI(TAG, "QUIC dial %s:%d tid=%llu lp=%d", peer_ip, peer_port, (unsigned long long)tid, local_port);
	i64 t0 = now_ms(), deadline = t0 + timeout_ms;
	c->t_init = c->t_fin = c->t_42 = t0 - 1000;                    /* 首轮立即发 */
	for (;;) {
		i64 now = now_ms();
		if (now > deadline) { ESP_LOGE(TAG, "建链超时 %lldms st=%d gi=%d rx=%d bad=%d", (long long)(now - t0), c->st, c->got_server_init, c->rx_pkts, c->rx_bad);    /* rx=0→网络/relay 未应答；rx>0 bad=rx→密钥或包格式 */ break; }
		if (!c->got_server_init && now - c->t_init >= 400) {       /* Initial(CH) 400ms 重发：新 PN 同内容，CRYPTO 按 offset 去重 */
			u8 *fr = malloc(1400);
			if (!fr) break;
			int n = vi_enc(fr, 0x06);
			n += vi_enc(fr + n, 0);
			n += vi_enc(fr + n, (u64)c->ch_len);
			memcpy(fr + n, c->chmsg, c->ch_len); n += (int)c->ch_len;
			q_send(c, QSP_INIT, fr, n, 1200, 0, 0, 0);
			free(fr);
			c->init_sent++; c->t_init = now;
			}
		if (c->st >= QST_APP && c->cfin_sent < 5 && now - c->t_fin >= 600) {   /* Finished 最多重发 5 次：原 !got_app_rx 判据会死锁——服务器解开 app 包却丢了我 Finished 时 got_app_rx 已 1，stream 永不打开（CRYPTO 按 offset 去重，重复发无害） */   
			u8 fr[48]; int n = vi_enc(fr, 0x06);
			n += vi_enc(fr + n, 0);
			n += vi_enc(fr + n, (u64)c->cfin_len);
			memcpy(fr + n, c->cfinmsg, c->cfin_len); n += (int)c->cfin_len;
			q_send(c, QSP_HS, fr, n, 0, 0, 0, 0);
			c->cfin_sent++; c->t_fin = now;
			}
		if (c->st >= QST_APP && c->hs42_sent < 3 && now - c->t_42 >= 600) {  /* stream0 [4/2][LE64 tid]：offset0 最多 3 次 */
			u8 f2[16];
			f2[0] = 8; f2[1] = 0; f2[2] = 0; f2[3] = 0;            /* dl=8（body 长） */
			f2[4] = 4; f2[5] = 0;                                  /* MsgP2P */
			f2[6] = 2; f2[7] = 0;                                  /* MsgTunnelHandshake */
			for (int i = 0; i < 8; i++) f2[8 + i] = (u8)(tid >> (8 * i));
			u8 fr[24]; int n = vi_enc(fr, 0x0E);
			n += vi_enc(fr + n, 0);
			n += vi_enc(fr + n, 0);                                /* stream0 offset 0 */
			n += vi_enc(fr + n, 16);
			memcpy(fr + n, f2, 16); n += 16;
			q_send(c, QSP_APP, fr, n, 0, 0, 0, 0);
			c->hs42_sent++; c->tx_off = 16; c->t_42 = now;         /* 后续 stream_write 从 16 续 */
			}
		int rem = (int)(deadline - now);
		q_recv_once(c, rem > 200 ? 200 : rem);
		q_check_retrans(c);
		if (c->rx_len >= 8) {                                      /* 成功判据：完整 [4/3]（"OpenP2P,hello2"） */
			u32 dl = (u32)c->rxbuf[0] | ((u32)c->rxbuf[1] << 8) | ((u32)c->rxbuf[2] << 16) | ((u32)c->rxbuf[3] << 24);
			u16 mt = (u16)(c->rxbuf[4] | (c->rxbuf[5] << 8));
			u16 st = (u16)(c->rxbuf[6] | (c->rxbuf[7] << 8));
			if (mt == 4 && st == 3 && c->rx_len >= 8 + dl) {
				ESP_LOGI(TAG, "QUIC 建链 ok：[4/3] body=\"%.*s\"", (int)(dl > 64 ? 64 : dl), (const char *)c->rxbuf + 8);
				memmove(c->rxbuf, c->rxbuf + 8 + dl, c->rx_len - 8 - dl);
				c->rx_len -= 8 + dl;
				return c;
				}
			if ((mt != 4 || st != 3) && dl <= QRX_SZ) {            /* 非预期首帧：吞掉不阻塞泵 */
				ESP_LOGW(TAG, "stream0 首帧 mt=%u st=%u dl=%u", mt, st, dl);
				if (c->rx_len >= 8 + dl) { memmove(c->rxbuf, c->rxbuf + 8 + dl, c->rx_len - 8 - dl); c->rx_len -= 8 + dl; }
				}
			}
		if (c->got_close) break;
		}
	ESP_LOGE(TAG, "建链失败 st=%d srv_init=%d app_rx=%d close=%d 42=%d rx=%d bad=%d", c->st, c->got_server_init, c->got_app_rx, c->got_close, c->hs42_sent, c->rx_pkts, c->rx_bad);
	quic_close(c);
	return NULL;
}

/* ============================ stream0 读写 + 生命周期 ============================ */
int quic_stream_write(quic_conn_t *c, const uint8_t *data, int len)
{
	if (!c || c->st < QST_APP) return -1;
	while (len > 0) {
		int chunk = len > 1200 ? 1200 : len;                       /* 1200+帧头 ≤1452（对端 max_packet_size） */
		u8 *fr = malloc(1232);
		u8 *pkt = malloc(1500);
		if (!fr || !pkt) { free(fr); free(pkt); return -1; }
		int n = 0;
		fr[n++] = 0x0E;                                            /* STREAM FIN=0 LEN=1 OFF=1 */
		n += vi_enc(fr + n, 0);
		n += vi_enc(fr + n, c->tx_off);
		n += vi_enc(fr + n, (u64)chunk);
		memcpy(fr + n, data, chunk); n += chunk;
		u64 pn = c->pn_n[QSP_APP];
		int plen = 0;
		if (q_send(c, QSP_APP, fr, n, 0, pkt, 1500, &plen) != 0) { free(fr); free(pkt); return -1; }
		free(fr);
		if (c->snd_cnt == 8) {                                     /* 满：丢最旧（极端丢包场景，上层超时兜底） */
			free(c->sndbuf[c->snd_head]); c->sndbuf[c->snd_head] = 0;
			c->snd_head = (c->snd_head + 1) % 8; c->snd_cnt--;
			}
		int idx = (c->snd_head + c->snd_cnt) % 8;
		c->sndbuf[idx] = malloc(plen);
		if (c->sndbuf[idx]) { memcpy(c->sndbuf[idx], pkt, plen); c->sndlen[idx] = plen; c->sndpn[idx] = pn; c->snd_cnt++; }
		free(pkt);
		if (c->snd_cnt == 1) c->t_pend = now_ms();
		c->tx_off += chunk;
		data += chunk; len -= chunk;
		}
	return 0;
}
int quic_rx_ready(quic_conn_t *c) { return (c && !c->got_close && c->st >= QST_APP) ? (int)c->rx_len : 0; }   /* 死链+残留 rxbuf 时返回 0：否则 listen 循环里 drain 读不出帧又不清 rxbuf=忙等饿死 IDLE0 触发 task_wdt */
int quic_udp_fd(quic_conn_t *c) { return c ? c->udp : -1; }
int quic_stream_read(quic_conn_t *c, uint8_t *dst, int need, int timeout_ms)
{
	if (!c) return -1;
	i64 deadline = now_ms() + timeout_ms;
	int got = 0;
	while (got < need) {
		if (c->rx_len) {
			u32 take = c->rx_len < (u32)(need - got) ? c->rx_len : (u32)(need - got);
			memcpy(dst + got, c->rxbuf, take);
			memmove(c->rxbuf, c->rxbuf + take, c->rx_len - take);
			c->rx_len -= take;
			got += (int)take;
			if (got >= need) return got;
			}
		i64 rem = deadline - now_ms();
		if (rem <= 0) return -1;
		q_recv_once(c, rem > 200 ? 200 : (int)rem);
		q_check_retrans(c);
		if (c->got_close) return -1;
		}
	return got;
}
void quic_close(quic_conn_t *c)
{
	if (!c) return;
	if (c->hp_ready[QSP_APP]) { u8 fr[3] = {0x1d, 0x00, 0x00}; q_send(c, QSP_APP, fr, 3, 0, 0, 0, 0); }
	for (int i = 0; i < 8; i++) free(c->sndbuf[i]);
	if (c->xkey) psa_destroy_key(c->xkey);
	if (c->udp >= 0) close(c->udp);
	free(c->chmsg);
	free(c);
}

/* ============================ 已知答案自检 ============================ */
int quic_selftest(void)
{
#if OPENP2P_DIAG_ON                                                                  	/* 纯观测（行为监听）：已知答案自检+打印，仅取证编译时在场 */
	int fail = 0;
	u8 h[32];
	static const u8 E_ABC[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
	                             0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
	sha256_1((const u8 *)"abc", 3, h);
	if (memcmp(h, E_ABC, 32)) { fail |= 1; ESP_LOGE(TAG, "selftest SHA256(abc) FAIL"); }
	static const u8 K0[16] = {0}, IV0[12] = {0};
	static const u8 E_TAG[16] = {0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a};
	u8 tag[16];
	gcm_tag(K0, IV0, (const u8 *)"", 0, (const u8 *)"", 0, tag);   /* NIST GCM case1：空 PT */
	if (memcmp(tag, E_TAG, 16)) { fail |= 2; ESP_LOGE(TAG, "selftest GCM empty-tag FAIL"); }
	u8 pt[32], ct[32], back[32], tag2[16];
	for (int i = 0; i < 32; i++) pt[i] = (u8)i;
	gcm_encrypt(K0, IV0, (const u8 *)"aad", 3, pt, 32, ct, tag2);
	if (gcm_decrypt(K0, IV0, (const u8 *)"aad", 3, ct, 32, back, tag2) || memcmp(back, pt, 32)) {
		fail |= 4; ESP_LOGE(TAG, "selftest GCM roundtrip FAIL");
		}
	ct[0] ^= 1;
	if (gcm_decrypt(K0, IV0, (const u8 *)"aad", 3, ct, 32, back, tag2) == 0) { fail |= 8; ESP_LOGE(TAG, "selftest GCM 篡改未检出"); }
	u8 k20[20]; memset(k20, 0x0b, 20);
	static const u8 E_HMAC[32] = {0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
	                             0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};     /* RFC4231#1 权威值（旧 5bdcc146 是记错的 SHA1 串）*/
	u8 ho[32];
	hmac_sha256(k20, 20, (const u8 *)"Hi There", 8, ho);           /* RFC4231 case1 */
	if (memcmp(ho, E_HMAC, 32)) { fail |= 16; ESP_LOGE(TAG, "selftest HMAC KAT FAIL"); }
	static const u8 V_SEC[32] = {0x96,0xd4,0xf2,0xa1,0x15,0x3f,0x36,0x9e,0x1c,0xb8,0xb2,0x67,0xee,0xc7,0x0c,0x01,
	                             0x92,0xeb,0x92,0x0a,0xd4,0x3c,0xe5,0x60,0x57,0x1e,0x96,0xa8,0xe4,0x56,0xc8,0x2d};    /* 真机取证 SEC 值 */
	static const u8 E_EL[32]  = {0xaa,0xed,0x33,0x81,0xa5,0x05,0x1c,0xfd,0x9a,0x3a,0x41,0x3f,0xe9,0x60,0x7e,0x1b,
	                             0x54,0xbe,0xda,0x9c,0x90,0x53,0xba,0x1f,0xc3,0x39,0x4e,0x4c,0xa9,0x82,0x69,0x5e};    /* cryptography 库独立验证的 el_label(V_SEC,"client in")；裸SHA256 bug 当年逃过全部 KAT 即缺此向量 */
	u8 elo[32];
	el_label(V_SEC, "client in", 0, 0, elo, 32);
	if (memcmp(elo, E_EL, 32)) { fail |= 32; ESP_LOGE(TAG, "selftest Expand-Label KAT FAIL"); }    /* 定罪补网：HKDF-Expand 退化裸 SHA256 的哨兵 */
	static const u8 APRIV[32] = {0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
	                             0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a};
	static const u8 APUB[32] = {0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
	                            0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a};
	if (psa_crypto_init() != PSA_SUCCESS) { ESP_LOGE(TAG, "selftest psa_crypto_init FAIL"); return fail | 64; }
	psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_type(&at, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&at, 255);
	psa_set_key_usage_flags(&at, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&at, PSA_ALG_ECDH);
	psa_key_id_t ka = 0;
	u8 pubx[32]; size_t ol = 0;
	psa_status_t st1 = psa_import_key(&at, APRIV, 32, &ka);
	if (st1 == PSA_SUCCESS) st1 = psa_export_public_key(ka, pubx, 32, &ol);
	int xok = (st1 == PSA_SUCCESS && ol == 32 && memcmp(pubx, APUB, 32) == 0);   /* RFC7748 §6.1 */
	psa_key_id_t kb = 0; u8 bpub[32];
	if (psa_x_makekey(&kb, bpub) != 0) xok = 0;
	else {
		u8 s1[32], s3[32];
		if (psa_x_shared(ka, bpub, s1) != 0 || psa_x_shared(kb, pubx, s3) != 0 || memcmp(s1, s3, 32) != 0) xok = 0;
		}
	if (ka) psa_destroy_key(ka);
	if (kb) psa_destroy_key(kb);
	if (!xok) { fail |= 32; ESP_LOGE(TAG, "selftest X25519 KAT FAIL"); }
	u8 vb[8];
	if (vi_enc(vb, 0x3f) != 1 || vi_enc(vb, 0x3fff) != 2 || vi_enc(vb, 0x3fffffff) != 4 || vi_enc(vb, 1ULL << 40) != 8) {
		fail |= 128; ESP_LOGE(TAG, "selftest varint FAIL");
		}
	u8 odc[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08}, sec[32], ci[32], ck[16];
static const u8 E_A5K[16] = {0x1f,0x36,0x96,0x13,0xdd,0x76,0xd5,0x46,0x77,0x30,0xef,0xcb,0xe3,0xb1,0xa2,0x2d};   /* RFC9001 A.5 client initial key 双源真值（aioquic 亲算==std 复现；文件旧注"3e80617cbb"为记忆畸变） */
	hkdf_extract(Q_SALT, 20, odc, 8, sec);                         /* RFC9001 A.5 参考值：软校验仅打印 */
	el_label(sec, "client in", 0, 0, ci, 32);
	el_label(ci, "quic key", 0, 0, ck, 16);
	if (memcmp(ck, E_A5K, 16)) { fail |= 256; ESP_LOGE(TAG, "selftest A.5 chain key FAIL (G01 sentinel)"); } else { ESP_LOGI(TAG, "selftest A.5 chain key OK"); }       /* G01c：断言钉死双源真值（aioquic 亲算==std 复现）；错形(旧 d783377d)或任何派生漂移当场 FAIL fail|=256；旧 ESP_LOGI 软校验行是 G01 藏身 30+ 代日志的保护色 */
	ESP_LOGI(TAG, "QUIC selftest: %s (fail=0x%x)", fail ? "FAIL" : "OK", fail);
	return fail;
#else
	return 0;                                                                         	/* 静默编译：自检不执行（其结果本就只供日志） */
#endif
}
