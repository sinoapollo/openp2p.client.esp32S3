/*
 * OpenP2P 控制面：登录 + 心跳保活（手写 WSS，见 wss.c）。
 *
 * 登录 = WSS dial（URL 带 token/version），服务器主动推一条 MainType=0(MSG_LOGIN)
 * 消息，body 为 JSON（LoginRsp）。error 字段 omitempty —— 成功时该键不存在；
 * 失败时 "error":<非0>。收到 error==0/无 → "login ok. user=.. node=.."。
 */
#include "openp2p.h"
#include "wss.h"
#include "config.h"
#include "p2p/p2p_protocol.h"
#include "cfg_store.h"    /* 运行时配置仓库（NVS+网页配置）：四口映射目标读 g_cfg */
#include "quic_cli.h"     /* 自包含 QUIC v1 客户端：relay UDP 洞口 dialQuic（quic_cli.c） */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_log.h"
#include "oplog.h"                                                                	/* 编译期日志开关（config.h OPENP2P_LOG_ON）——必须在 esp_log.h 之后 */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"     /* 11434 多会话并发：会话下行帧队列 xQueue* */
#include "freertos/semphr.h"    /* 11434 多会话并发：隧道帧发送锁 xSemaphore* */
#include "esp_netif.h"   /* 默认 netif + IPSTR/IP2STR 打印内网 IP */
#include "esp_mac.h"     /* esp_efuse_mac_get_default 读出厂 MAC */
#include "lwip/sockets.h" /* relay 数据面：普通 TCP（socket/connect/send/recv/select） */
#include "lwip/tcp.h"      /* TCP_NODELAY：本地与隧道双侧关 Nagle（交互式按键/HTTP 小包的响应延迟元凶） */
#include "esp_random.h"   /* esp_fill_random 生成 app.id/app.key/tunnel.id */
#include "esp_timer.h"      /* esp_timer_get_time: rtt/punch alignment monotonic clock */
#include "esp_heap_caps.h"       /* heap_caps_get_free_size: s2c 300 并发 pcb 池内存续量取证 */
#include <sys/time.h>          /* gettimeofday: SNTP sync check */
/* AES-128-CBC 为自包含实现（本文件下方 aes_block_enc/dec + app_cipher）：
 * mbedtls medium profile 禁了 AES 解密(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)、cipher 模块未启用，
 * 且数据泵需加解密双向，故不依赖 mbedtls、自写 S-box/CBC/PKCS7。 */
#include <fcntl.h>     /* fcntl O_NONBLOCK: fire-SYN 非阻塞 connect */
#include <errno.h>       /* select 被中断时 errno==EINTR */
#include <time.h>       /* time() 心跳保活计时 */
#include <math.h>         /* exp(): Go calcRetryTimeRelay=10+e^(0.8(n-3.6)) 指数退避对位（common.go:302） */

static const char *TAG = "openp2p";

/* EMBED_TXTFILES 生成的内嵌 CA bundle（../certs/ca_bundle.pem → ca_bundle_pem） */
extern const char ca_bundle_pem[];   /* EMBED_TXTFILES 生成，null 结尾；长度用 strlen */

static wss_t s_ws;

/* ---------- 数据面（relay 端口映射）运行时状态：一个 App = 一个端口映射 = 一条独立 relay 隧道 ----------
 * 源码实证：P2PTunnel.config 内嵌 AppConfig(p2ptunnel.go:32)、App.ID()=SrcPort*10(config.go:65)
 * → 每端口一个 App、独立 tunnel.id/rtid/underlay 连接。4 端口 = 4 App = 4 条隧道。 */
/* ---------- 11434 多会话并发（用户 2026-10-31 授权性能增强） ----------
* 11434 单会话串行+backlog(2)=CC"Request timed out"真凶：主会话+并行 agent 6 路以上并发流
* 挤爆 backlog → 后续 SYN 静默丢。Go 端 App 原生支持 overlayConn 并发（listenTCP:506），[4/9] 帧带
* [LE64 ovid] 天然可按会话分流（官方客户端浏览器经单隧道并发十几路连接，对端必支持此实现）。 */
#define S14_PORT         11434                                       /* multi enable table lives in app_listen_task gate (11434/8000/22 all multi); macro kept as 11434 identity check */
#define S14_MAX_SESS  8                                             /* 每端口并发本地会话上限（超出的 SYN 在 backlog 排队，不拒不丢） */
#define S14_RQ_LEN    4                                             /* 每会话下行排队帧数（send_all(cfd) 慢时削峰；满则 mux14 背压等待） */

struct p2p_app_s;                                                   /* 前置：s14_conn_arg 需持其指针 */

struct s14_conn_arg { int cfd; struct p2p_app_s *a; int slot; };    /* sess14_task 参数（fwd 是唯一 spawn 点，无竞争） */

typedef struct {
	volatile int  used;                                             /* fwd 认领槽位时抢置、sess 退出清 0；mux14 只对 used=1 的槽按 rid 分流 [4/9] */
	volatile int  gone;
	volatile int  rsp_ok;                                             /* mux14 收 [4/8] 或下行字节流断 → sess 自终 */
	uint64_t      ovid;                                             /* sess 认领后即填（发 ConnectReq 前），mux14 按 rid 匹配 */
	QueueHandle_t rq;                                               /* 元素=s14_frame_t* */
} s14_sess_t;

static volatile int g_ctl_send_fail;      /* 控制面 WSS 写侧死(tls_write 连败-0x1)时 rebuild 仍逐轮打空 setup≈3min/口，heartbeat_loop 让位期无人救活 WSS，"连接断开10s后重连"永不到场，3389 listen 被 tun_dead 高挂=连不上元凶。Go 控制面常驻 goroutine 写失败即重连；此计数>=3 即短路交外层重登（文件下方同名暂定定义为同一对象） */
	static SemaphoreHandle_t s_wtx;   /* 控制面 WSS 发送锁——sess14 memapp 重推引入 heartbeat_loop 运行期首个非主流程任务并发调 op2p_send/push（mbedTLS 会话 socket 写不可并发）*/
static volatile int g_ctrl_dead;             /* 控制面死亡唯一入口=Go pn.close(false) 对位——写败(:972-974 一票)/ctrl_rx 读错(:927-931)/60s 零帧(:951-954) 均直置；heartbeat_loop 见之返0、recv_expect 见之即退、外层等 ctrl_rx 退场后 close */
static volatile int g_ctrl_rx_up;            /* ctrl_rx 常驻标记（mux_alive 同款）：外层重登先等它退场再 wss_close，防 fd 号回收错位让旧读者读新连接帧 */
static time_t g_ctrl_last_rx_msg;            /* Go readLoop 外层 60s 钟 :939-955 对位：ctrl_rx 收完整帧触钟；60s 零帧=半死连（send 仍入缓冲假活）-> close+relogin */
static volatile int64_t g_hb_t1_ns;          /* Go pn.t1 对位：发心跳前一瞬时间戳（handleMessage :871 rtt 与 :878 thisdt 的基线） */
static volatile unsigned g_dt_upd;           /* ctrl_rx 算完 (1,0) 心跳 ack 自增——hb_sync_dt 的被动等待同步点（Go：readLoop 直耗心跳，客户端不亲读 socket） */
static int64_t now_ns_real(void);            /* 前向声明：send_heartbeat 定义在前需盖 t1 */
typedef struct p2p_app_s {
	uint16_t  srcport;        /* 本地监听端口 */
	uint16_t  dstport;        /* 对端 dial 的目标端口（= srcport，透传到目标主机同端口） */
	uint64_t  app_id;         /* 本端 app 句柄（rand64，推给对端对齐） */
	uint64_t  app_key;        /* AES key（rand64，推给对端） */
	uint64_t  tunnel_id;      /* relay 隧道 ID（rand64，ConnectReq.id 用） */
	char      relay_name[64]; /* 服务器分配的在线中继（RelayNodeRsp；不写死节点名） */
	uint64_t  relay_token;
	char      relay_mode[16];
	char      last_fail[64];  /* 上次建链尝试过的中继名，失败后重试时进 excludeNodes */
	uint64_t  relay_tid;       /* Go addRelayTunnel 建独立隧道：relay 侧 allTunnels 主键，与对端直连 tunnel_id 无关，生成一次跨重试复用 */
	uint64_t  rtid;           /* 对端 relay 隧道 ID（AddRelayTunnelRsp 返回） */
	int         direct;         /* relay==目标 => 直连隧道(tcp4/v4l)，数据面免 rtid 外层 */
	int         relay_fd;         /* relay 数据 TCP socket */
	void      *qconn;           /* quic_conn_t*：QUIC relay 隧道（与 relay_fd 互斥；非空时 ul_* / pump 走 stream0） */
	int       ready;          /* 建链成功标志 */
	int       multi;            /* =1（11434）：走 mux14 多会话并发路径；其余端口保持单会话路径 */
	int       s14_cap;            /* per-port multi session cap (22=4 SSH long-lived, 11434/8000=8); unused on single-path ports */
	time_t    mux_hb;               /* this mux instance's own last-heartbeat time (file-static shared by all instances starved idle tunnels to peer 20s deadline) */
	time_t    gone_rep;             /* last s14_gone_all E-log time; dead-tunnel recv-0 hot loop must not storm logs */

	volatile int tun_dead;                         /* 隧道层死亡标记（Go Tunnel.isActive 对位）——隧道心跳连败×2（writeLoop err->Close）或数据面 ul_readn 半帧/EOF/对端关置位；openp2p_task 重建通道接手 */
	volatile int mux_alive;                         /* mux14 常驻标记——创建成功置 1、死隧退场清 0；重建等唯一 rx 读者退场后才 close 旧 fd（防 fd 号回收错位） */
	int        hb_fail;                          /* 复任心跳 send defer 连败计数（打印节流）——拥塞非死，判死归 rx-silence 钟与 ul_readn recv 侧 */
	int        retry_num;                         /* Go app.retryNum[idx] 对位——calcRetryTimeRelay 指数退避计数，rebuild 成功清零（原固定120s远慢于Go 10s/轮起步） */
	time_t     last_rx;                                                 /* 数据面最近收帧时刻——Go Tunnel.isActive 对位（readLoop 每帧触 lastActive）；mux14 rx-silence>=60s 判死依据（健康空闲每10s 有对端 ST=5 帧，6×余量） */
	time_t     next_rebuild;                         /* calcRetryTimeRelay 形退避钟——daemon 扫描时间门（重建 5 轮全败后置 now+120，防对端离线忙重试） */
		int        listen_on;                         /* fwd 监听任务已建标记——rebuild 补建与外层重连再入防双建；mux14 入口重复建防护同用此意 */
	SemaphoreHandle_t txmtx;    /* 隧道帧发送锁：多会话 pup + mux14 ack/心跳 send_all 整帧原子（NULL=单会话旧路原样） */
	s14_sess_t s14[S14_MAX_SESS];                                    /* 每槽下行会话状态（mux14 按 rid 分流进 rq） */
	struct s14_conn_arg s14_args[S14_MAX_SESS];                      /* sess14_task 参数槽 */
} p2p_app_t;

#define OPENP2P_APP_NUM  OPENP2P_FWD_PORT_NUM
static p2p_app_t g_apps[OPENP2P_APP_NUM];
static uint16_t  g_app_ports[OPENP2P_APP_NUM] = OPENP2P_FWD_PORTS;
static char g_peer_pool[8][48];                                                         /* 服务器下发 peer 池（SDWANInfo Nodes[] 剔自身，用户令 2026-11-17 删硬编码） */
static int  g_peer_count = 0;                                                           /* 有效 peer 数（SDWANInfo 未到前=0） */
static int  g_peer_idx = 0;                                                             /* 当前选中下标 */
static char g_peer_name[64];                                                            /* 当前 dial 方（空=未定，SDWANInfo 后填充） */
static int g_peer_nattype[8] = {-1,-1,-1,-1,-1,-1,-1,-1};                               /* 各节点 NatType（-1=未查/离线，1=FullCone punch通，2=Symmetric punch不通） */
static int g_peer_probed = 0;                                                            /* 是否已探测过 NatType */
static int g_peer_ok[8] = {0};                                                            /* 各 peer 建链成功次数 */
static int g_peer_fail[8] = {0};                                                          /* 各 peer 建链失败次数 */
static int g_peer_black_idx = -1;                                                         /* 上轮 dial 失败的 peer 下标：peer_select 本轮排除之（失败即换 dial 方；一次性，选中后清零） */

/* 从 SDWANInfo body 提取 Nodes[] 所有节点名（剔自身），写入 pool，返回个数。
   JSON key 是 "Nodes"（大写 N，服务器实测 2026-11-17）。 */
static int jcollect_node_names(const char *body, char pool[][48], int max)
{
	const char *p = strstr(body, "\"Nodes\":[");
	if (!p) return 0;
	p += 8;
	int count = 0;
	for (;;) {
		const char *name = strstr(p, "\"name\":\"");
		if (!name) break;
		name += 8;
		char tmp[48];
		size_t i = 0;
		while (*name && *name != '"' && i < 47) tmp[i++] = *name++;
		tmp[i] = 0;
		p = name;
		if (strcmp(tmp, OPENP2P_NODE) == 0) continue;
		if (count < max) { memcpy(pool[count], tmp, i + 1); count++; }
	}
	return count;
}

/* ---------- 极简 JSON 字段提取（避免 cJSON，体积最小） ---------- */

static int jget_int(const char *j, const char *key, long long *out)
{
	char pat[40];
	snprintf(pat, sizeof(pat), "\"%s\"", key);
	const char *p = strstr(j, pat);
	if (!p) return -1;
	p += strlen(pat);
	while (*p == ' ' || *p == '\t' || *p == ':' || *p == '\r' || *p == '\n') p++;
	int neg = 0;
	long long v = 0;
	if (*p == '-') { neg = 1; p++; }
	if (*p < '0' || *p > '9') return -2;
	while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
	*out = neg ? -v : v;
	return 0;
}

static int jget_str(const char *j, const char *key, char *out, size_t sz)
{
	char pat[40];
	snprintf(pat, sizeof(pat), "\"%s\"", key);
	const char *p = strstr(j, pat);
	if (!p) return -1;
	p += strlen(pat);
	while (*p == ' ' || *p == '\t' || *p == ':' || *p == '\r' || *p == '\n') p++;
	if (*p != '"') return -2;
	p++;
	size_t i = 0;
	while (*p && *p != '"' && i < sz - 1) out[i++] = *p++;
	out[i] = 0;
	return 0;
}

/* ---------- 通用：发/收一条 OpenP2P 消息（8 字节 LE 头 + JSON body） ---------- */

/* 发送。body 以 '\0' 结尾（可为空串）。DataLen = strlen(body)。
   头序对齐 Go 的 openP2PHeader{DataLen u32, MainType u16, SubType u16}，全程小端。 */
/* 节点名 -> 节点 ID：对齐 Go 源码 protocol.go:275 —— crc64.Checksum(name, crc64.MakeTable(crc64.ISO))，
   即 Go 标准库 hash/crc64：反射表（poly=0xD800000000000000），update() 出入口各取反一次
   （等效 init=~0、最终 ~crc），无任何私有盐。此前"服务器私有参数 xorout=0xFFFFFFFFACFFFFFF"
   系逐位实现过拟合陷阱：两对观察节点名恰同为12字符，固定 xorout 只对该长度等价；13字符的
   节点名用拟合值推送被服务器拒（peer offline）后定案。真机 oracle 验证：
   以任意真实节点名对拍 Go 标准库 crc64，push 被服务器接受、nodeID 与 Go 一致即通过。 */
static uint64_t node_name_to_id(const char *name)
{
	static const uint64_t poly = 0xD800000000000000ULL;       /* crc64.ISO 反射多项式 */
	uint64_t crc = 0xFFFFFFFFFFFFFFFFULL;                     /* 标准库 update() 入口取反 */
	const unsigned char *p = (const unsigned char *)name;
	while (*p) {
		crc ^= *p++;
		for (int i = 0; i < 8; i++)
			crc = (crc & 1) ? ((crc >> 1) ^ poly) : (crc >> 1);
		}
	return ~crc;                                              /* 标准库 update() 出口取反 */
}

static esp_err_t op2p_send(uint16_t main_type, uint16_t sub_type, const char *body)
{
	size_t blen = strlen(body);
	unsigned char *buf = malloc(OPENP2P_HEADER_SIZE + blen);
	if (!buf) return ESP_ERR_NO_MEM;
	buf[0] = (unsigned char)(blen & 0xFF);           /* DataLen u32 LE */
	buf[1] = (unsigned char)((blen >> 8) & 0xFF);
	buf[2] = (unsigned char)((blen >> 16) & 0xFF);
	buf[3] = (unsigned char)((blen >> 24) & 0xFF);
	buf[4] = (unsigned char)(main_type & 0xFF);      /* MainType u16 LE */
	buf[5] = (unsigned char)((main_type >> 8) & 0xFF);
	buf[6] = (unsigned char)(sub_type & 0xFF);       /* SubType u16 LE */
	buf[7] = (unsigned char)((sub_type >> 8) & 0xFF);
	if (blen) memcpy(buf + OPENP2P_HEADER_SIZE, body, blen);
	if (s_wtx) xSemaphoreTake(s_wtx, portMAX_DELAY);                    /* 跨任务控制面发送串行化 */
	esp_err_t e = wss_send_binary(&s_ws, buf, OPENP2P_HEADER_SIZE + blen); if (e != ESP_OK) { g_ctl_send_fail++; g_ctrl_dead = 1; } else g_ctl_send_fail = 0;     /* 控制面写连败计数 */
	if (s_wtx) xSemaphoreGive(s_wtx);
	free(buf);
	return e;
}

/* 发 MsgPush 请求：带 PushHeader(From/To)。对齐 core/p2pnetwork.go push()。
 * 帧 = [头,DataLen=16+len][From 8B LE][To 8B LE][body]。From=本节点, To=目的节点。 */
static esp_err_t op2p_push(const char *to_node, uint16_t sub_type, const char *body)
{
	size_t blen = strlen(body);
	uint32_t datalen = OPENP2P_PUSH_HEADER_SIZE + (uint32_t)blen;
	unsigned char *buf = malloc(OPENP2P_HEADER_SIZE + OPENP2P_PUSH_HEADER_SIZE + blen);
	if (!buf) return ESP_ERR_NO_MEM;
	uint64_t from = node_name_to_id(OPENP2P_NODE);
	uint64_t to   = node_name_to_id(to_node);
	buf[0] = (unsigned char)(datalen & 0xFF);
	buf[1] = (unsigned char)((datalen >> 8) & 0xFF);
	buf[2] = (unsigned char)((datalen >> 16) & 0xFF);
	buf[3] = (unsigned char)((datalen >> 24) & 0xFF);
	buf[4] = (unsigned char)(MSG_PUSH & 0xFF);
	buf[5] = (unsigned char)((MSG_PUSH >> 8) & 0xFF);
	buf[6] = (unsigned char)(sub_type & 0xFF);
	buf[7] = (unsigned char)((sub_type >> 8) & 0xFF);
	for (int i = 0; i < 8; i++) buf[8 + i]  = (unsigned char)((from >> (8 * i)) & 0xFF);
	for (int i = 0; i < 8; i++) buf[16 + i] = (unsigned char)((to >> (8 * i)) & 0xFF);
	if (blen) memcpy(buf + OPENP2P_HEADER_SIZE + OPENP2P_PUSH_HEADER_SIZE, body, blen);
	if (s_wtx) xSemaphoreTake(s_wtx, portMAX_DELAY);                     /* 跨任务控制面发送串行化（sess14 重推 vs heartbeat_loop）*/
	esp_err_t e = wss_send_binary(&s_ws, buf, OPENP2P_HEADER_SIZE + OPENP2P_PUSH_HEADER_SIZE + blen); if (e != ESP_OK) { g_ctl_send_fail++; g_ctrl_dead = 1; } else g_ctl_send_fail = 0;     /* 控制面写连败计数 */
	if (s_wtx) xSemaphoreGive(s_wtx);
	free(buf);
	return e;
}

static uint64_t g_push_from, g_push_to;     /* 最近一条带头 push 帧的 From/To（取证：op2p_recv 填、recv_expect 读） */
/* 接收一条完整应用帧，解析头与 body。
 * 出参 main_type/sub_type；body 以 '\0' 结尾（可能为空串）。 */
static esp_err_t send_heartbeat(void);
static volatile int g_ctl_send_fail;                      /* 3389 失联元凶——控制面 WSS 写侧死(tls_write rc=-0x1 连败)时 rebuild 环仍逐轮跑 setup（RPC 全打空≈3min/口），heartbeat_loop 让位期无人救活 WSS，"连接断开10s后重连"永不到场。Go 控制面是常驻 goroutine 写失败即重连；此计数连败>=3 即短路交外层重登 */

static esp_err_t op2p_recv(uint16_t *main_type, uint16_t *sub_type,
		char *body, size_t body_sz, int timeout_ms)
{
	unsigned char frame[4096];   /* SDWANInfo(nodes[]+resource[]) 可能较大，放宽到 4KB */
	size_t flen = 0;
	int op = -1;
	esp_err_t e;
	int left = timeout_ms;                                           /* 1s 分片等待：保活已归 ctrl_rx 30s ticker——，旧 idle 踢线根因由常驻心跳根治 */
	for (;;) {
		e = wss_recv_frame(&s_ws, frame, sizeof(frame), &flen, &op, left > 1000 ? 1000 : left);
		if (e == ESP_OK) break;
		left -= 1000;
		if (e != ESP_ERR_TIMEOUT || left <= 0) return e;
			}
	if (flen < OPENP2P_HEADER_SIZE) return ESP_ERR_INVALID_SIZE;
	openp2p_header hd;
	memcpy(&hd, frame, OPENP2P_HEADER_SIZE);
	*main_type = hd.MainType;
	*sub_type = hd.SubType;
	/* 是否带 16B PushHeader 取决于"发送方"而非 SubType：
	 *   节点间 push（客户端 push() 生成）带头：ConnectReq(1)/Rsp(2)/HandshakeStart(3)/
	 *     AddRelayTunnelReq(4)/Rsp(5)/UnderlayConnect(8)/APPKey(13)/ServerSideSaveMemApp(18)
	 *   服务器发起的 push 不带头（handler 从 msg[8:] 解析）：Rsp(0)/Update(6)/ReportApps(7)/
	 *     EditApp(9)/SwitchApp(10)/Restart(11)/EditNode(12)/ReportLog(14).../SDWanRefresh(22)/Nat4Detect(23)
	 * 对齐 p2pnetwork.go:1000-1013(push 恒加头) vs handlepush.go 各 handler(按消息类型)。 */
	static const uint16_t push_with_header[] = {1, 2, 3, 4, 5, 8, 13, 18};
	size_t off = OPENP2P_HEADER_SIZE;
	g_push_from = 0; g_push_to = 0;           /* 不带 PushHeader 的帧（服务器发起）一律 0 */
	if (hd.MainType == MSG_PUSH) {
		for (unsigned i = 0; i < sizeof(push_with_header) / sizeof(push_with_header[0]); i++)
			if (hd.SubType == push_with_header[i]) { off = OPENP2P_HEADER_SIZE + OPENP2P_PUSH_HEADER_SIZE; break; }
		/* 取证：解析带头帧的 From/To(u64 LE) 并打印，判定服务器是否真转发、rsp 来自谁 */
		if (off > OPENP2P_HEADER_SIZE && flen >= OPENP2P_HEADER_SIZE + OPENP2P_PUSH_HEADER_SIZE) {
			memcpy(&g_push_from, frame + 8, 8);
			memcpy(&g_push_to,  frame + 16, 8);
			ESP_LOGI(TAG, "push帧 main=%u sub=%u from=%016llx to=%016llx", hd.MainType, hd.SubType,
					(unsigned long long)g_push_from, (unsigned long long)g_push_to);
		}
	}
	size_t blen = flen - off;
	if (blen > body_sz - 1) blen = body_sz - 1;
	if (blen) memcpy(body, frame + off, blen);
	body[blen] = 0;
	return ESP_OK;
}


/* 64 位随机（esp_fill_random，ESP32 TRNG；对齐源码 rand.Uint64） */
static uint64_t rand64(void)
{
	uint64_t v;
	esp_fill_random((uint8_t *)&v, sizeof(v));
	return v;
}

/* TCP socket 精确收 n 字节；EOF/错误返回 <n */
static int recv_n(int fd, void *buf, int n)
{
	int got = 0;
	while (got < n) {
		int r = recv(fd, buf + got, n - got, 0);
		if (r <= 0) return got;
		got += r;
	}
	return got;
}

/* 每段 select 自等窗口——Go readLoop p2ptunnel.go:601 读者自己 SetReadDeadline(TunnelHeartbeatTime*2=20s,
   protocol.go:170) 对位（读者自管窗口）。旧形 recv_n 的窗口来自共享 SO_RCVTIMEO，被 ul_recv(:1808)/handle_session(:1975)/
   mux14(:2156) 多任务互改，谁最后 setsockopt 谁定别人家的读窗：mux14 半帧 1s 到点即 :2189 拆隧=误杀（Go 读者唯一，绝无此雷）。 */
static int recv_n_to(int fd, void *buf, int n, int tmo_ms)
{
	int got = 0;
	while (got < n) {
		fd_set rs; FD_ZERO(&rs); FD_SET(fd, &rs);
		struct timeval tv; tv.tv_sec = tmo_ms / 1000; tv.tv_usec = (tmo_ms % 1000) * 1000;
		int sel = select(fd + 1, &rs, NULL, NULL, &tv);
		if (sel <= 0) return got;                                             /* 无数据到点=读败（Go :603 timeout err 同判，窗口由调用方定） */
		int r = recv(fd, buf + got, n - got, 0);
		if (r <= 0) return got;
		got += r;
	}
	return got;
}

/* 帧预缓存队列（对齐 Go msgMap 路由：read() 不丢弃非匹配帧，缓存供后续等待者取用）。
   真机实证：sub=8 UnderlayConnect 常在 ConnectRsp 等待之前到达，被旧版"跳过即丢弃"吞掉
   导致 "UnderlayConnect 等待失败 263"。只缓存三类竞态帧，避免无关帧挤占重要帧。 */
typedef struct { uint16_t mt, st; uint64_t from, to; int64_t ts_ms; char body[704]; } recv_q_item_t;
#define RECV_Q_CAP 16
static recv_q_item_t g_recv_q[RECV_Q_CAP];
static int g_recv_q_cnt;
static SemaphoreHandle_t s_qmtx;      /* Go msgMap channel 线程安全对位——take/put 跨任务互斥（has 纯读不锁） */

static int recv_q_take(uint16_t mt, uint16_t st, uint64_t from_req, char *body, size_t body_sz)
{
	if (!s_qmtx) s_qmtx = xSemaphoreCreateMutex();                 /* Go msgMap channel 线程安全对位(Go channel 天然互斥)——ctrl_rx put vs RPC 等待任务 take 跨任务裸数组竞争(memmove 移位 vs 写槽=帧撕裂) */
	xSemaphoreTake(s_qmtx, portMAX_DELAY);
	int64_t qnow = now_ns_real() / 1000000;                          /* Go readMsg p2pnetwork.go:1063-1066 time.Since(msg.ts)>ReadMsgTimeout(5s,protocol.go:181) 出队即弃——旧帧不得迟命中新 RPC */
	for (int i = 0; i < g_recv_q_cnt; i++) {
		if (qnow - g_recv_q[i].ts_ms > 5000) {                       /* Go :1063 timeout continue 同判：过期帧整体丢弃不参与匹配 */
			memmove(&g_recv_q[i], &g_recv_q[i + 1], (size_t)(g_recv_q_cnt - i - 1) * sizeof(g_recv_q[0]));
			g_recv_q_cnt--;
			i--;
			continue;
						}
		if (g_recv_q[i].mt != mt || g_recv_q[i].st != st) continue;
		if (from_req && g_recv_q[i].from != from_req) continue;   /* relay 隧道的 [3/2]/[3/8] 只认 relay 节点ID，防拿成对端帧拨错地址 */
		size_t blen = strlen(g_recv_q[i].body);
		if (blen > body_sz - 1) blen = body_sz - 1;
		memcpy(body, g_recv_q[i].body, blen);
		body[blen] = 0;
		g_push_from = g_recv_q[i].from;                       /* 取证：与 op2p_recv 同义 */
		g_push_to = g_recv_q[i].to;
		memmove(&g_recv_q[i], &g_recv_q[i + 1], (size_t)(g_recv_q_cnt - i - 1) * sizeof(g_recv_q[0]));
		g_recv_q_cnt--;
		ESP_LOGI(TAG, "命中预缓存帧 main=%u sub=%u", mt, st);
		if (s_qmtx) xSemaphoreGive(s_qmtx);                          /* 出口放锁 */
		return 1;
		}
	if (s_qmtx) xSemaphoreGive(s_qmtx);                                /* 未命中出口放锁 */
	return 0;
}

static int recv_q_has(uint16_t mt, uint16_t st)
{
	int64_t qnow2 = now_ns_real() / 1000000;
	for (int i = 0; i < g_recv_q_cnt; i++)
		if (g_recv_q[i].mt == mt && g_recv_q[i].st == st && qnow2 - g_recv_q[i].ts_ms <= 5000) return 1;    /* 过期帧不算存在（Go :1063 continue 对位）；纯读扫描不整锁，竞态伤害全在 memmove 写侧 */
	return 0;
}

static void recv_q_put(uint16_t mt, uint16_t st, const char *body, uint64_t from, uint64_t to)
{
	if (strlen(body) >= sizeof(g_recv_q[0].body)) return;
	if (!s_qmtx) s_qmtx = xSemaphoreCreateMutex();                    /* 入队侧同锁（与 take 互斥） */
	xSemaphoreTake(s_qmtx, portMAX_DELAY);
	int slot;
	if (g_recv_q_cnt >= RECV_Q_CAP) {                        /* 满则丢最旧（FIFO） */
		memmove(&g_recv_q[0], &g_recv_q[1], (size_t)(RECV_Q_CAP - 1) * sizeof(g_recv_q[0]));
		slot = RECV_Q_CAP - 1;
		} else slot = g_recv_q_cnt++;
	g_recv_q[slot].mt = mt; g_recv_q[slot].st = st;
	g_recv_q[slot].from = from; g_recv_q[slot].to = to;
	g_recv_q[slot].ts_ms = now_ns_real() / 1000000;                   /* msg.ts 对位（Go :1063 基座） */
	snprintf(g_recv_q[slot].body, sizeof(g_recv_q[slot].body), "%s", body);
	ESP_LOGI(TAG, "预缓存帧 main=%u sub=%u", mt, st);
	if (s_qmtx) xSemaphoreGive(s_qmtx);                               /* 直落出口放锁 */
}

/* 收帧直到命中 (main,sub)，跳过交错的心跳/MsgPush/上报 rsp。
  * 窗口 max_frames × timeout_ms。命中返回 ESP_OK（body 已填充）；否则 ESP_ERR_TIMEOUT。
  * 非匹配帧不再丢弃而是进 g_recv_q，供后面的 recv_expect 命中（修 sub=8 竞态吞帧）。 */
static esp_err_t op2p_recv_expect(uint16_t main, uint16_t sub, char *body, size_t body_sz,
		int timeout_ms, int max_frames)
{
	/* Go read() :1038-1059 对位——RPC 等待者从不亲读 socket（socket 归唯一 ctrl_rx_task=常驻 readLoop），
	   只等 msgMap(key0) 入队帧。旧 :352 的 15s 补心跳与旧 :354 的 60s rx-silence 弃窗分别归 ctrl_rx
	   的 30s ticker 与 60s 零帧钟（Go 这两颗钟常驻 readLoop 协程，RPC 层不持有）。 */
	int64_t endt_us = esp_timer_get_time() + (int64_t)timeout_ms * max_frames * 1000;
	for (;;) {
		if (g_ctrl_dead) return ESP_FAIL;                             /* Go close(false) 对位：读写皆死一切 RPC 作罢；旧形在此继续空耗收窗只会拖死重登流程 */
		if (recv_q_take(main, sub, 0, body, body_sz)) return ESP_OK;
		int left = (int)((endt_us - esp_timer_get_time()) / 1000);
		if (left <= 0) return ESP_ERR_TIMEOUT;                        /* deadline 语义：timeout 不消耗帧名额不早退（[3/8] 被心跳 ACK 拖 98s 且吞帧教训） */
		vTaskDelay(pdMS_TO_TICKS(left > 200 ? 200 : left));            /* 200ms 轮询片：Go read() chan select 超时等待同款（ctrl_rx 收帧入队、此处取队） */
	}
	return ESP_ERR_TIMEOUT;
}

/* 等 (main,sub) 且要求 PushHeader.From==from_req（0=任意）。relay 隧道专用：relay 自身的
   [3/2]/[3/8]（from=relay 节点ID）与目标对端的 [3/2]/[3/8]（from=peer 节点ID）SubType 相同，
   不区分就会拿错节点的帧去拨错地址。 */
static esp_err_t op2p_recv_expect_from(uint16_t main, uint16_t sub, uint64_t from_req,
		char *body, size_t body_sz, int timeout_ms, int max_frames)
{
	/* 同队列化（Go read() chan 等待对位）；relay 帧 from 甄别由 recv_q_take 的 from_req 完成
	   （[3/2]/[3/8] 只认 relay 节点ID，防拿成对端帧拨错地址） */
	int64_t endt_us = esp_timer_get_time() + (int64_t)timeout_ms * max_frames * 1000;
	for (;;) {
		if (g_ctrl_dead) return ESP_FAIL;
		if (recv_q_take(main, sub, from_req, body, body_sz)) return ESP_OK;
		int left = (int)((endt_us - esp_timer_get_time()) / 1000);
		if (left <= 0) return ESP_ERR_TIMEOUT;
		vTaskDelay(pdMS_TO_TICKS(left > 200 ? 200 : left));
	}
	return ESP_ERR_TIMEOUT;
}

/* ---------- NAT 探测（对齐 nat.go getNATType/natDetectTCP） ----------
  * 用同一本地端口 TCP 拨 api.openp2p.cn 的探测口 27180/27181（NATDetectPort1/2），
  * 发 "1"，服务器回 "publicIP:publicPort" 文本；两探测外端口相同=NATCone(1) 否则
  * NATSymmetric(2)。Go 客户端登录 URL 带 ipv4=publicIP&nattype=natType、ConnectReq
  * 带 fromIP/natType —— 之前我全空，服务器可能因此视我为无效节点。 */
#include <netdb.h>
static char g_public_ip[48];          /* 对齐 gConf.Network.publicIP */
static int  g_nat_type;                /* 对齐 gConf.Network.natType：NATCone=1/NATSymmetric=2 */
static int  g_udp_hole_local, g_udp_hole_nat;    /* UDP 探测本端口/外端口：QUIC dial 复用同一 cone 映射（Go ListenUDP 复用 natDetectUDP 同口） */

static char s_server_ip[48];               /* 对齐 gConf.Network.ServerIP：p2pnetwork.go:676-681 resolveServerIP 一次取 ips[0] */
static const char *server_ip(void)         /* 所有探测共用同一 IP：Go getNATType/initPort 均拨该单址，防多 A 记录把探测打到没开探测服务的机器 */
{
	if (s_server_ip[0]) return s_server_ip;
	struct addrinfo hints = {0}, *ai = NULL;
	hints.ai_family = AF_INET;
	if (getaddrinfo(OPENP2P_LOGIN_HOST, NULL, &hints, &ai) != 0 || !ai) return NULL;
	struct sockaddr_in *sa4 = (struct sockaddr_in *)ai->ai_addr;
	snprintf(s_server_ip, sizeof(s_server_ip), "%s", inet_ntoa(sa4->sin_addr));
	freeaddrinfo(ai);
	return s_server_ip;
}

static int nat_probe(int local_port, int server_port, char *ip, size_t ip_sz)
{
	const char *sip = server_ip(); if (!sip) return -1;
	struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET; sa.sin_addr.s_addr = inet_addr(sip);    /* ServerIP 单址（Go resolveServerIP ips[0]） */
	sa.sin_port = htons((uint16_t)server_port);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	struct timeval tv = { .tv_sec = 5 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));   /* 收超时，防 hang（记忆坑③） */
	struct sockaddr_in la;
	memset(&la, 0, sizeof(la));
	la.sin_family = AF_INET;
	la.sin_port = htons((uint16_t)local_port);
	if (bind(fd, (struct sockaddr *)&la, sizeof(la)) != 0) { close(fd); return -1; }
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
	if (send(fd, "1", 1, 0) != 1) { close(fd); return -1; }
	char rsp[64] = {0};
	int n = recv(fd, rsp, sizeof(rsp) - 1, 0);
	close(fd);
	if (n <= 0) return -1;
	rsp[n] = 0;
	char *colon = strchr(rsp, ':');
	if (!colon) return -1;
	*colon = 0;
	snprintf(ip, ip_sz, "%s", rsp);
	return atoi(colon + 1);
}

static int nat_probe_udp(int local_port, int server_port, char *ip, size_t ip_sz)    /* 对齐 nat.go:60 natDetectUDP（Go 主路；TCP 仅 UDP 被封时兜底） */
	{
		const char *sip = server_ip(); if (!sip) return -1;
		struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET; sa.sin_addr.s_addr = inet_addr(sip);     /* 与 Go natDetectUDP 拨同一 ServerIP */
		sa.sin_port = htons((uint16_t)server_port);
		int fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0) return -1;
		struct timeval tv = { .tv_sec = 5 };                                      /* NatDetectTimeout=5s */
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		struct sockaddr_in la;
		memset(&la, 0, sizeof(la));
		la.sin_family = AF_INET;
		la.sin_port = htons((uint16_t)local_port);                                /* 两探测同本地口（nat.go:101 同 localPort 复拨两服务器） */
		if (bind(fd, (struct sockaddr *)&la, sizeof(la)) != 0) { ESP_LOGW(TAG, "udp probe %d bind local %d fail errno=%d", server_port, local_port, errno); close(fd); return -1; }    /* Go ListenPacket 串行复用同 localPort，lwIP 若 EADDRINUSE 在此暴露 */
		unsigned char req[12] = {4, 0, 0, 0, 2, 0, 0, 0, 'n', 'u', 'l', 'l'};     /* Go newMessage(MsgNATDetect,MsgNAT,nil)=json.Marshal(nil)="null"：DataLen=4，整帧 12B。openp2p.cn 对 DataLen=0 空 body 探测包静默不回，必须逐字节同 Go */                                               /* newMessage(MsgNATDetect=2, MsgNAT=0, nil)：DataLen=0 空 body */
		/* req 初始化已含 [4/2/0]+"null"，见上行 */
		if (sendto(fd, req, 12, 0, (struct sockaddr *)&sa, sizeof(sa)) != 12) { ESP_LOGW(TAG, "udp probe %d sendto fail errno=%d", server_port, errno); close(fd); return -1; }
		unsigned char buf[64] = {0};
		ssize_t n = recvfrom(fd, buf, sizeof(buf) - 8, 0, NULL, NULL);            /* 8B 头后是 JSON body */
		close(fd);
		if (n < 8) { ESP_LOGW(TAG, "udp probe %d: 无响应/过短 n=%d errno=%d（Go NatDetectTimeout=5s）", server_port, (int)n, errno); return -1; }    /* 零回包(EAGAIN)与乱包可见分 */
		char body[64] = {0};
		memcpy(body, buf + 8, (size_t)(n - 8));
		long long port = 0;
		char rip[48] = {0};
		if (jget_int(body, "port", &port) != 0 || port <= 0 || port > 65535) return -1;
		if (jget_str(body, "IP", rip, sizeof(rip)) == 0 && rip[0]) snprintf(ip, ip_sz, "%s", rip);
		return (int)port;
	}

	static void nat_detect(void)
	{
		int local_port = (int)(esp_random() % 15000 + 50000);                     /* 对齐 nat.go:101 rand.Uint32()%15000+50000 */
		char ip1[48] = {0};
		int m1 = 0, m2 = 0;
		int p1 = nat_probe_udp(local_port, 27180, ip1, sizeof(ip1));              /* Go 主路 UDP 优先 */
		if (p1 > 0) { m1 = 1; g_udp_hole_local = local_port; g_udp_hole_nat = p1; }    /* UDP 探测成功的口对记下来给 QUIC dial 复用；TCP 兜底(m1=2)不记，QUIC 端自退随机口 */
		else { p1 = nat_probe(local_port, 27180, ip1, sizeof(ip1)); m1 = p1 > 0 ? 2 : 0; }
		if (p1 <= 0) { ESP_LOGW(TAG, "NAT 探测 27180 UDP+TCP 均失败：登录将不带 ipv4/nattype"); return; }
		int p2 = nat_probe_udp(local_port, 27181, ip1, sizeof(ip1));              /* NATDetectPort2=27181，只比端口 */
		if (p2 > 0) m2 = 1;
		else { p2 = nat_probe(local_port, 27181, ip1, sizeof(ip1)); m2 = p2 > 0 ? 2 : 0; }
		g_nat_type = (p2 <= 0) ? 0 : (p1 == p2 ? 1 : 2);                           /* 探测2失败=0未知；同口=Cone(1) 异口=Symmetric(2) */
		snprintf(g_public_ip, sizeof(g_public_ip), "%s", ip1);
		ESP_LOGI(TAG, ">>> NAT 探测: publicIP=%s port1=%d(m%d) port2=%d(m%d) natType=%d", g_public_ip, p1, m1, p2, m2, g_nat_type);
	g_nat_type = 2;													/* 调试期自报对称(ICS 热点网)：Go getNATType 单服务器两端口 port1==port2 判 cone(1)，区分不了"仅对服务器开放"的 restricted；tcppunch 是双端同时开，双向 SYN 零回音(pf_errs=0 且 peer SYN 未入)⇒互丢。自报 2 ⇒ 对端进 connectUnderlayTCPSymmetric c2s TCP 800 路广拨(p2ptunnel.go:460, holepunch.go:81, 官方成功率99.24%)，我方同标志进 s2c 分支(180 路随机源口建映射+LISTEN+[4/1] echo)=原路全通。验收通过后整行删除 */
	}

/* ---------- 登录 ---------- */

static void build_login_url(char *buf, size_t sz)
{
	snprintf(buf, sz,
			"/api/v1/login?node=%s&token=%s&version=%s&ipv4=%s&ipv6=&nattype=%d&sharebandwidth=0",
			OPENP2P_NODE, g_cfg.token, OPENP2P_CLIENT_VERSION, g_public_ip, g_nat_type);
}

esp_err_t openp2p_login_once(void)
{
	char url[256];
	build_login_url(url, sizeof(url));
	ESP_LOGI(TAG, "登录 %s:%d", OPENP2P_LOGIN_HOST, OPENP2P_WS_PORT);
	ESP_LOGI(TAG, "  %s", url);

	/* mbedTLS 4.0 判定 PEM 要求 buf[buflen-1]=='\0'（见 x509_crt.c 的 parse）；
	   EMBED_TXTFILES 生成 null 结尾数组，故 ca_len 必须含末尾 null = strlen()+1，
	   否则会被误当 DER 解析，报 MBEDTLS_ERR_X509_BAD_FORMAT_DATA(-0x2180)。 */
	size_t ca_len = strlen(ca_bundle_pem) + 1;
	esp_err_t e = wss_connect(&s_ws, OPENP2P_LOGIN_HOST, OPENP2P_WS_PORT, url,
			(const unsigned char *)ca_bundle_pem, ca_len);
	if (e != ESP_OK) {
		ESP_LOGW(TAG, "主端口 %d 失败，试备用端口 %d", OPENP2P_WS_PORT, OPENP2P_WS_PORT2);
		e = wss_connect(&s_ws, OPENP2P_LOGIN_HOST, OPENP2P_WS_PORT2, url,
				(const unsigned char *)ca_bundle_pem, ca_len);
	}
	if (e != ESP_OK) {
		wss_close(&s_ws);
		return e;
	}

	/* 收登录响应（MainType=MSG_LOGIN=0，body=JSON） */
	unsigned char frame[2048];
	size_t flen = 0;
	int op = -1;
	e = wss_recv_frame(&s_ws, frame, sizeof(frame), &flen, &op, 15000);
	if (e != ESP_OK) { wss_close(&s_ws); return e; }
	if (flen < OPENP2P_HEADER_SIZE) {
		ESP_LOGE(TAG, "登录响应太短 %zu", flen);
		wss_close(&s_ws);
		return ESP_FAIL;
	}

	openp2p_header hd;
	memcpy(&hd, frame, OPENP2P_HEADER_SIZE);
	ESP_LOGI(TAG, "首包 MainType=%u SubType=%u DataLen=%u",
			hd.MainType, hd.SubType, hd.DataLen);
	if (hd.MainType != MSG_LOGIN) {
		ESP_LOGE(TAG, "首包非登录响应 MainType=%u", hd.MainType);
		wss_close(&s_ws);
		return ESP_FAIL;
	}

	char body[1024] = {0};
	size_t blen = (flen > OPENP2P_HEADER_SIZE + sizeof(body) - 1) ?
			sizeof(body) - 1 : (flen - OPENP2P_HEADER_SIZE);
	memcpy(body, frame + OPENP2P_HEADER_SIZE, blen);
	body[blen] = 0;
	ESP_LOGI(TAG, "login body: %s", body);

	long long err_code = 0;
	if (jget_int(body, "error", &err_code) == 0 && err_code != 0) {
		char detail[128] = {0};
		jget_str(body, "detail", detail, sizeof(detail));
		ESP_LOGE(TAG, "登录失败 error=%lld detail=%s", err_code, detail);
		wss_close(&s_ws);
		return ESP_FAIL;
	}

	char user[80] = {0}, node[80] = {0};
	jget_str(body, "user", user, sizeof(user));
	jget_str(body, "node", node, sizeof(node));
	ESP_LOGI(TAG, "login ok. user=%s node=%s", user, node);
	return ESP_OK;
}

/* ---------- 心跳保活 ---------- */

/* 心跳请求 = 8 字节头(MainType=1,SubType=0,DataLen=2) + body ""（2 字节 JSON 空串） */
static esp_err_t send_heartbeat(void)
{
	unsigned char hb[10];
	hb[0] = 2; hb[1] = 0; hb[2] = 0; hb[3] = 0;  /* DataLen=2 (LE u32) */
	hb[4] = 1; hb[5] = 0;                        /* MainType=MSG_HEARTBEAT=1 (LE u16) */
	hb[6] = 0; hb[7] = 0;                        /* SubType=0 (LE u16) */
	hb[8] = '"'; hb[9] = '"';                    /* body = "" */
	g_hb_t1_ns = now_ns_real();	esp_err_t hb_e = wss_send_binary(&s_ws, hb, sizeof(hb));      /* Go pn.t1=now 于发 hb 前一瞬（readLoop :871 rtt 与 :878 thisdt 基线） */ if (hb_e != ESP_OK) { g_ctl_send_fail++; g_ctrl_dead = 1; } else g_ctl_send_fail = 0;     /* 连败>=3 时 rebuild k-loop 短路交 heartbeat_loop 触发外层重登 */
	return hb_e;
}

static int64_t now_ns_real(void)                         /* Go: time.Now().UnixNano()，gettimeofday 避免 time(2) 的 ±1s 量化误差 */
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (int64_t)tv.tv_sec * 1000000000LL + (int64_t)tv.tv_usec * 1000LL;
}

static volatile int64_t g_dt_ns;                    /* Go GNetwork.dt: local clock - server clock (ns) */
static int heartbeat_loop(void)
{
	/* 心跳收发/dt 计算/60s 钟整块归 ctrl_rx_task（Go readLoop+run():175 ticker 合体对位）；
	   本函数降级为 Go daemonP2PTunnel 轮：每 1s 扫 tun_dead 见死返1（控制面主任务接手 rebuild），
	   见控制面死返 0（Go close(false) 旗标 -> 外层"连接断开10s后重连"）。 */
	ESP_LOGI(TAG, "enter daemon poll (心跳归 ctrl_rx_task; 本环=Go daemonP2PTunnel 每轮扫描)");
	for (;;) {
		if (g_ctrl_dead) { ESP_LOGW(TAG, "daemon sees control-plane dead (Go close(false) flag 对位) -> outer relogin"); return 0; }
		for (int db = 0; db < OPENP2P_APP_NUM; db++) {                 /* Go daemon 每轮全槽扫描（:160-172） */
			p2p_app_t *d = &g_apps[db];
			if (d->tun_dead && time(NULL) >= d->next_rebuild) { ESP_LOGW(TAG, "[port %d] daemon sees dead tunnel (Go daemonP2PTunnel !isActive), rebuild pass next in control-plane task", d->srcport); return 1; }
				}
		vTaskDelay(pdMS_TO_TICKS(1000));                                /* Go daemon 每轮 sleep 1s 节奏（p2papp.go:163/:170/:172） */
	}
}

/* ---------- punch dt 同步（对齐 Go synctime p2pnetwork.go:869-891） ----------
    * punch 双端 sleep 到 punchts（服务器钟帧）需 dt=本机钟-服务器钟 换算到本机钟帧；
    * 取法与 Go 同式：thisdt = t1 + rtt/2 - t2（t2=心跳rsp body 的 u64 LE 服务器时间戳）。
    * 不用 SNTP：本机裸钟+dt 数学自洽即可，SNTP 步进反而打断 punch 窗口。 */
static void hb_sync_dt(void)
{
	/* punch 窗不再自读 socket（socket 归 ctrl_rx）——发一颗心跳等 ctrl_rx 算完 dt 自增 g_dt_upd。
	   Go 对位：客户端发 hb 盖 pn.t1（:871/:878 基线），readLoop 收 ack handleMessage 直耗算 dt（:868-891）。 */
	unsigned pre = g_dt_upd;
	if (send_heartbeat() != ESP_OK) return;
	for (int i = 0; i < 50 && g_dt_upd == pre && !g_ctrl_dead; i++) vTaskDelay(10);    /* 至多 5s 等 ack（tick=100Hz:10tick=100ms）；等不到沿用现 dt 不阻塞（Go 亦无同步等待，punch 靠 punchTs 窗对齐） */
}


/* ---------- 登录后节点信息上报（控制面里最接近"注册"的一步） ----------
 * 对齐 Go 客户端登录成功后紧接着的 pn.write(MsgReport, MsgReportBasic, &req)
 * (p2pnetwork.go:788-808)：把 OS/MAC/内网IP/版本上报给服务器，后台据此把节点
 * 连同其信息展示出来。我们做 L4(p2pApp)，故 publicIPPort/IPv6/netInfo 等
 * omitempty 字段留空省略。服务器回 MsgReportBasicRsp(SubType=7)，只记录即可。 */
static void report_basic_once(void)
{
	/* 出厂 MAC */
	uint8_t mac[6];
	char macstr[32] = "";
	if (esp_efuse_mac_get_default(mac) == ESP_OK)
		snprintf(macstr, sizeof(macstr), "%02x:%02x:%02x:%02x:%02x:%02x",
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	/* 内网 IP（默认 WiFi STA netif） */
	char lanip[40] = "";
	esp_netif_t *ni = esp_netif_get_default_netif();
	if (ni) {
		esp_netif_ip_info_t ip;
		if (esp_netif_get_ip_info(ni, &ip) == ESP_OK)
			snprintf(lanip, sizeof(lanip), IPSTR, IP2STR(&ip.ip));
	}

	char body[256];
	/* 字段与 Go ReportBasic 的 json tag 一致；空值(omitempty)直接省略 */
	snprintf(body, sizeof(body),
			"{"
			"\"os\":\"ESP32-S3\","
			"\"mac\":\"%s\","
			"\"lanIP\":\"%s\","
			"\"hasIPv4\":1,"
			"\"version\":\"%s\""
			"}", macstr, lanip, OPENP2P_CLIENT_VERSION);

	ESP_LOGI(TAG, "上报节点信息 MsgReport/Basic: %s", body);
	if (op2p_send(MSG_REPORT, MSG_REPORT_BASIC, body) != ESP_OK) {
		ESP_LOGW(TAG, "ReportBasic 发送失败");
		return;
	}

	/* 等服务器回 MsgReportBasicRsp(SubType=7)；只记录，不影响后续流程 */
	char rsp[512] = {0};
	if (op2p_recv_expect(MSG_REPORT, MSG_REPORT_BASIC_RSP, rsp, sizeof(rsp), 2000, 5) == ESP_OK) {    /* 队列化等 Rsp（socket 归 ctrl_rx） */
		ESP_LOGI(TAG, "ReportBasic 响应 body=%s", rsp);
	} else {
		ESP_LOGW(TAG, "ReportBasic 响应超时/断开（Go 客户端此处会重试）");
	}
}

/* ---------- 本节点虚拟 IP（SD-WAN 网络里 nodes[] 中 name==本节点 的那条 ip） ---------- */

/* 在 SDWANInfo 的 nodes 数组里找 name==node 的对象，取其 ip。
 * 依赖 OpenP2P 固定输出顺序 {"name":"..","ip":".."}（Go 结构体字段序）。找不到返回 -1。 */
static int jfind_node_ip(const char *j, const char *node, char *ipout, size_t sz)
{
	char pat[80];
	snprintf(pat, sizeof(pat), "\"name\":\"%s\"", node);
	const char *p = strstr(j, pat);
	if (!p) return -1;
	p += strlen(pat);
	const char *q = strstr(p, "\"ip\"");       /* 本对象内取 ip */
	if (!q) return -1;
	q += 4;
	while (*q == ' ' || *q == ':' || *q == '\t' || *q == '\n') q++;
	if (*q != '"') return -2;
	q++;
	size_t i = 0;
	while (*q && *q != '"' && i < sz - 1) ipout[i++] = *q++;
	ipout[i] = 0;
	return 0;
}

/* 登录后请求 SD-WAN 信息，如实反映"本节点是否被分配了虚拟 IP"：
 *   分配了（gateway 非空 + nodes 里有本节点名）→ 取该 ip；
 *   没分配（gateway 空 或 nodes 无本节点）       → 不取。
 *
 * 为什么不"盲目重试到能拿到为止"（之前的错误做法）？——对齐 Go 源码：
 *  - 接收是常驻 readLoop 按 MainType 分发（p2pnetwork.go:892/894），MsgPush/心跳/SDWAN
 *    交错推送，无"请求后紧跟响应"保证；所以收帧必须跳过非目标帧，不能把第一帧当 InfoRsp。
 *  - 虚拟 IP 是【服务器后台配置】决定的，没分配就一直是空；重拉不会凭空造出 IP。
 *  - 重拉的正确触发器是服务器推 MsgPushSDWanRefresh(=22)（handlepush.go:222-223），
 *    那才是"配置变了"的信号，而不是客户端空转重试。 */
static void request_sdwan(void)
{
	ESP_LOGI(TAG, "请求 SD-WAN 信息 MsgSDWAN/InfoReq（本节点分配了虚拟 IP 就取，没分配就不取）");
	if (op2p_send(MSG_SDWAN, MSG_SDWAN_INFO_REQ, "null") != ESP_OK) ESP_LOGW(TAG, "SDWAN InfoReq 发送失败");
	/* 原"6帧×3s 直读等 InfoRsp + push22 重发"整块归 ctrl_rx_task 直耗
	   = Go handleSDWANInfoRsp/handlePush 在 readLoop 内（p2pnetwork.go:892-895）——客户端从不阻塞读 socket */
}

/* 常驻控制面唯一读者 = Go readLoop(:911-959) + run():175 Ticker 合体。
   全文件唯一调 op2p_recv 者；帧到按 (mt,st) 直耗分发（handleMessage :868-895 对位），
   其余帧 recv_q_put 全收入队（msgMap key0 :897-905 满即丢）。
   判死唯一入口：任何读错(:927-931)、60s 零帧(:951-955)、心跳发败(:972-974) -> g_ctrl_dead=1 退场。 */
static char g_ctrl_body[4096];                                        /* 唯一读者帧体缓冲（静态省栈：ctrl_rx 栈要装 op2p_recv 的 frame[4096] + wss_recv_frame 的 acc[2048] + mbedtls 记录层/PSA 全链） */
static void ctrl_rx_task(void *arg)
{
	ESP_LOGI(TAG, "ctrl_rx start (Go readLoop 常驻唯一读者: 30s hb ticker + 60s 零帧钟 + handleMessage 分发)");
	time_t last_hb = time(NULL);
	g_ctrl_last_rx_msg = last_hb;
	for (;;) {
		if (g_ctrl_dead) break;
		time_t nowh = time(NULL);                                       /* 心跳无条件化——Go run():175-182 Ticker(NetworkHeartbeatTime=30s) 发 hb 与帧流量无关；旧形藏 TIMEOUT 分支=帧密窗(建链 push 风暴期)心跳饿死，服务器按 hb 计时把我们判离线 */
		if (nowh - last_hb >= OPENP2P_HEARTBEAT_INTERVAL_MS / 1000) {
			if (send_heartbeat() != ESP_OK) break;                      /* Go pn.write err→close(false) 对位（send_heartbeat 内部已置 g_ctrl_dead） */
			last_hb = nowh;
					}
		uint16_t mt = 0, st = 0;
		esp_err_t e = op2p_recv(&mt, &st, g_ctrl_body, sizeof(g_ctrl_body), 1000);    /* 首字节 1s 片（B项后 wss_recv_frame 的 timeout_ms 真正生效） */
		if (e == ESP_ERR_TIMEOUT) {
			time_t now = time(NULL);
			if (now - g_ctrl_last_rx_msg >= 60) { ESP_LOGW(TAG, "ctrl_rx rx-silence 60s 零帧 (Go readLoop 外层钟 :951-955 半死连 close+relogin 对位——静默拆链上 send 仍入缓冲假活) -> relogin"); g_ctrl_dead = 1; break; }
			if (now - last_hb >= OPENP2P_HEARTBEAT_INTERVAL_MS / 1000) {               /* Go run():175 Ticker(NetworkHeartbeatTime=30s)——保活常驻，建链期不再靠窗内自发运气 */
				if (send_heartbeat() != ESP_OK) break;                                  /* 一票判死（send_heartbeat 内部已置 g_ctrl_dead） */
				last_hb = now;
					}
			continue;
				}
		if (e != ESP_OK) { ESP_LOGW(TAG, "ctrl_rx recv err=0x%x (Go ReadMessage err -> close :927-931：半帧/EOF/真错一票判死) -> relogin", e); g_ctrl_dead = 1; break; }
		g_ctrl_last_rx_msg = time(NULL);                                                /* 帧到触钟（Go :943 readChan 到手对位） */
		if (mt == MSG_HEARTBEAT && st == 0) {                                           /* 心跳 ack 直耗不入队（handleMessage :868-891 对位，旧形 (1,0) 与 RPC 抢帧名额还吞帧） */
			int64_t rtt_ns = now_ns_real() - g_hb_t1_ns;                                /* Go :871 rtt = hbTime - t1 */
			if (rtt_ns < 0 || rtt_ns > 3000000000LL) continue;                           /* Go :872-875 rtt>PunchTsDelay(3s)：忽略该帧（不判死，已触钟） */
			int64_t t2 = 0;
			memcpy(&t2, g_ctrl_body, 8);                                                /* body = u64 LE 服务器时戳 */
			g_dt_ns = g_hb_t1_ns + rtt_ns / 2 - t2;                                     /* Go :878 thisdt = t1 + rtt/2 - t2（ddtma 滑动均值不参与 punch 对齐，保留现行简式） */
			g_dt_upd++;
			ESP_LOGI(TAG, "ctrl_rx heartbeat ok dt=%lldms rtt=%lldms", (long long)(g_dt_ns / 1000000), (long long)(rtt_ns / 1000000));
			continue;
				}
		if (mt == MSG_PUSH && st == MSG_PUSH_DST_NODE_ONLINE) {                         /* C项：Go handlepush.go:206-213 -> config.go:178-189 retryApp——长期 OFFLINE 退避期的唯一唤醒源 */
			char nd[64] = {0};
			jget_str(g_ctrl_body, "node", nd, sizeof(nd));                              /* protocol.go:295-297 PushDstNodeOnline{Node} */
			ESP_LOGI(TAG, "push DstNodeOnline node=%s (Go retryApp 对位：重置退避，daemon 1s 内重建——不空等指数退避顶格)", nd);
			for (int i = 0; i < OPENP2P_APP_NUM; i++) {
				p2p_app_t *d = &g_apps[i];
				if (strcmp(nd, g_peer_name) == 0) {                                /* config.go:181-183 PeerNode -> Retry(true)：retryNum=0+nextRetryTime=now+isActive 强制重建 */
					d->retry_num = 0; d->next_rebuild = time(NULL);
					if (d->ready || d->mux_alive) d->tun_dead = 1;                       /* Go Retry(true) 把 hbTime 拨快 30s：活隧也拆重建（对端"刚上线"=旧隧早已死） */
						} else if (d->relay_name[0] && strcmp(nd, d->relay_name) == 0) {   /* :184-187 RelayNode -> Retry(false)：仅重置退避，活隧不动 */
					d->retry_num = 0; d->next_rebuild = time(NULL);
						}
					}
			continue;                                                                   /* Go handler 直耗，不入队 */
				}
		if (mt == MSG_PUSH && st == MSG_PUSH_SDWAN_REFRESH) {                            /* handlepush.go:222-223 对位：后台改了 SD-WAN 配置，重拉 */
			ESP_LOGI(TAG, "push SDWanRefresh(sub=22) -> 重发 InfoReq（handlepush.go:222-223 对位）");
			op2p_send(MSG_SDWAN, MSG_SDWAN_INFO_REQ, "null");
			continue;
				}
		if (mt == MSG_SDWAN && st == MSG_SDWAN_INFO_RSP) {                               /* 巨大 body（nodes[] 表 >704B 入不了队）直耗 = handleSDWANInfoRsp 在 readLoop 内 */
			char gw[48] = {0}, ip[40] = {0};
			jget_str(g_ctrl_body, "gateway", gw, sizeof(gw));
			if (gw[0] && jfind_node_ip(g_ctrl_body, OPENP2P_NODE, ip, sizeof(ip)) == 0 && ip[0]) ESP_LOGI(TAG, ">>> 本节点 %s 已分配虚拟 IP = %s (gateway=%s)", OPENP2P_NODE, ip, gw);
			else ESP_LOGI(TAG, "本节点 %s 未分配虚拟 IP（gateway=%s，不获取）", OPENP2P_NODE, gw);
			g_peer_count = jcollect_node_names(g_ctrl_body, g_peer_pool, 8);            /* 删硬编码 peer 池：服务器 Nodes[] 剔自身=候选 dial 方（用户令 2026-11-17） */
			ESP_LOGI(TAG, ">>> peer 池（服务器 Nodes[] 剔自身，共 %d）：", g_peer_count);
			for (int i = 0; i < g_peer_count; i++) ESP_LOGI(TAG, "    [%d] %s", i, g_peer_pool[i]);
			continue;
				}
		recv_q_put(mt, st, g_ctrl_body, g_push_from, g_push_to);                         /* Go msgMap key0 全收入队（队列满丢弃 "msgQueue full, drop it" :897-905） */
			}
	g_ctrl_rx_up = 0;
	ESP_LOGW(TAG, "ctrl_rx 退场 (g_ctrl_dead=%d，交控制面重登环)", g_ctrl_dead);
	vTaskDelete(NULL);
}

/* 向服务器请求一个在线中继节点（对齐 addRelayTunnel:312-331）。
 * 发 MsgRelay/MsgRelayNodeReq{peerNode} 给服务器（write，不带 PushHeader）→
 * 收 MsgRelay/MsgRelayNodeRsp{relayName,relayToken,mode}。不写死 relay 名，
 * 由服务器按 peer 与在线情况分配（RPi 系节点为服务器所派公共中继，与 peer 无关）。 */
static char g_live_relay_name[64];                          /* （22/11434 挂牌 26min 不复听）：Go addRelayTunnel:296-311 先"复用同 peer 其他 app 的活 relay 隧道"再发 RelayNodeReq，C 缺此步——每个口 rebuild 都回炉问服务器，官方服务器认准派 QUIC v4l 口每轮漂移的某公共中继，每口每轮白烧≈45s dial 空转；改用 mode=public 官方 ECS 中继全链打通(对称洞+SSM+X.224)实证可达。全局缓存该活 relay 供同 peer 各口 rebuild 直接复用 */
static uint64_t g_live_relay_token;                         /* RelayNodeRsp 原派 token（复用=连 token 一起继承，Go :329 relayConfig.peerToken=rsp.RelayToken） */
static char g_live_relay_mode[16];                          /* private/public 同款继承（Go :330） */
static volatile time_t g_live_relay_ts;                     /* Go app.hbTime[1] 对位：mux14 收到整帧=该 relay underlay 双向活，live_relay_touch 刷钟；保鲜窗 25s（Go TunnelHeartbeatTime*2=20s+收帧余量），过期无人触钟=relay 死 */
static void live_relay_touch(p2p_app_t *a)                  /* Go hbTime[1] 触钟对位（mux14 读循环收到整帧处调用）：空窗后先到先得重登记，同名续期 */
{
	time_t now = time(NULL);
	if (a->relay_name[0] == 0) return;
	if (g_live_relay_name[0] == 0 || now - g_live_relay_ts > 25) {      /* 空窗过期→当前收帧者重登记（登记日志在此打一次） */
		if (strcmp(a->relay_name, g_live_relay_name) != 0) {
			snprintf(g_live_relay_name, sizeof(g_live_relay_name), "%s", a->relay_name);
			g_live_relay_token = a->relay_token;
			snprintf(g_live_relay_mode, sizeof(g_live_relay_mode), "%s", a->relay_mode);
			ESP_LOGI(TAG, ">>> 登记全局活 relay=%s mode=%s（Go addRelayTunnel find existing relay tunnel 缓存；同 peer 各口 rebuild 优先复用不再求服务器）", a->relay_name, a->relay_mode);
		}
		g_live_relay_ts = now;
	} else if (strcmp(a->relay_name, g_live_relay_name) == 0) g_live_relay_ts = now;/* 已登记 relay 的隧道每收一帧续期 */
}
static void live_relay_invalidate(p2p_app_t *a)             /* relay underlay 所有候选无 ack=拨不通实锤 → 全家停复用回服务器重派（Go hbTime[1] 陈旧→:312 再发 RelayNodeReq）；ConnectRsp 超时/[3/2] busy 等点不置此——relay 本身仍在线，冤杀会连坐健康口 */
{
	if (g_live_relay_name[0] && strcmp(a->relay_name, g_live_relay_name) == 0) {
		g_live_relay_name[0] = 0;
		ESP_LOGW(TAG, "[port %d] dial 不通作废全局活 relay %s → 后续 rebuild 回炉 RelayNodeReq", a->srcport, a->relay_name);
	}
}
static esp_err_t try_reuse_live_relay(p2p_app_t *a, const char *exclude)/* Go addRelayTunnel:294-332 found existing relay tunnel 对位：活缓存命中即跳过 RelayNodeReq（服务器官方派单只认 dial 不通的某公共中继，=22/11434 rebuild dial 死元凶） */
{
	if (g_live_relay_name[0] == 0 || time(NULL) - g_live_relay_ts > 25) return ESP_FAIL;/* Go:302 time.Now().Before(hbTime[1]+TunnelHeartbeatTime*2) */
	if (exclude && exclude[0] && strcmp(g_live_relay_name, exclude) == 0) return ESP_FAIL;/* Go:302 Tunnel(i).config.PeerNode != excludeNodes */
	if (a->last_fail[0] && strcmp(g_live_relay_name, a->last_fail) == 0) return ESP_FAIL;/* 11434 不自愈修：本口上次拨不通的 relay 拒复用——全局活 relay 缓存被其它口 live_relay_touch 复写，死节点重入=挂掉后 rebuild 死循环不复位 */
	snprintf(a->relay_name, sizeof(a->relay_name), "%s", g_live_relay_name);
	a->relay_token = g_live_relay_token;                    /* Go:329 继承派发时原 token，TOTP 校验口径一致 */
	snprintf(a->relay_mode, sizeof(a->relay_mode), "%s", g_live_relay_mode);
	snprintf(a->last_fail, sizeof(a->last_fail), "%s", g_live_relay_name);
	ESP_LOGI(TAG, "[port %d] 复用全局活 relay=%s mode=%s（Go addRelayTunnel:296-311；省一轮 RelayNodeReq=免一次服务器硬派不可达中继的≈45s dial 空烧）", a->srcport, a->relay_name, a->relay_mode);
	return ESP_OK;
}
static esp_err_t request_relay_node(p2p_app_t *a, const char *exclude)
{
	char req[160];
	if (try_reuse_live_relay(a, exclude) == ESP_OK) return ESP_OK;      /* Go addRelayTunnel:294-311 先复用活 relay 再问服务器——服务器官方派单无视 excludeNodes 只肯派 QUIC 拨不通的某公共中继，22/11434 rebuild 每轮被硬派 dial 死=26min 不复听元凶 */
	if (exclude && exclude[0])   /* 对齐 Go RelayNodeReq{PeerNode,ExcludeNodes}：排除 dial 不通的中继 */
		snprintf(req, sizeof(req), "{\"peerNode\":\"%s\",\"excludeNodes\":\"%s\"}", g_peer_name, exclude);
	else
		snprintf(req, sizeof(req), "{\"peerNode\":\"%s\"}", g_peer_name);
	ESP_LOGI(TAG, "[port %d] RelayNodeReq: %s", a->srcport, req);
	if (op2p_send(MSG_RELAY, MSG_RELAY_NODE_REQ, req) != ESP_OK) {
		ESP_LOGE(TAG, "RelayNodeReq 发送失败");
		return ESP_FAIL;
	}
	char rsp[512] = {0};
	esp_err_t e = op2p_recv_expect(MSG_RELAY, MSG_RELAY_NODE_RSP, rsp, sizeof(rsp), 8000, 10);
	if (e != ESP_OK) { ESP_LOGE(TAG, "[port %d] RelayNodeRsp 超时/失败 %d", a->srcport, e); return e; }
	ESP_LOGI(TAG, "[port %d] RelayNodeRsp: %s", a->srcport, rsp);
	jget_str(rsp, "relayName", a->relay_name, sizeof(a->relay_name));
	long long tok = 0;
	if (jget_int(rsp, "relayToken", &tok) == 0) a->relay_token = (uint64_t)tok;
	jget_str(rsp, "mode", a->relay_mode, sizeof(a->relay_mode));
	if (a->relay_name[0] == 0 || a->relay_token == 0) {
		ESP_LOGE(TAG, "RelayNodeRsp 缺 relayName/relayToken");
		return ESP_FAIL;
	}
	ESP_LOGI(TAG, ">>> 服务器分配 relay=%s relayToken=%llu mode=%s",
			a->relay_name, (unsigned long long)a->relay_token, a->relay_mode);
	snprintf(a->last_fail, sizeof(a->last_fail), "%s", a->relay_name);/* 记住试过谁，失败后排除重试 */
	return ESP_OK;
}

/* 向服务器查 peer 在线状态 —— 对齐 buildRelayTunnel 第一步 requestPeerInfo（p2pnetwork.go:1133-1163）。
 * 发 MsgQuery/PeerInfoReq{peerNode} → 收 MsgQuery/PeerInfoRsp，完整打印 online/IPv4/lanIP/version。
 * 判定：rsp.online==0 → 对应 Go ErrPeerOffline，返回 ESP_FAIL；据此提前放弃，别空等 4 个 ConnectReq 超时。 */
static esp_err_t query_peer_info(const char *peer, const char *token_str)
{
	char req[96];
	/* 对齐 p2pnetwork.go:378 AddApp: config.peerToken = gConf.Network.Token（登录 token，非0），
	   requestPeerInfo 据此带上 token 字段；缺它服务器不应答。Go omitempty 因非0 而保留 token。
	   官方 public relay 属别人账号：查它必须用 RelayNodeRsp 的 relayToken（Go addDirectTunnel:518
	   的 requestPeerInfo 用 relayConfig.peerToken），用登录 token 查=服务器沉默（Ubuntu22.04.5 冤案）。 */
	snprintf(req, sizeof(req), "{\"token\":%s,\"peerNode\":\"%s\"}", token_str, peer);
	ESP_LOGI(TAG, "查询 peer 在线状态 MsgQuery/PeerInfoReq: %s", req);
	if (op2p_send(MSG_QUERY, MSG_QUERY_PEER_INFO_REQ, req) != ESP_OK) {
		ESP_LOGW(TAG, "PeerInfoReq 发送失败");
		return ESP_FAIL;
	}
	char rsp[512] = {0};
	esp_err_t re = op2p_recv_expect(MSG_QUERY, MSG_QUERY_PEER_INFO_RSP, rsp, sizeof(rsp), 8000, 10);
	if (re != ESP_OK) {
		ESP_LOGW(TAG, "PeerInfoRsp 无应答（Go requestPeerInfo :1140-1143 head==nil -> ErrNetwork 形：不判 OFFLINE、不加成退避，正常下轮重试）");
		return re;       /* ESP_FAIL=发败一票死 / ESP_ERR_TIMEOUT=无应答——两态透传调用方分流 */
	}
	ESP_LOGI(TAG, ">>> PeerInfoRsp 全文: %s", rsp);
	long long online = 0;
	jget_int(rsp, "online", &online);                                      /* Go unmarshal 缺字段视 0 同判 ErrPeerOffline（:1148 同形），缺字段不反向放行 ONLINE */
	char ip[64] = {0}, lan[64] = {0};
	jget_str(rsp, "IPv4", ip, sizeof(ip));
	jget_str(rsp, "lanIP", lan, sizeof(lan));
	int on = (online != 0);
	ESP_LOGI(TAG, ">>> peer %s 在线判定: %s (online=%lld IPv4=%s lanIP=%s)",
			peer, on ? "ONLINE" : "OFFLINE", online, ip, lan);
	return on ? ESP_OK : ESP_ERR_NOT_FOUND;                                /* Go :1148-1150 rsp.Online==0 -> ErrPeerOffline——唯一合法 OFFLINE 判据 */
}

/* ---------- peer 池自动选路（Go requestPeerInfo NatType 筛选） ----------
   * 核心判据：natType=1 (Full Cone) punch 成功，natType=2 (Symmetric) punch 全 RST。
   * 优先选 natType=1 且在线的节点做 peer；全 natType=1 失败再兜底 natType=2。 */
static void peer_probe_nattype(void)
{
	if (g_peer_probed) return;
	for (int i = 0; i < g_peer_count; i++) {
		if (g_peer_nattype[i] >= 0) continue;
		char req[160];
		snprintf(req, sizeof(req), "{\"token\":%s,\"peerNode\":\"%s\"}", g_cfg.token, g_peer_pool[i]);
		if (op2p_send(MSG_QUERY, MSG_QUERY_PEER_INFO_REQ, req) != ESP_OK) continue;
		char rsp[512] = {0};
		if (op2p_recv_expect(MSG_QUERY, MSG_QUERY_PEER_INFO_RSP, rsp, sizeof(rsp), 3000, 5) != ESP_OK) { g_peer_nattype[i] = -2; continue; }
		long long online = 0, nt = 99;
		jget_int(rsp, "online", &online);
		jget_int(rsp, "natType", &nt);
		g_peer_nattype[i] = (online != 0) ? (int)nt : -1;
		ESP_LOGI(TAG, "peer_probe[%d]=%s online=%lld natType=%lld %s", i, g_peer_pool[i], online, nt, (online && nt == 1) ? "<<< 首选" : "");
	}
	g_peer_probed = 1;
}
static int peer_select(void)
{
	if (g_peer_count == 0) { ESP_LOGW(TAG, "peer 池未填充（SDWANInfo 未到），跳过"); return 0; }
	peer_probe_nattype();
	/* 评分：成功率≥50% 且 natType=1 优先；其次 natType=1 未试过的；最后 natType=2 兜底。
	   g_peer_black_idx=上轮 dial 失败的 peer 下标，本轮评分先排除它——失败即换 dial 方（用户令 2026-11-18）。 */
	int best = -1;
	int best_score = -999;
	for (int i = 0; i < g_peer_count; i++) {
		if (i == g_peer_black_idx) continue;                 /* 排除上轮失败的 dial 方 */
		int nt = g_peer_nattype[i];
		if (nt < 0) continue;              /* 离线/无应答跳过 */
		int total = g_peer_ok[i] + g_peer_fail[i];
		int score = 0;
		if (total > 0) {
			int rate = (g_peer_ok[i] * 100) / total;
			if (rate >= 50) score += 100;  /* 成功率≥50% 加分 */
		}
		if (nt == 1) score += 50;          /* natType=1 加分 */
		if (total == 0) score += 10;       /* 未试过加分（先试新的） */
		if (score > best_score) { best_score = score; best = i; }
	}
	if (best < 0 && g_peer_black_idx >= 0) {                 /* 排除后无候选（池里只剩它/其它全离线）→ 放行被排除的，避免死锁 */
		if (g_peer_nattype[g_peer_black_idx] >= 0) best = g_peer_black_idx;
	}
	if (best < 0) {
		g_peer_probed = 0;
		peer_probe_nattype();
		for (int i = 0; i < g_peer_count; i++) { if (g_peer_nattype[i] > 0) { best = i; break; } }
	}
	g_peer_black_idx = -1;                                  /* 一次性排除：本轮选中后清零，下轮再失败可再换 */
	if (best < 0) { ESP_LOGW(TAG, "peer 池全离线（共 %d），保持 %s", g_peer_count, g_peer_name[0] ? g_peer_name : "(未定)"); return 0; }
	if (g_peer_idx != best) {
		int total = g_peer_ok[best] + g_peer_fail[best];
		int rate = total > 0 ? (g_peer_ok[best] * 100) / total : -1;
		ESP_LOGW(TAG, ">>> peer 切换：dial 方=%s natType=%d 成功率=%d%% (%d/%d)", g_peer_pool[best], g_peer_nattype[best], rate, g_peer_ok[best], total);
	}
	g_peer_idx = best; snprintf(g_peer_name, sizeof(g_peer_name), "%s", g_peer_pool[best]);
	return 1;
}
/* 建链结果反馈：成功+1 ok，失败+1 fail（用于 peer_select 评分） */
void peer_feedback(int ok)
{
	if (g_peer_idx < 0 || g_peer_idx >= g_peer_count) return;
	if (ok) g_peer_ok[g_peer_idx]++;
	else g_peer_fail[g_peer_idx]++;
}
/* 对等节点池快照（网页只读展示对位）：只读 g_peer_* 全局，strncpy 有界拷贝，跨任务读最多读到一致快照的中间态，不会越界 */
int p2p_peer_snapshot(p2p_peer_info_t *out, int max)
{
	int n = 0;
	for (int i = 0; i < g_peer_count && n < max; i++) {
		strncpy(out[n].name, g_peer_pool[i], sizeof(out[n].name) - 1);
		out[n].name[sizeof(out[n].name) - 1] = 0;
		out[n].online = (g_peer_nattype[i] >= 0) ? 1 : 0;
		out[n].nattype = g_peer_nattype[i];
		out[n].ok = g_peer_ok[i];
		out[n].fail = g_peer_fail[i];
		out[n].active = (i == g_peer_idx) ? 1 : 0;
		n++;
	}
	return n;
}


/* ---------- tcppunch punching-port prepare (align p2ptunnel.go initPort LinkModeTCPPunch) ----------
   * Go: natDetectTCP(ServerIP, NATDetectPort1, 0) -> system-assigned source port localPort2
   * + cone mapping natPort; later dialTCP reuses that local port (reuse pkg borrows the
   * TIME_WAIT tuple). lwIP has no such magic, so we keep the detect connection OPEN to
   * hold the cone mapping fresh, and the dial socket binds the same source port via
   * SO_REUSEADDR (different destination tuple, coexists with the detect connection). */
static int g_punch_fd = -1, g_punch_local_port, g_punch_nat_port;
static char g_punch_ip[64];                                           /* detect echo 的 ip = 我方 CGNAT 当前出口 IP；peer SYN target=detect echo */
static void tcp_punch_prepare(int reuse_port)                            /* reuse_port>0: 重试复用同洞源口，CGNAT 映射同口保持 */
{
	if (g_punch_fd >= 0) { close(g_punch_fd); g_punch_fd = -1; }
	g_punch_local_port = 0; g_punch_nat_port = 0; g_punch_ip[0] = 0;
	const char *sip = server_ip(); if (!sip) { ESP_LOGW(TAG, "punch prepare 失败: server_ip=NULL(DNS 未解析)"); return; }
	struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET; sa.sin_addr.s_addr = inet_addr(sip);    /* ServerIP 单址，对齐 Go initPort natDetectTCP(ServerIP,27180,0) */
	sa.sin_port = htons(27180);                                    /* NATDetectPort1 */
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) { ESP_LOGW(TAG, "punch prepare 失败: socket errno=%d", errno); return; }
	struct timeval tv = { .tv_sec = 5 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));    /* 允许 TIME_WAIT 期同源端口被 dial 套接字重绑（Go reuse 等效） */
	struct sockaddr_in la; memset(&la, 0, sizeof(la));
	la.sin_family = AF_INET; la.sin_port = htons((uint16_t)reuse_port);    /* 0 = OS assigned；重试复用同洞端口 */
	if (bind(fd, (struct sockaddr *)&la, sizeof(la)) != 0 && (la.sin_port = 0, bind(fd, (struct sockaddr *)&la, sizeof(la))) != 0) { close(fd); ESP_LOGW(TAG, "punch prepare 失败: bind reuse=%d 及回落随机口均失败 errno=%d", reuse_port, errno); return; }    /* 复用口被占则回落随机口 */
	socklen_t ll = sizeof(la);
	getsockname(fd, (struct sockaddr *)&la, &ll);                  /* actual localPort2 */
	g_punch_local_port = ntohs(la.sin_port);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); ESP_LOGW(TAG, "punch prepare 失败: connect errno=%d local=%d (104=RST 105=REFUSED 11=超时)", errno, g_punch_local_port); g_punch_local_port = 0; return; }
	if (send(fd, "1", 1, 0) != 1) { close(fd); ESP_LOGW(TAG, "punch prepare 失败: send errno=%d local=%d", errno, g_punch_local_port); g_punch_local_port = 0; return; }
	char rsp[64] = {0};
	int n = recv(fd, rsp, sizeof(rsp) - 1, 0);
	if (n <= 0) { close(fd); ESP_LOGW(TAG, "punch prepare 失败: recv n=%d errno=%d local=%d (n=0=对端关 11=5s超时 104=RST)", (int)n, errno, g_punch_local_port); g_punch_local_port = 0; return; }
	rsp[n] = 0;
	char *colon = strchr(rsp, ':');
	if (!colon) { close(fd); ESP_LOGW(TAG, "punch prepare 失败: rsp 无冒号 n=%d rsp=[%.40s]", (int)n, rsp); g_punch_local_port = 0; return; }
	if (colon - rsp <= 0 || colon - rsp >= (int)sizeof(g_punch_ip)) { close(fd); ESP_LOGW(TAG, "punch prepare 失败: ip 段长异常 len=%d rsp=[%.40s]", colon - rsp, rsp); g_punch_local_port = 0; return; }
	memcpy(g_punch_ip, rsp, (size_t)(colon - rsp)); g_punch_ip[colon - rsp] = 0;   /* echo "ip:port" 拆 ip */
	g_punch_nat_port = atoi(colon + 1);                            /* 我方 coneNatPort=公网映射口 P_map */
	g_punch_fd = fd;															/* 保持探测连接：ICS 全锥(port1=port2=m1)映射随 socket 生死，close 即删 coneNat 洞——对端 Go listenTCP 预拨我方的 SYN 无处落地(pf 拨 34865 全程无应答)。Go 原版关连接依赖标准端口保持锥假设，本网不成立 */
	ESP_LOGI(TAG, "tcppunch hole ports: local=%d coneNat=%d (detect conn held)", g_punch_local_port, g_punch_nat_port);
}

/* ---------- relay 数据面建链（Flash 1，不含本地监听/AES 数据泵） ----------
 * 按  源码 relay 路径逐条实现（p2pnetwork.go addRelayTunnel/buildRelayTunnel
 * + p2ptunnel.go connect/connectUnderlayTCP）。每步 req/rsp 原样打日志，首连真服务器
 * 据此把 token/isServer/relayMode 等字段一次改准。顺序：
 *   1) WSS ConnectReq→ConnectRsp（拿 relay 公网 IP:port）
 *   2) TCP 连 relay + TunnelHandshake
 *   3) WSS AddRelayTunnelReq→Rsp（拿对端 rtid）
 *   4) WSS APPKey（同步 app.id/app.key）
 *   5) relay TCP TunnelHeartbeat 验证双向可用
 * app.id/app.key/tunnel.id 均本地随机（源码 rand.Uint64），app.key 再推给对端。 */
static esp_err_t setup_one_app(p2p_app_t *a, const char *exclude)
{
	if (a->app_id == 0) a->app_id = rand64();     /* Go app.id 于 AddApp 创建时生成一次终身不变——旧形每 rebuild 重掷=对端 memapp 每轮新 appID 僵尸条目堆积+DeleteApp 殃及池鱼(同款雷)；首进 g_apps static 零值→与原形等价 */
	if (a->app_key == 0) a->app_key = rand64();   /* Go app.key 同 app.id 终身不变(p2papp.go:39 创建即定,SaveKey/GetKey 全库零调用=纯内存不持久)，且 Go 每次建隧同步双推 APPKey+SSM 同一把键(:278-289)——旧形每轮重掷+rebuild 不重推=对端 memapp 持旧键而我方换新键，sess14 下行/上行 app_cipher 双向全灭(3389 点登录 mstsc 静默死强疑凶)；仿下行 @tunnel_id 钉死形 */
	if (a->tunnel_id == 0) a->tunnel_id = rand64();   /* Go: p2pApp/tunnel 身份生成一次跨重试复用——tid 是服务器/对端隧道表主键，每重试换 tid 在两端堆僵尸隧道（"p2ptunnel busy" 配额疑点） */
	if (a->relay_fd >= 0) { close(a->relay_fd); a->relay_fd = -1; }    /* (审计实锤#1)：入口曾裸弃上轮 underlay socket——ESTABLISHED pcb 不发 FIN 则 lwIP 永不回收（MEMP_MEM_MALLOC=1，pcb/netconn/recvmbox 全吃内部堆），k 环5轮×4口+rebuild 每轮各泄≈650B+1 fd 槽=20min 掉 70K 单调下降的元凶 */
		if (a->qconn) { quic_close((quic_conn_t *)a->qconn); a->qconn = NULL; }    /* 上次重试的 QUIC 必须关：lwIP fd 泄漏 + 同源口占用 */
	ESP_LOGI(TAG, "[port %d] app.id=%llu app.key=%llu tunnel.id=%llu (tid 跨重试复用)",
			a->srcport, (unsigned long long)a->app_id, (unsigned long long)a->app_key,
			(unsigned long long)a->tunnel_id);
	/* 先查 peer 是否在线（对齐 Go buildRelayTunnel 第一步 requestPeerInfo），离线就明确报出、别空等 */
	/* requestPeerInfo 两态（Go p2pnetwork.go:1133-1163）——
	   无应答=ErrNetwork 形（Go 注释明言 should not be ErrPeerOffline）：正常退避下轮重试；
	   明确 online=0=ErrPeerOffline 形：Go daemonDirectTunnel:207-210 retryNum>2 加成 retryLimit=20，
	   退避公式到 300s 顶格封顶，之后靠 ctrl_rx 收 push DstNodeOnline(sub=15) 唤醒（C项）——不空轮询。 */
	/* peer 池自动兜底：主 peer 离线/无应答则切备 peer（同级对端任一在线皆可 dial） */
	if (!peer_select()) {
		ESP_LOGE(TAG, "[port %d] peer 池全离线/无应答 (Go ErrPeerOffline/ErrNetwork 形：退避重试+等 DstNodeOnline 推唤醒)", a->srcport);
		if (a->retry_num > 2) a->retry_num = 20;                           /* 对位 p2papp.go:207-210：retryNum>2 -> retryLimit(20) */
		return ESP_FAIL;
	}
	/* 再向服务器要一个在线中继（不写死），然后建链。对齐 buildRelayTunnel→addRelayTunnel */
	if (strcmp(OPENP2P_RELAY_NODE, "") != 0) {    /* config.RelayNode 指定机制（addRelayTunnel:290-293）：跳过服务器分配 */
		snprintf(a->relay_name, sizeof(a->relay_name), "%s", OPENP2P_RELAY_NODE);
		a->relay_token = strtoull(g_cfg.token, NULL, 10);/* 同账号中继：handleConnectReq TOTP 校验用登录 token（RPi4B 案先例） */
		snprintf(a->relay_mode, sizeof(a->relay_mode), "%s", "private");
		snprintf(a->last_fail, sizeof(a->last_fail), "%s", a->relay_name);
		ESP_LOGI(TAG, "[port %d] 使用指定 relay=%s（对齐 Go config.RelayNode，跳过 RelayNodeReq）", a->srcport, a->relay_name);
	} else if (request_relay_node(a, exclude) != ESP_OK) {
		ESP_LOGE(TAG, "[port %d] 获取在线中继失败，放弃本次建链", a->srcport);
		return ESP_FAIL;
	}
	/* 对照 Go 权威值验证 C 端 CRC64：From=本节点、peer=对端，nodeID 与 Go 一致即通过 */
	char relay_tok_str[24];
	snprintf(relay_tok_str, sizeof(relay_tok_str), "%llu", (unsigned long long)a->relay_token);    /* Go requestPeerInfo:1138 QueryPeerInfoReq{config.peerToken,...}：查 relay 必须用 relayToken——官方中继属别人账号，登录 token 查询服务器沉默（Ubuntu22.04.5 冤案） */
	if (query_peer_info(a->relay_name, relay_tok_str) != ESP_OK)                                    /* 不阻断：Go addRelayTunnel:289 压根不查 relay（TODO），可达性由 relay 亲推 [3/2]+dial 结果自证，勿冤杀官方中继 */
		ESP_LOGW(TAG, "[port %d] relay %s 在线查询无应答/离线 → 仍继续建链", a->srcport, a->relay_name);
	ESP_LOGI(TAG, "[port %d] nodeID from=%llx relay=%s(%llx) peer=%llx",
			a->srcport, (unsigned long long)node_name_to_id(OPENP2P_NODE),
			a->relay_name, (unsigned long long)node_name_to_id(a->relay_name),
			(unsigned long long)node_name_to_id(g_peer_name));
	a->direct = (strcmp(a->relay_name, g_peer_name) == 0);    /* relay==目标 => Go 官方 IPv4 直连：拨其 v4l(PublicIPPort) 即直达隧道 */

	/* 1) ConnectReq -> ConnectRsp（MsgPush=3 sub=1 -> sub=2） */
	hb_sync_dt();                                /* punch 前刷新 dt */
	static char s_last_relay[64]; static int s_last_hole;                  /* 记录上次成功洞口口（观测用） */
	if (!a->direct) tcp_punch_prepare(0);    /* Go initPort:62 natDetectTCP(ServerIP,27180,0) lp=0 恒随机口；重试复用同口会撞上上次 close 的 TIME_WAIT→lwIP ENOTCONN(112)（51841/55181 首成连败3次实证 2026-11-17），故不传 reuse */
	if (g_punch_local_port > 0) { snprintf(s_last_relay, sizeof(s_last_relay), "%s", a->relay_name); s_last_hole = g_punch_local_port; }
	char creq[256];
	int punch_ok = (!a->direct && g_punch_nat_port > 0 && g_punch_local_port > 0 && g_punch_ip[0] != 0);
	ESP_LOGI(TAG, "[port %d] punch_ok=%d (detect local=%d nat=%d ip=%s)", a->srcport, punch_ok, g_punch_local_port, g_punch_nat_port, g_punch_ip);
	if (punch_ok) {                                     /* 对端原样复制 isServer=0 => 对端 dialTCP 于 punchts+dt 拨我方 fromIP:coneNatPort（handlepush.go:334-346） */
	snprintf(creq, sizeof(creq),
	"{\"from\":\"%s\",\"version\":\"%s\",\"fromIP\":\"%s\",\"natType\":%d,\"token\":%llu,"
	"\"coneNatPort\":%llu,\"id\":%llu,\"appKey\":0,\"linkMode\":\"tcppunch\",\"isServer\":0,"
	"\"underlayProtocol\":\"quic\",\"hasIPv4\":1}",
	OPENP2P_NODE, OPENP2P_CLIENT_VERSION, g_punch_ip, g_nat_type, (unsigned long long)strtoull(g_cfg.token, NULL, 10),     /* token 恒=登录 token（Go t.config.peerToken=自己网 token，ConnectReq 收件人=目标节点，服务器按此校验；定案填官方中继 relayToken 被服务器拒 push denied）；fromIP=Go publicIP 但 handlepush.go:337 peerIP=req.FromIP 对端拨此值：本网多出口(出口 IP≠登录 IP) 报 detect echo=洞口真外口（getNATType echo）；initPort 探测 echo 在 Go 被 _ 丢弃，绝不可上报 */
	(unsigned long long)g_punch_nat_port, (unsigned long long)a->tunnel_id);
	} else {                                            /* 检测失败/官方中继回落: 原 tcp4 候选拨出（v4l 常驻监听口） */
	snprintf(creq, sizeof(creq),
	"{\"from\":\"%s\",\"version\":\"%s\",\"fromIP\":\"%s\",\"natType\":%d,\"token\":%llu,"
	"\"coneNatPort\":%llu,\"id\":%llu,\"appKey\":0,\"linkMode\":\"tcp4\",\"isServer\":1,"
	"\"underlayProtocol\":\"quic\",\"hasIPv4\":1}",
	OPENP2P_NODE, OPENP2P_CLIENT_VERSION, g_public_ip, g_nat_type, (unsigned long long)strtoull(g_cfg.token, NULL, 10),      /* token 恒=登录 token：ConnectReq 收件人=目标节点，服务器按自己网 token 校验（官方中继 relayToken 冤案同上）；relayToken 只属于 relay 方向 rreq 与 AddRelayTunnelReq */
	(unsigned long long)(node_name_to_id(OPENP2P_NODE) % 8192ULL + 1025ULL), (unsigned long long)a->tunnel_id);
	}
ESP_LOGI(TAG, "ConnectReq: %s", creq);
	if (op2p_push(g_peer_name, MSG_PUSH_CONNECT_REQ, creq) != ESP_OK) {     /* Go p2ptunnel.go:96 GNetwork.push(t.config.PeerNode,...)——ConnectReq 的收件人永远是目标节点，不是 relay（此前推给 relay 导致目标节点从未收到、服务器/relay 侧状态错乱 busy） */
		ESP_LOGE(TAG, "[port %d] ConnectReq 发送失败", a->srcport);
		return ESP_FAIL;
	}
	char crsp[1024] = {0};
	esp_err_t e = op2p_recv_expect(MSG_PUSH, MSG_PUSH_CONNECT_RSP, crsp, sizeof(crsp), 8000, 10);
	if (e != ESP_OK) { ESP_LOGE(TAG, "[port %d] ConnectRsp 超时/失败 %d → 拉黑 relay %s", a->srcport, e, a->relay_name); snprintf(a->last_fail, sizeof(a->last_fail), "%s", a->relay_name); return e; }
	ESP_LOGI(TAG, "ConnectRsp: %s", crsp);
	char relay_ip[64] = {0};
	long long relay_port = 0;
	jget_str(crsp, "fromIP", relay_ip, sizeof(relay_ip));
	jget_int(crsp, "coneNatPort", &relay_port);
	if (relay_ip[0] == 0) {                        /* busy/peer offline/Access Denied：服务器未转发或对端拒绝——拉黑本 relay 换口重试（Go addRelayTunnel:341-344 把 relay 不可用报给外层换节点） */
		long long errv = 0; jget_int(crsp, "error", &errv);
		ESP_LOGE(TAG, "[port %d] ConnectRsp 无 fromIP error=%lld → 拉黑 relay %s", a->srcport, errv, a->relay_name);
		snprintf(a->last_fail, sizeof(a->last_fail), "%s", a->relay_name);
		return ESP_FAIL;
		}
	ESP_LOGI(TAG, ">>> relay 公网 = %s:%lld", relay_ip, relay_port);

		/* tcppunch simultaneous punching (Go p2ptunnel.go:397-412 + underlay_tcp.go
		   listenTCP TCPPunch): relay-side handleConnectReq -> addDirectTunnel(server side)
		   -> listenTCP actively dials MY fromIP:coneNatPort after sleeping to punchts; I
		   sleep to the same instant and dial its fromIP:coneNatPort. The two SYNs cross in
		   mid-air and each NAT admits the peer SYN as reply to its own fresh outbound.
		   So NO sub=8 wait here (Go client else-branch does not read sub=8). */
	long long v4l_port = (long long)(node_name_to_id(g_peer_name) % 8192ULL + 1025ULL     /* 定案：tcp4 分支对端推 sub=8 进 listenTCP 被动 accept，underlay 对面=目标节点 v4l，非 relay_name 算出的 relay 口 */);    /* PublicIPPort=nodeID%8192+1025（config.go:520，v4l 常驻监听口） */
	long long punch_ts_ll = 0;
	jget_int(crsp, "punchts", &punch_ts_ll);
	int hs_done = 0;
	unsigned char hs[16];
	hs[0] = 8; hs[1] = 0; hs[2] = 0; hs[3] = 0;                        /* DataLen=8 */
	hs[4] = (unsigned char)MSG_P2P; hs[5] = 0;
	hs[6] = (unsigned char)MSG_TUNNEL_HANDSHAKE; hs[7] = 0;            /* [头][tunnelID 8B LE]，v4l.handleConnection/对端 ReadBuffer 配对 */
	for (int i = 0; i < 8; i++) hs[8 + i] = (unsigned char)((a->tunnel_id >> (8 * i)) & 0xFF);
	long long cand[2];
	cand[0] = v4l_port;
	cand[1] = relay_port;
	if (cand[1] == cand[0]) cand[1] = 0;
	if (inet_addr(relay_ip) == INADDR_NONE) { ESP_LOGE(TAG, "[port %d] relay IP illegal %s", a->srcport, relay_ip); return ESP_FAIL; }
	/* 单向 tcppunch（对端 connectUnderlayTCP:412 会拨我方洞，但 :400-405 有 ts<=0
	不睡直接拨分支——那时我还在睡、洞未 LISTEN，SYN 命中无 pcb 被 RST，Go 不重试即永失）。
	倒置顺序：ConnectRsp 后立即 fire-SYN（同源口，开 restricted-cone 对对端 IP 的入站许可）+
	LISTEN(g_punch_local_port)，积分等待覆盖 [ConnectRsp, punchts+10s] 全窗；窗内 fire-SYN 每 4s
	保鲜映射、WSS 心跳每 15s 防 idle 断连（setup 期无 heartbeat_loop）。accept 首帧
	[4/2][LE64 t.id]（对端 t.id=addDirectTunnel(req.ID)=我方 tunnel_id），echo [4/3] 即成。 */
	int punch_listen_ok = 0;
	if (punch_ok) {
	struct sockaddr_in pa; memset(&pa, 0, sizeof(pa));
	pa.sin_family = AF_INET; pa.sin_port = htons((uint16_t)relay_port); pa.sin_addr.s_addr = inet_addr(relay_ip);
if (g_nat_type == 2) {                                                 /* NATSymmetric：Go connectUnderlayTCPSymmetric s2c 三路并进（p2ptunnel.go:509-530 dialTCP lp=0 + c2s 800 并发对偶） */
enum { S2C_N = 360, S2C_BATCH = 40 };                                       /* Go SymmetricHandshakeNum=800（protocol.go:174 自证 0.9924）的 lwIP 适配：IDF FD_SETSIZE=64 硬顶（vfs_lwip.c:25-27 断言 → MAX_SOCKETS≤58，stdio 占 6）→ 同时存活 ~52；在途≤40 滚动，每轮 360 覆盖点 P≈1-e^(-360*800/65532)=0.987（180→360：栈+4.2KB 已核 32K 内安全） */
int fds[S2C_N]; int nf = 0;                                                 /* nf=高水位；槽 -1=空/死（滚动批次取代旧 3s 整轮重拨） */
	int64_t t_send[S2C_N];                                          /* 每槽拨出时刻：SYN-SENT>1.2s 判死依据 */
	int s_dialed = 0, s_readable = 0, s_aged = 0, s_rsts = 0, s_frames = 0;                              /* 诊断：拨出/有事件/判死 */
	for (int si = 0; si < S2C_N; si++) { fds[si] = -1; t_send[si] = 0; }
int64_t s2c_deadline = esp_timer_get_time() + (punch_ts_ll + g_dt_ns - now_ns_real()) / 1000 + 10000000;      /* 与 cone 同窗 [ConnectRsp, punchts+10s] */
if (s2c_deadline < esp_timer_get_time() + 4000000) s2c_deadline = esp_timer_get_time() + 4000000;
time_t s2c_ctl_hb = time(NULL);
int pf = socket(AF_INET, SOCK_STREAM, 0);                               /* 路A fire-SYN：洞源口常驻拨对端，钉住洞口外口映射+抢 restricted 许可（对齐 Go reuse 借洞元组 dialTCP） */
if (pf >= 0) {
int one3 = 1; setsockopt(pf, SOL_SOCKET, SO_REUSEADDR, &one3, sizeof(one3));
struct sockaddr_in la3; memset(&la3, 0, sizeof(la3));
la3.sin_family = AF_INET; la3.sin_port = htons((uint16_t)g_punch_local_port);
bind(pf, (struct sockaddr *)&la3, sizeof(la3));
fcntl(pf, F_SETFL, O_NONBLOCK);
connect(pf, (struct sockaddr *)&pa, sizeof(pa));
}
int lfd2 = socket(AF_INET, SOCK_STREAM, 0);                             /* 路B LISTEN(洞源口)：对端 c2s 知道我的上报 coneNatPort，其专拨 SYN 唯有此 pcb 能收 */
if (lfd2 >= 0) {
int one4 = 1; setsockopt(lfd2, SOL_SOCKET, SO_REUSEADDR, &one4, sizeof(one4));
struct sockaddr_in la4; memset(&la4, 0, sizeof(la4));
la4.sin_family = AF_INET; la4.sin_port = htons((uint16_t)g_punch_local_port);
if (bind(lfd2, (struct sockaddr *)&la4, sizeof(la4)) != 0 || listen(lfd2, 2) != 0) {
ESP_LOGW(TAG, "[port %d] s2c LISTEN :%d fail errno=%d", a->srcport, g_punch_local_port, errno);
close(lfd2); lfd2 = -1;
}
}
int64_t t_fire = esp_timer_get_time();
ESP_LOGI(TAG, "[port %d] s2c symmetric: %d rand-src + LISTEN:%d(pub %d) + fire-SYN -> %s:%lld until punchts+10s heap_int=%u",
a->srcport, S2C_N, g_punch_local_port, g_punch_nat_port, relay_ip, relay_port, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
while (!punch_listen_ok && esp_timer_get_time() < s2c_deadline) {
	int live = 0;
	for (int si = 0; si < nf; si++) if (fds[si] >= 0) live++;
	if (nf >= S2C_N && live == 0) {                                           /* 一轮 180 口全判死 → 起新一轮换新随机源口集（10s 窗≈2 轮） */
	ESP_LOGI(TAG, "[port %d] s2c round2 @%lldms heap_int=%u dialed=%d readable=%d aged=%d", a->srcport, esp_timer_get_time() / 1000, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), s_dialed, s_readable, s_aged);
	nf = 0;
	}
	while (nf < S2C_N && live < S2C_BATCH) {                                  /* 滚动补发（Go 800 并发的 lwIP 适配，FD_SETSIZE=64 硬顶）：在途≤40，死一补一，铺满 180 覆盖点 */
	int fd5 = socket(AF_INET, SOCK_STREAM, 0);
	if (fd5 < 0) break;                                                       /* socket 池尽（58 顶）：本 tick 止，下个 select tick 续铺 */
	int one6 = 1; setsockopt(fd5, SOL_SOCKET, SO_REUSEADDR, &one6, sizeof(one6));
	fcntl(fd5, F_SETFL, O_NONBLOCK);
	if (connect(fd5, (struct sockaddr *)&pa, sizeof(pa)) != 0 && errno != EINPROGRESS) { close(fd5); fds[nf++] = -1; continue; }    /* 立即失败：占位推进防死循环，不占 pcb */
	fds[nf] = fd5; t_send[nf] = esp_timer_get_time(); nf++; live++; s_dialed++;
	}
fd_set rr, ww; FD_ZERO(&rr); FD_ZERO(&ww); int maxfd5 = -1;
for (int si = 0; si < S2C_N; si++) if (fds[si] >= 0) { FD_SET(fds[si], &rr); if (fds[si] > maxfd5) maxfd5 = fds[si]; }
if (lfd2 >= 0) { FD_SET(lfd2, &rr); if (lfd2 > maxfd5) maxfd5 = lfd2; }
if (pf >= 0) { FD_SET(pf, &ww); if (pf > maxfd5) maxfd5 = pf; }
struct timeval tvs2; tvs2.tv_sec = 0; tvs2.tv_usec = 100000;
int nsel = select(maxfd5 + 1, &rr, &ww, NULL, &tvs2);
if (nsel > 0 && lfd2 >= 0 && FD_ISSET(lfd2, &rr)) {                     /* 对端 c2s 专拨我上报洞口的 SYN 进门 */
int cfd2 = accept(lfd2, NULL, NULL);
if (cfd2 >= 0) {
struct timeval rtv2; rtv2.tv_sec = 2;
setsockopt(cfd2, SOL_SOCKET, SO_RCVTIMEO, &rtv2, sizeof(rtv2));
unsigned char ih2[8], jb2[96], tb2[8];
if (recv_n(cfd2, ih2, 8) == 8) {
uint32_t dl2; uint16_t mt2, st2;
memcpy(&dl2, ih2, 4); memcpy(&mt2, ih2 + 4, 2); memcpy(&st2, ih2 + 6, 2);
if (mt2 == MSG_P2P && st2 == MSG_PUNCH_HANDSHAKE_ACK && dl2 > 0 && dl2 < sizeof(jb2) && recv_n(cfd2, jb2, (int)dl2) == (int)dl2) {    /* [4/1]{"id":t.id}（Go c2s 连上先发）*/
jb2[dl2] = 0;
long long rid = 0;
if (jget_int((char *)jb2, "id", &rid) == 0 && (uint64_t)rid == a->tunnel_id) {
char ab[48]; int al = snprintf(ab, sizeof(ab), "{\"id\":%llu}", (unsigned long long)a->tunnel_id);
unsigned char fh[8]; memset(fh, 0, sizeof(fh));
fh[0] = (unsigned char)(al & 0xFF); fh[4] = (unsigned char)MSG_P2P; fh[6] = (unsigned char)MSG_PUNCH_HANDSHAKE_ACK;
if (send(cfd2, fh, 8, 0) == 8 && send(cfd2, ab, al, 0) == al) {
a->relay_fd = cfd2; cfd2 = -1; punch_listen_ok = 1; hs_done = 1;
ESP_LOGI(TAG, "[port %d] >>> symmetric hole-SYN [4/1] echo ok (peer c2s dialed my reported coneNatPort)", a->srcport);
}
} else ESP_LOGW(TAG, "[port %d] hole [4/1] id mismatch %lld vs %llu", a->srcport, rid, (unsigned long long)a->tunnel_id);
} else if (dl2 == 8 && mt2 == MSG_P2P && st2 == MSG_TUNNEL_HANDSHAKE && recv_n(cfd2, tb2, 8) == 8) {   /* [4/2][LE64 tid]（Go c2s 直连对偶协议）*/
uint64_t tid2; memcpy(&tid2, tb2, 8);
unsigned char ac[16];
ac[0] = 8; ac[4] = (unsigned char)MSG_P2P; ac[6] = (unsigned char)MSG_TUNNEL_HANDSHAKE_ACK;
memcpy(ac + 8, tb2, 8);
if (send(cfd2, ac, sizeof(ac), 0) == (ssize_t)sizeof(ac)) {
a->relay_fd = cfd2; cfd2 = -1; punch_listen_ok = 1; hs_done = 1;
ESP_LOGI(TAG, "[port %d] >>> symmetric hole-SYN [4/2] ack ok tid=%llu self=%llu", a->srcport, (unsigned long long)tid2, (unsigned long long)a->tunnel_id);
}
} else ESP_LOGW(TAG, "[port %d] hole SYN first frame bad dl=%u mt=%u st=%u", a->srcport, dl2, mt2, st2);
}
if (cfd2 >= 0) close(cfd2);
}
}
if (nsel > 0 && pf >= 0 && FD_ISSET(pf, &ww)) {                         /* 路A SYN-ACK 到家：我方作拨出方先发 [4/2] 等 [4/3]（Go dialTCP 成功语义） */
int soerr = 0; socklen_t sol = sizeof(soerr);
getsockopt(pf, SOL_SOCKET, SO_ERROR, &soerr, &sol);
	if (soerr == 0 && !punch_listen_ok) {                                     /* Go s2c(p2ptunnel.go:501-522)连上=先收对端[4/1]{"id"}再回[4/1]建underlay;pf原先发[4/2]等[4/3]会把[4/1]判 dial-handshake bad frame→close(pf)自杀将成之连——30+轮零命中头号嫌疑 */
	struct timeval rtv1; rtv1.tv_sec = 2;
	setsockopt(pf, SOL_SOCKET, SO_RCVTIMEO, &rtv1, sizeof(rtv1));
	unsigned char ph[8], pb[96];
	if (recv_n(pf, ph, 8) == 8) {
	uint32_t dl1; uint16_t mt1, st1;
	memcpy(&dl1, ph, 4); memcpy(&mt1, ph + 4, 2); memcpy(&st1, ph + 6, 2);
	if (mt1 == MSG_P2P && st1 == MSG_PUNCH_HANDSHAKE_ACK && dl1 > 0 && dl1 < sizeof(pb) && recv_n(pf, pb, (int)dl1) == (int)dl1) {
	pb[dl1] = 0;
	long long rid1 = 0;
	if (jget_int((char *)pb, "id", &rid1) == 0 && (uint64_t)rid1 == a->tunnel_id) {
	char ab1[48]; int al1 = snprintf(ab1, sizeof(ab1), "{\"id\":%llu}", (unsigned long long)a->tunnel_id);
	unsigned char fh1[8]; memset(fh1, 0, sizeof(fh1));
	fh1[0] = (unsigned char)(al1 & 0xFF); fh1[4] = (unsigned char)MSG_P2P; fh1[6] = (unsigned char)MSG_PUNCH_HANDSHAKE_ACK;
	if (send(pf, fh1, 8, 0) == 8 && send(pf, ab1, al1, 0) == al1) {
	a->relay_fd = pf; pf = -1; punch_listen_ok = 1; hs_done = 1;
	ESP_LOGI(TAG, "[port %d] >>> symmetric s2c pf [4/1] echo ok (Go dial-success semantics)", a->srcport);
	}
	}
	} else if (dl1 > 0 && dl1 < sizeof(pb)) { unsigned char sink[96]; recv_n(pf, sink, (int)dl1); ESP_LOGW(TAG, "[port %d] pf frame mt=%u st=%u dl=%u (非[4/1])", a->srcport, mt1, st1, dl1); }   /* 垃圾帧:吞body保管线,继续走[4/2]plain路 */
	}
	}
if (soerr != 0) { close(pf); pf = -1; }
else if (pf >= 0) {                                              /* (审计实锤#5)：路C 命中已把 pf 提升为 relay_fd=-1+listen_ok，soerr==0 时原 else 仍对 -1 空转 setsockopt/send 一串 EBADF——加守卫只放行 pf 仍开着的正常 SYN-ACK 回家路 */
unsigned char hs[16]; memset(hs, 0, sizeof(hs));
hs[0] = 8; hs[4] = (unsigned char)MSG_P2P; hs[6] = (unsigned char)MSG_TUNNEL_HANDSHAKE;
uint64_t tidv = a->tunnel_id; memcpy(hs + 8, &tidv, 8);
struct timeval rtv3; rtv3.tv_sec = 2;
setsockopt(pf, SOL_SOCKET, SO_RCVTIMEO, &rtv3, sizeof(rtv3));
if (send(pf, hs, 16, 0) == 16) {
unsigned char rh[8], rb[8];
if (recv_n(pf, rh, 8) == 8) {
uint32_t dl3; uint16_t mt3, st3;
memcpy(&dl3, rh, 4); memcpy(&mt3, rh + 4, 2); memcpy(&st3, rh + 6, 2);
if (dl3 == 8 && mt3 == MSG_P2P && st3 == MSG_TUNNEL_HANDSHAKE_ACK && recv_n(pf, rb, 8) == 8) {
a->relay_fd = pf; pf = -1; punch_listen_ok = 1; hs_done = 1;
ESP_LOGI(TAG, "[port %d] >>> symmetric dial-out [4/3] ack (SYN-ACK home through CGNAT)", a->srcport);
} else ESP_LOGW(TAG, "[port %d] dial-handshake bad frame dl=%u mt=%u st=%u", a->srcport, dl3, mt3, st3);
}
}
if (pf >= 0 && !punch_listen_ok) { close(pf); pf = -1; }
}
}
int64_t nowt = esp_timer_get_time();
if (pf < 0 && !punch_listen_ok && nowt - t_fire >= 2000000) {           /* fire-SYN 2s 节流重拨：早拨撞对端未醒的 listen 被 RST，同口 REUSEADDR 续洞映射 */
pf = socket(AF_INET, SOCK_STREAM, 0);
if (pf >= 0) {
int one5 = 1; setsockopt(pf, SOL_SOCKET, SO_REUSEADDR, &one5, sizeof(one5));
struct sockaddr_in la5; memset(&la5, 0, sizeof(la5));
la5.sin_family = AF_INET; la5.sin_port = htons((uint16_t)g_punch_local_port);
bind(pf, (struct sockaddr *)&la5, sizeof(la5));
fcntl(pf, F_SETFL, O_NONBLOCK);
connect(pf, (struct sockaddr *)&pa, sizeof(pa));
}
t_fire = nowt;
}
if (nsel > 0) {
for (int si = 0; si < nf && !punch_listen_ok; si++) {                   /* 路C 广撒命中（实证路）：对端 c2s 随机 dst 扫中我的拨出 */
	if (fds[si] >= 0 && FD_ISSET(fds[si], &ww)) t_send[si] = esp_timer_get_time();   /* lwIP 对 ESTABLISHED 恒置 ww = Go s2c dialTCP 连上驻留态 → 触钟豁免下方1.2s老化(Go 800驻留口无老化判死,此前[4/1]将至的连致口被误杀) */
										if (fds[si] < 0 || !FD_ISSET(fds[si], &rr)) continue;
	s_readable++;                                                                /* continue 未到 ⇒ FD_ISSET 真：SYN-ACK/RST/数据帧都算对端有答 */
struct timeval rtv2; rtv2.tv_sec = 2;
setsockopt(fds[si], SOL_SOCKET, SO_RCVTIMEO, &rtv2, sizeof(rtv2));
unsigned char ih2[8], jb[96];
int hr5 = recv_n(fds[si], ih2, 8);                                       /* 0B=我方SYN被RST/FIN答(对端口不在punch配对态);8B=应用帧 */
	if (hr5 == 0) s_rsts++;
	else if (hr5 == 8) { s_frames++;
uint32_t dl2; uint16_t mt2, st2;
memcpy(&dl2, ih2, 4); memcpy(&mt2, ih2 + 4, 2); memcpy(&st2, ih2 + 6, 2);
if (mt2 == MSG_P2P && st2 == MSG_PUNCH_HANDSHAKE_ACK && dl2 > 0 && dl2 < sizeof(jb) && recv_n(fds[si], jb, (int)dl2) == (int)dl2) {   /* 对端 c2s 连上先发 [4/1]{"id":t.id} */
jb[dl2] = 0;
long long rid = 0;
if (jget_int((char *)jb, "id", &rid) == 0 && (uint64_t)rid == a->tunnel_id) {
char ab[48]; int al = snprintf(ab, sizeof(ab), "{\"id\":%llu}", (unsigned long long)a->tunnel_id);
unsigned char fh[8]; memset(fh, 0, sizeof(fh));
fh[0] = (unsigned char)(al & 0xFF); fh[4] = (unsigned char)MSG_P2P; fh[6] = (unsigned char)MSG_PUNCH_HANDSHAKE_ACK;
if (send(fds[si], fh, 8, 0) == 8 && send(fds[si], ab, al, 0) == al) {
a->relay_fd = fds[si]; fds[si] = -1; punch_listen_ok = 1; hs_done = 1;
ESP_LOGI(TAG, "[port %d] >>> symmetric s2c [4/1] echo ok (peer SYN hit my mapping)", a->srcport);
}
} else ESP_LOGW(TAG, "[port %d] s2c [4/1] id mismatch %lld vs %llu", a->srcport, rid, (unsigned long long)a->tunnel_id);
}
}
if (fds[si] >= 0 && !punch_listen_ok) {                                  /* 死口（connect 失败/SYN 重传尽/垃圾帧）摘除，等下轮整补 */
close(fds[si]); fds[si] = -1;
}
}
}
	for (int si = 0; si < nf && !punch_listen_ok; si++) {                    /* SYN-SENT 无事件 >1.2s 判死摘除补位（≈2 次 SYN 未回，不等 lwIP 9s SYN 超时）；readable 口已由命中路径处理（非命中必关） */
	if (fds[si] < 0) continue;
	if (esp_timer_get_time() - t_send[si] > 1200000) { close(fds[si]); fds[si] = -1; s_aged++; }
	}
if (time(NULL) - s2c_ctl_hb >= 15) { send_heartbeat(); s2c_ctl_hb = time(NULL); }   /* WSS 保活 */
vTaskDelay(pdMS_TO_TICKS(20));
}
	ESP_LOGI(TAG, "[port %d] s2c window end dialed=%d readable=%d aged=%d rsts=%d frames=%d (rsts≈readable ⇒ 对端把我方全部SYN纯RST=对端不在打(punch配对窗未开);frames>0无命中 ⇒ 配对语义问题;rsts=0且frames=0 ⇒ readable全是SYN-ACK半连)", a->srcport, s_dialed, s_readable, s_aged, s_rsts, s_frames);
for (int si = 0; si < S2C_N; si++) if (fds[si] >= 0) close(fds[si]);
if (lfd2 >= 0) close(lfd2);
if (pf >= 0) close(pf);
		} else {
	int lfd2 = -1;
		int pf_errs = 0;														/* pf 拨出失败次数：RST风暴(对端listen没起) vs 静默(路由丢) */
	int pf = socket(AF_INET, SOCK_STREAM, 0);                       /* fire-SYN #1：先于一切，抢 restricted-cone 许可 */
	if (pf >= 0) {
	int one3 = 1; setsockopt(pf, SOL_SOCKET, SO_REUSEADDR, &one3, sizeof(one3));
	struct sockaddr_in la3; memset(&la3, 0, sizeof(la3));
	la3.sin_family = AF_INET; la3.sin_port = htons((uint16_t)g_punch_local_port);
	if (bind(pf, (struct sockaddr *)&la3, sizeof(la3)) != 0)
	ESP_LOGW(TAG, "[port %d] fire-SYN bind %d fail errno=%d", a->srcport, g_punch_local_port, errno);
	fcntl(pf, F_SETFL, O_NONBLOCK);
		if (connect(pf, (struct sockaddr *)&pa, sizeof(pa)) != 0 && errno != EINPROGRESS) ESP_LOGW(TAG, "[port %d] pf 首拨 %s:%lld 即败 errno=%d (RST=对端出口拒绝/router代RST)", a->srcport, relay_ip, relay_port, errno);					/* 非阻塞常驻：EINPROGRESS 正常，主循环写集监控 SYN-ACK（Go dialTCP 语义） */
	}
	lfd2 = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd2 >= 0) {
	int one4 = 1; setsockopt(lfd2, SOL_SOCKET, SO_REUSEADDR, &one4, sizeof(one4));
	struct sockaddr_in la4; memset(&la4, 0, sizeof(la4));
	la4.sin_family = AF_INET; la4.sin_port = htons((uint16_t)g_punch_local_port);
	if (bind(lfd2, (struct sockaddr *)&la4, sizeof(la4)) != 0 || listen(lfd2, 2) != 0) {
	ESP_LOGW(TAG, "[port %d] punch LISTEN :%d fail errno=%d", a->srcport, g_punch_local_port, errno);
	close(lfd2); lfd2 = -1;
	}
	}
	if (lfd2 >= 0) {
	int64_t deadline_us = esp_timer_get_time() + (punch_ts_ll + g_dt_ns - now_ns_real()) / 1000 + 10000000;    /* punchts 本机钟帧 +10s */
	if (deadline_us < esp_timer_get_time() + 3000000) deadline_us = esp_timer_get_time() + 3000000;
	ESP_LOGI(TAG, "[port %d] LISTEN :%d (pub %s:%d) <- peer %s:%lld until punchts+10s",
	a->srcport, g_punch_local_port, g_punch_ip, g_punch_nat_port, relay_ip, relay_port);
	int64_t t_fire = esp_timer_get_time();
	time_t last_ctl_hb = time(NULL);
	while (!punch_listen_ok && esp_timer_get_time() < deadline_us) {
	fd_set ra, wa; FD_ZERO(&ra); FD_ZERO(&wa);
	FD_SET(lfd2, &ra);
	if (pf >= 0) FD_SET(pf, &wa);                                   /* dial 写集：connect 完成(SYN-ACK 到家)是主路 */
	int nfd2 = (pf > lfd2 ? pf : lfd2) + 1;
	struct timeval tvw; tvw.tv_sec = 0; tvw.tv_usec = 100000;    /* 100ms 片 */
	int nsel = select(nfd2, &ra, &wa, NULL, &tvw);
	if (nsel > 0 && FD_ISSET(lfd2, &ra)) {
	int cfd2 = accept(lfd2, NULL, NULL);
	if (cfd2 >= 0) {
	struct timeval rtv; rtv.tv_sec = 3;
	setsockopt(cfd2, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
	unsigned char ih[8], tb[8];
	if (recv_n(cfd2, ih, 8) == 8) {
	uint32_t dl; uint16_t mt, st;
	memcpy(&dl, ih, 4); memcpy(&mt, ih + 4, 2); memcpy(&st, ih + 6, 2);
	if (dl == 8 && mt == MSG_P2P && st == MSG_TUNNEL_HANDSHAKE && recv_n(cfd2, tb, 8) == 8) {
	uint64_t tid; memcpy(&tid, tb, 8);
	ESP_LOGI(TAG, "[port %d] peer SYN in! [4/2] tid=%llu self=%llu%s", a->srcport,
	(unsigned long long)tid, (unsigned long long)a->tunnel_id, tid == a->tunnel_id ? "" : " MISMATCH");
	unsigned char ac[16];
	ac[0] = 8; ac[1] = 0; ac[2] = 0; ac[3] = 0;    /* DataLen=8，echo 原 body */
	ac[4] = (unsigned char)MSG_P2P; ac[5] = 0;
	ac[6] = (unsigned char)MSG_TUNNEL_HANDSHAKE_ACK; ac[7] = 0;
	memcpy(ac + 8, tb, 8);
	if (send(cfd2, ac, sizeof(ac), 0) == (ssize_t)sizeof(ac)) {
	a->relay_fd = cfd2; cfd2 = -1; punch_listen_ok = 1; hs_done = 1;
	ESP_LOGI(TAG, "[port %d] >>> underlay DIRECT via one-way punch (peer dialed us)", a->srcport);
	}
	} else ESP_LOGW(TAG, "[port %d] accept first frame bad (dl=%u mt=%u st=%u)", a->srcport, dl, mt, st);
	}
	if (cfd2 >= 0) close(cfd2);
	}
			}                                             /* if (select...) 可读分支闭合 */
		if (nsel > 0 && pf >= 0 && FD_ISSET(pf, &wa)) {             /* Go dialTCP 成功路径：SO_ERROR==0 → 拨出方先发 [4/2][LE64 tid]（同 cand 直连协议），等对端 listen 侧回 [4/3] */
			int soerr = 0; socklen_t sol = sizeof(soerr);
			if (soerr != 0) { pf_errs++; ESP_LOGW(TAG, "[port %d] pf 拨 %s:%lld err=%d（2s 节流重拨同口）", a->srcport, relay_ip, relay_port, soerr); close(pf); pf = -1; }
			/* (审计实锤#4)：此条与上一行字面重复的 close(pf) 双关行已删。另本分支 soerr 从未 getsockopt 取值恒0，整块 [4/2] 路为 dead code（g_nat_type=2 硬写不走），启用 cone 路时须仿 s2c @1176 补 getsockopt */
			else {
				unsigned char hs[16]; memset(hs, 0, sizeof(hs));
				hs[0] = 8; hs[4] = (unsigned char)MSG_P2P; hs[6] = (unsigned char)MSG_TUNNEL_HANDSHAKE;
				uint64_t tidv = a->tunnel_id; memcpy(hs + 8, &tidv, 8);
				struct timeval rtv3; rtv3.tv_sec = 2;
				setsockopt(pf, SOL_SOCKET, SO_RCVTIMEO, &rtv3, sizeof(rtv3));
				if (send(pf, hs, 16, 0) == 16) {
					unsigned char rh[8], rb[8];
					if (recv_n(pf, rh, 8) == 8) {
						uint32_t dl3; uint16_t mt3, st3;
						memcpy(&dl3, rh, 4); memcpy(&mt3, rh + 4, 2); memcpy(&st3, rh + 6, 2);
						if (dl3 == 8 && mt3 == MSG_P2P && st3 == MSG_TUNNEL_HANDSHAKE_ACK && recv_n(pf, rb, 8) == 8) {
							a->relay_fd = pf; pf = -1; punch_listen_ok = 1; hs_done = 1;
							ESP_LOGI(TAG, "[port %d] >>> underlay DIRECT via my dial: [4/3] ack (SYN-ACK home through CGNAT)", a->srcport);
							} else ESP_LOGW(TAG, "[port %d] dial-handshake bad frame dl=%u mt=%u st=%u", a->srcport, dl3, mt3, st3);
						}
					}
				if (pf >= 0 && !punch_listen_ok) { close(pf); pf = -1; }
				}
			}
	int64_t nowt = esp_timer_get_time();
	if (pf < 0 && nowt - t_fire >= 2000000) {                       /* dial 重拨节流：首拨早于对端 listen 睡醒被 RST，2s 后同口 REUSEADDR 重发，落 punchts 后命中 */                  /* fire-SYN 4s 周期性：洞映射保鲜(30-120s)+restricted 许可续期 */
	pf = socket(AF_INET, SOCK_STREAM, 0);
	if (pf >= 0) {
	int one5 = 1; setsockopt(pf, SOL_SOCKET, SO_REUSEADDR, &one5, sizeof(one5));
	struct sockaddr_in la5; memset(&la5, 0, sizeof(la5));
	la5.sin_family = AF_INET; la5.sin_port = htons((uint16_t)g_punch_local_port);
	bind(pf, (struct sockaddr *)&la5, sizeof(la5));
	fcntl(pf, F_SETFL, O_NONBLOCK);
	connect(pf, (struct sockaddr *)&pa, sizeof(pa));
	}
	t_fire = nowt;
	}
	if (time(NULL) - last_ctl_hb >= 15) { send_heartbeat(); last_ctl_hb = time(NULL); }    /* WSS 保活：防 setup 期被服务器 idle 踢 */
	vTaskDelay(pdMS_TO_TICKS(20));
	}
	}
	ESP_LOGI(TAG, "[port %d] punch 窗口退出 pf_errs=%d（pf_errs≈窗长/2s=每拨皆RST⇒对端listen未起或router不转34865；pf_errs=0且peer SYN未入⇒双向静默）", a->srcport, pf_errs);
	if (lfd2 >= 0) close(lfd2);
	if (pf >= 0) close(pf);                             /* 泄漏修复(审计实锤#3)：cone 分支窗口退出从不关 pf（s2c 分支 @1275 有关）——现 g_nat_type=2 硬写未触发，删该行后每次 dial 泄一颗 */
	}                                                                   /* if (g_nat_type==2) s2c / else cone-LISTEN 双分支闭合 */
	if (punch_listen_ok) {
	a->direct = 1;                                       /* 裸 [4/9]/[4/4]/[4/6] 直连分支；relay 槽弃用 */
	char ssm2[256];
	snprintf(ssm2, sizeof(ssm2),
			"{\"from\":\"%s\",\"node\":\"%s\",\"tunnelID\":%llu,\"relayTunnelID\":0,\"relayMode\":\"%s\","
			"\"appID\":%llu,\"appKey\":%llu,\"relayIndex\":0,\"tunnelNum\":2,\"srcPort\":%u}",
	OPENP2P_NODE, a->relay_name, (unsigned long long)a->tunnel_id, a->relay_mode,
	(unsigned long long)a->app_id, (unsigned long long)a->app_key, (unsigned)a->srcport);
	ESP_LOGI(TAG, "ServerSideSaveMemApp(direct): %s", ssm2);    /* handlepush.go:111 direct tunnel rtid=0 */
	if (op2p_push(g_peer_name, MSG_PUSH_SERVER_SIDE_SAVE_MEMAPP, ssm2) != ESP_OK)
	ESP_LOGW(TAG, "[port %d] direct SSM push fail (peer won't know appID)", a->srcport);
	}
	}
	for (int ci = 0; ci < (punch_ok ? 0 : 2) && !hs_done; ci++) {          /* punch 主路跳过候选：Mobile->Unicom v4 全 113 黑洞实证 */
		if (cand[ci] == 0) continue;
		long long port = cand[ci];
			for (int tryno = 0; tryno < (punch_ok ? 1 : 3) && !hs_done; tryno++) {   /* punch 主路时 fallback 各候选仅 1 次：113 黑洞省时间 */
			if (tryno > 0) vTaskDelay(pdMS_TO_TICKS(tryno == 1 ? 400 : 500));   /* 落在对端 punch SYN 之后再拨 */
			struct sockaddr_in sa;
			memset(&sa, 0, sizeof(sa));
			sa.sin_family = AF_INET;
			sa.sin_port   	= htons((uint16_t)port);
			sa.sin_addr.s_addr = inet_addr(relay_ip);
			a->relay_fd = socket(AF_INET, SOCK_STREAM, 0);
			if (a->relay_fd < 0) { ESP_LOGE(TAG, "[port %d] relay socket fail", a->srcport); return ESP_FAIL; }
			int one2 = 1;
			setsockopt(a->relay_fd, SOL_SOCKET, SO_REUSEADDR, &one2, sizeof(one2));
			if (g_punch_local_port > 0 && port != v4l_port) {         /* punch 候选绑同源口命中同 cone 映射；v4l=随机源口（Go dialTCP tcp4:109） */
				struct sockaddr_in la2; memset(&la2, 0, sizeof(la2));
				la2.sin_family = AF_INET; la2.sin_port = htons((uint16_t)g_punch_local_port);
				if (bind(a->relay_fd, (struct sockaddr *)&la2, sizeof(la2)) != 0)
					ESP_LOGW(TAG, "[port %d] bind hole source port %d failed, fallback random", a->srcport, g_punch_local_port);
			}
				if (connect(a->relay_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
				ESP_LOGW(TAG, "[port %d] dial cand=%lld try=%d fail errno=%d", a->srcport, port, tryno, errno);
				close(a->relay_fd); a->relay_fd = -1;
				continue;
			}
			ESP_LOGI(TAG, "[port %d] cand=%lld TCP up (try=%d), probe TunnelHandshake", a->srcport, port, tryno);
			if (send(a->relay_fd, hs, sizeof(hs), 0) != (ssize_t)sizeof(hs)) {
				ESP_LOGW(TAG, "[port %d] TunnelHandshake send fail cand=%lld", a->srcport, port);
				close(a->relay_fd); a->relay_fd = -1;
				continue;
			}
			struct timeval acktv = { .tv_sec = 3 };                   /* ack 超时：假连（打到自家出站映射）不吊死 */
			setsockopt(a->relay_fd, SOL_SOCKET, SO_RCVTIMEO, &acktv, sizeof(acktv));
			unsigned char rh[8];
			uint32_t rdl = 0xFFFFFFFF; uint16_t rmt = 0, rsub = 0;
			char rbody[256] = {0};
			if (recv_n(a->relay_fd, rh, 8) == 8) {
				memcpy(&rdl, rh, 4); memcpy(&rmt, rh + 4, 2); memcpy(&rsub, rh + 6, 2);
				if (rdl > 0 && rdl < sizeof(rbody) && recv_n(a->relay_fd, rbody, (int)rdl) != (int)rdl) rdl = 0xFFFFFFFF;
			}
			if (rmt == MSG_P2P && rsub == MSG_TUNNEL_HANDSHAKE_ACK && rdl == 8) {
				relay_port = port;                                    /* 命中候选：v4l getUnderlay(tid)/punch listenTCP 均回 4/3 */
				hs_done = 1;
				ESP_LOGI(TAG, ">>> cand %lld ack OK — relay TCP connected to %s:%lld (try=%d)", port, relay_ip, port, tryno);
			} else {
				ESP_LOGW(TAG, "[port %d] cand=%lld no 4/3 ack (rdl=%u mt=%u st=%u) — not the real listener", a->srcport, port, rdl, rmt, rsub);
				close(a->relay_fd); a->relay_fd = -1;
			}
		}
	}
	if (!hs_done && strcmp(a->relay_name, g_peer_name) != 0) {   /* Go addRelayTunnel:280-374——对端 v4l 拨不通（双 CGNAT RST 实证）回落官方 relay 隧道：relay 地址不在 RelayNodeRsp（只有名/token），relay 自己经网关 WSS 推 [3/2]（Go p2ptunnel.go:845-868 listen(): FromIP=relay 公网/ConeNatPort=relay PublicIPPort）；Go 里 ConnectReq 收件人=relay（p2ptunnel.go:96 push(t.config.PeerNode=relayName)） */
	uint64_t relay_id = node_name_to_id(a->relay_name);           /* relay 节点ID(CRC-64)，[3/x] from 过滤 */
	if (a->relay_tid == 0) a->relay_tid = rand64();               /* Go addRelayTunnel→addDirectTunnel 建独立隧道：tid 独立于对端直连，relay allTunnels 主键，跨重试复用防僵尸 */
	/* Go initPort:49-58 LinkModeUDPPunch：每条隧道建前用自身随机本口先 natDetectUDP(ServerIP,27180)
	   预开一个 cone 映射，其外口即上报的 coneNatPort，稍后 QUIC 绑同本口拨出（Go dialQuic 的 conn
	   就是 ListenUDP(coneLocalPort)）；relay 依 coneNatPort 回拨我，洞才配得上 */
	int hole_local = (int)(esp_random() % 8192 + 1025);                  /* Go rand.Uint32()%8192+1025，非 nat_detect 的 50000 段 */
	char hole_ip[48] = {0};
	int hole_nat = nat_probe_udp(hole_local, 27180, hole_ip, sizeof(hole_ip));     /* Go initPort:56 只探测口1；UDP 被封无 TCP 兜底=洞必死，dial 失败拉黑换 relay */
	ESP_LOGI(TAG, "[port %d] udppunch 预打洞 coneLocalPort=%d coneNatPort=%d (Go initPort:71 prepare punching port)", a->srcport, hole_local, hole_nat);
	char rreq[256];
			snprintf(rreq, sizeof(rreq),
				"{\"from\":\"%s\",\"version\":\"%s\",\"fromIP\":\"%s\",\"natType\":%d,\"token\":%llu,"
				"\"coneNatPort\":%llu,\"id\":%llu,\"appKey\":0,\"linkMode\":\"udppunch\",\"isServer\":1,"
				"\"underlayProtocol\":\"quic\",\"hasIPv4\":1}",
		OPENP2P_NODE, OPENP2P_CLIENT_VERSION, g_public_ip, g_nat_type, (unsigned long long)a->relay_token,
				(unsigned long long)(hole_nat > 0 ? hole_nat : hole_local), (unsigned long long)a->relay_tid);    /* linkMode=udppunch：relay handleConnectReq→connectUnderlayUDP server 用自身 natDetectUDP 口 listenQuic 再推 [3/2]/[3/8]；coneNatPort 诚实上报我的 UDP 探测外口（Go t.coneNatPort） */
	ESP_LOGI(TAG, "[port %d] RelayConnectReq→relay %s (Go addRelayTunnel 的 ConnectReq 收件人=relay): %s", a->srcport, a->relay_name, rreq);
	char rrsp[1024] = {0};
	char rip[64] = {0}; long long rport = 0, rerr = 0;
	int pushok = (op2p_push(a->relay_name, MSG_PUSH_CONNECT_REQ, rreq) == ESP_OK);
	esp_err_t e7 = ESP_ERR_TIMEOUT;
	if (pushok) e7 = op2p_recv_expect_from(MSG_PUSH, MSG_PUSH_CONNECT_RSP, relay_id, rrsp, sizeof(rrsp), 2000, 15);
	if (pushok && e7 == ESP_OK) { jget_str(rrsp, "fromIP", rip, sizeof(rip)); jget_int(rrsp, "coneNatPort", &rport); if (!rip[0]) jget_int(rrsp, "error", &rerr); }
	if (pushok && e7 == ESP_OK && rip[0] && rport > 0) {
		ESP_LOGI(TAG, "[port %d] relay 自身地址 = %s:%lld（relay 亲推 [3/2]=Go listen() 推 connect ok，其 v4l 已就位）", a->srcport, rip, rport);
			esp_err_t e8 = op2p_recv_expect_from(MSG_PUSH, MSG_PUSH_UNDERLAY_CONNECT, relay_id, rrsp, sizeof(rrsp), 1500, 8);
		ESP_LOGI(TAG, "[port %d] [3/8] MsgPushUnderlayConnect e=%d（Go client 等 relay listenQuic 就位后 dialQuic；迟到无妨：Initial 400ms 自重发）", a->srcport, e8);
		/* 预打洞口对 coneLocalPort:coneNatPort 见 rreq 前（Go initPort:49-58），appidx 偏移已废 */
		int qport = hole_nat > 0 ? hole_local : 0;     /* Go dialQuic(conn=ListenUDP(coneLocalPort))：预打洞成功绑 coneLocalPort 拨出，失败退随机口 */    /* QUIC 源口=UDP 探测同 cone 映射口（Go ListenUDP 复用 natDetectUDP 同口）；+appidx 避 lwIP 同口双绑；0=随机（relay 被动 accept，回程按我出站映射，可接受） */
		a->qconn = quic_connect(qport, rip, (int)rport, a->relay_tid, 8000);    /* dialQuic(rip:[3/2]coneNatPort)：ALPN openp2pv1/v1/InsecureSkipVerify；stream0 [4/2][LE64 relay_tid] 等 [4/3]"OpenP2P,hello2" */
		if (a->qconn) {
			hs_done = 1;
			snprintf(relay_ip, sizeof(relay_ip), "%s", rip); relay_port = rport;
			ESP_LOGI(TAG, "[port %d] >>> QUIC relay 隧道打通：dialQuic %s:%lld (源口 %d)", a->srcport, rip, rport, qport);
				} else {
			snprintf(a->last_fail, sizeof(a->last_fail), "%s", a->relay_name);
			ESP_LOGE(TAG, "[port %d] QUIC dial %s:%lld 失败 → 拉黑 %s（换中继重试）", a->srcport, rip, rport, a->relay_name);
				}
			if (!hs_done) { snprintf(a->last_fail, sizeof(a->last_fail), "%s", a->relay_name);    /* private relay 同样在 CGNAT 后/官方 relay 故障 → 拉黑，外层 excl 追加逼服务器改派 */
			ESP_LOGE(TAG, "[port %d] relay %s v4l 拨不通 → 拉黑（Go addRelayTunnel relay 不可用报外层换节点）", a->srcport, a->relay_name); }
			} else {
		if (pushok && e7 == ESP_OK && !rerr) jget_int(rrsp, "error", &rerr);
		ESP_LOGE(TAG, "[port %d] relay 的 [3/2] 无地址 e=%d pushok=%d error=%lld → 拉黑 %s（busy=服务器未转发）", a->srcport, e7, pushok, rerr, a->relay_name);
		snprintf(a->last_fail, sizeof(a->last_fail), "%s", a->relay_name);
				}
	}
	if (!hs_done) { ESP_LOGE(TAG, "[port %d] relay %s 所有候选端口无 ack (v4l=%lld rsp=%lld)", a->srcport, relay_ip, v4l_port, relay_port); live_relay_invalidate(a);/* relay underlay 拨不通实锤→作废全局活 relay，全家回炉 RelayNodeReq（Go hbTime[1] 过期→:312 重派；健康 relay 被 mux14 持续续期不受冤杀） */ return ESP_FAIL; }
	if (g_punch_fd >= 0) { close(g_punch_fd); g_punch_fd = -1; }    /* close detect connection: mapping already punched through */

	/* 3) AddRelayTunnelReq -> Rsp（MsgPush=3 sub=4 -> sub=5）拿 rtid */
	char areq[256];
	if (!a->direct) {                                        /* 直连隧道无 relay：免 AddRelayTunnelReq/rtid */
	snprintf(areq, sizeof(areq),
			"{\"from\":\"%s\",\"relayName\":\"%s\",\"relayToken\":%llu,\"relayMode\":\"%s\","
			"\"relayTunnelID\":%llu,\"punchPriority\":1,\"underlayProtocol\":\"quic\"}",
			OPENP2P_NODE, a->relay_name, (unsigned long long)a->relay_token, a->relay_mode,
			(unsigned long long)a->tunnel_id);
	ESP_LOGI(TAG, "AddRelayTunnelReq: %s", areq);
	if (op2p_push(g_peer_name, MSG_PUSH_ADD_RELAY_TUNNEL_REQ, areq) != ESP_OK) {
		ESP_LOGE(TAG, "[port %d] AddRelayTunnelReq 发送失败", a->srcport);
		return ESP_FAIL;
	}
	char arsp[512] = {0};
	e = op2p_recv_expect(MSG_PUSH, MSG_PUSH_ADD_RELAY_TUNNEL_RSP, arsp, sizeof(arsp), 10000, 10);
	if (e != ESP_OK) { ESP_LOGE(TAG, "[port %d] AddRelayTunnelRsp 超时/失败 %d", a->srcport, e); return e; }
	ESP_LOGI(TAG, "AddRelayTunnelRsp: %s", arsp);
	long long rtid_ll = 0;
	if (jget_int(arsp, "id", &rtid_ll) == 0) a->rtid = (uint64_t)rtid_ll;
	ESP_LOGI(TAG, ">>> rtid(对端 relay 隧道 ID) = %llu", (unsigned long long)a->rtid);
		/* 注册 memapp 到对端（对齐 buildRelayTunnel:422 push ServerSideSaveMemApp）：
		对端 handle(handlepush.go:66-114) 用 allTunnels.Load(tunnelID) 找到它对 relay
		的隧道、按 appID 建 memapp 并 SetRelayTunnelID(relayTunnelID)——缺这步对端
		handleOverlayConnectReq 找不到我的 app，不会 dial 目标也不会回 OverlayConnectRsp。
		tunnelID=对端 AddRelayTunnelRsp 回给我的 rtid（对端 allTunnels 以它的 tunnel.id 为键）；
		relayTunnelID=我的 relay 隧道 id（对端回数据按它裹 [4/10] 外层交 relay server 转我）；
		relayIndex=1/tunnelNum=2 对齐 Go 双槽布局(idx0=direct idx1=relay) */
		char ssm[256];
		snprintf(ssm, sizeof(ssm),
		"{\"from\":\"%s\",\"node\":\"%s\",\"tunnelID\":%llu,\"relayTunnelID\":%llu,\"relayMode\":\"%s\","
		"\"appID\":%llu,\"appKey\":%llu,\"relayIndex\":1,\"tunnelNum\":2,\"srcPort\":%u}",
		OPENP2P_NODE, a->relay_name, (unsigned long long)a->rtid, (unsigned long long)a->tunnel_id,
		a->relay_mode, (unsigned long long)a->app_id, (unsigned long long)a->app_key, (unsigned)a->srcport);
		ESP_LOGI(TAG, "ServerSideSaveMemApp: %s", ssm);
		if (op2p_push(g_peer_name, MSG_PUSH_SERVER_SIDE_SAVE_MEMAPP, ssm) != ESP_OK)
		ESP_LOGW(TAG, "[port %d] ServerSideSaveMemApp 推送失败（对端将不认 appID）", a->srcport);
	}

	/* 4) APPKey（MsgPush=3 sub=13）同步 app.id/app.key */
	char ak[128];
	snprintf(ak, sizeof(ak), "{\"appID\":%llu,\"appKey\":%llu}",
			(unsigned long long)a->app_id, (unsigned long long)a->app_key);
	ESP_LOGI(TAG, "APPKey: %s", ak);
	if (op2p_push(g_peer_name, MSG_PUSH_APP_KEY, ak) != ESP_OK) {
		ESP_LOGE(TAG, "[port %d] APPKey 发送失败", a->srcport);
		return ESP_FAIL;
	}

	/* 5) TunnelHeartbeat 验证 relay TCP 双向（MT=4 ST=4，body=nodeID 8B） */
	unsigned char hb[16];
	uint64_t nodeid = rand64();
	hb[0] = 8; hb[1] = 0; hb[2] = 0; hb[3] = 0;   /* DataLen=8 */
	hb[4] = (unsigned char)MSG_P2P; hb[5] = 0;     /* MainType=4 */
	hb[6] = (unsigned char)MSG_TUNNEL_HEARTBEAT; hb[7] = 0;  /* SubType=4 */
	for (int i = 0; i < 8; i++) hb[8 + i] = (unsigned char)((nodeid >> (8 * i)) & 0xFF);
	if ((a->qconn ? (quic_stream_write((quic_conn_t *)a->qconn, hb, (int)sizeof(hb)) == 0 ? (ssize_t)sizeof(hb) : -1) : send(a->relay_fd, hb, sizeof(hb), 0)) != (ssize_t)sizeof(hb)) {
		ESP_LOGE(TAG, "[port %d] TunnelHeartbeat send 失败", a->srcport);
		return ESP_FAIL;
	}
	ESP_LOGI(TAG, "[port %d] TunnelHeartbeat sent —— relay 数据面建链完成", a->srcport);
	a->ready = 1;
	return ESP_OK;
}

/* ==================== Flash 2：数据面（本地监听 + overlay 复用 + AES 双向泵） ====================
 * 角色定位（源码实证）：ESP32 = app 监听侧，本地 0.0.0.0:SrcPort 监听。
 *   RDP 客户端连本地端口 → 发 OverlayConnectReq 通知对端(PEER) dial DstHost:DstPort →
 *   收 OverlayConnectRsp → 双向搬数据（经 relay 隧道）。对端 handleOverlayConnectReq
 *   (p2ptunnel.go:753) 负责 dial DstHost:DstPort 并回 Rsp。
 * 协议要点（对齐 ）：
 *   - overlay 帧 body = [overlayHeader id 8B LE] + [payload]；
 *     payload = app.key!=0 ? AES-128-CBC-PKCS7(明文) : 明文（overlay.go:71 / p2ptunnel.go:662）。
 *   - 发侧 relay 模式（p2ptunnel.go WriteBytes:970）：外层 MsgRelayData(10) + [rtid 8B]
 *     + 内层 MsgOverlayData(9) 头 + data；relay 按 rtid 把 body[8:] 原样转发给对端（pn.relay:979）。
 *   - 收侧（p2ptunnel.go:643）：直接是内层 MsgOverlayData(9) + [id 8B] + [payload]（relay 已剥外层）。
 *   - OverlayConnectReq(6) 的 token 用 Network.Token（登录 token，非 relayToken；对端 :760 校验）。
 *   - tunnel 保活：收 TunnelHeartbeat(4) 回 Ack(5)；定期发 TunnelHeartbeat(4) body=nodeID。
 */

/* ---------- 自包含 AES-128（加解密 + 密钥扩展），逐字节对齐 Go crypto/aes ----------
 * S-box 用 GF(2^8) 逆 + 仿射在运行期一次性生成（免手写 512 字节表）。
 * state 用 FIPS-197 列主序：state(r,c)=s[r+4c]，即 s[i]=in[i]（flat 即列主序）。 */
static uint8_t g_sbox[256], g_inv_sbox[256];
static volatile int g_sbox_ready = 0;

static uint8_t aes_gmul(uint8_t a, uint8_t b)	/* GF(2^8) 乘，约减多项式 0x11b */
{
	uint8_t p = 0;
	for (int i = 0; i < 8; i++) {
		if (b & 1) p ^= a;
		uint8_t hi = (uint8_t)(a & 0x80);
		a = (uint8_t)(a << 1);
		if (hi) a ^= 0x1b;
		b >>= 1;
	}
	return p;
}

static uint8_t aes_ginv(uint8_t x)	/* x^{-1} = x^254（x==0 → 0） */
{
	if (x == 0) return 0;
	uint8_t r = 1, b = x;
	int e = 254;
	while (e) { if (e & 1) r = aes_gmul(r, b); b = aes_gmul(b, b); e >>= 1; }
	return r;
}

static uint8_t aes_sbox_gen(uint8_t b)	/* S(b) = L(b^{-1}) ^ 0x63；L(x)=x^rot(x)^rot²(x)^rot³(x)^rot⁴(x) */
{
	uint8_t x = aes_ginv(b), l = x, r = x;
	for (int i = 1; i <= 4; i++) { r = (uint8_t)((r << 1) | (r >> 7)); l ^= r; }
	return (uint8_t)(l ^ 0x63);
}

static void aes_init_tables(void)	/* 一次性生成 S-box / InvS-box（幂等） */
{
	if (g_sbox_ready) return;
	for (int i = 0; i < 256; i++) g_sbox[i] = aes_sbox_gen((uint8_t)i);
	for (int i = 0; i < 256; i++) g_inv_sbox[g_sbox[i]] = (uint8_t)i;
	g_sbox_ready = 1;
}

static void aes_key_schedule(const uint8_t key[16], uint8_t rk[176])	/* 44 字 = 176 字节 */
{
	memcpy(rk, key, 16);
	uint8_t rcon = 1;
	for (int i = 4; i < 44; i++) {
		uint8_t t[4];
		memcpy(t, rk + 4 * (i - 1), 4);
		if (i % 4 == 0) {	/* t = SubWord(RotWord(t) ^ rcon)，rcon 作用于首字节 */
			uint8_t a0 = (uint8_t)(g_sbox[t[1]] ^ rcon);
			uint8_t a1 = g_sbox[t[2]];
			uint8_t a2 = g_sbox[t[3]];
			uint8_t a3 = g_sbox[t[0]];
			t[0] = a0; t[1] = a1; t[2] = a2; t[3] = a3;
			rcon = aes_gmul(rcon, 2);
		}
		for (int j = 0; j < 4; j++) rk[4 * i + j] = (uint8_t)(rk[4 * (i - 4) + j] ^ t[j]);
	}
}

static void aes_subbytes(uint8_t s[16])	{ for (int i = 0; i < 16; i++) s[i] = g_sbox[s[i]]; }
static void aes_inv_subbytes(uint8_t s[16])	{ for (int i = 0; i < 16; i++) s[i] = g_inv_sbox[s[i]]; }

static void aes_shiftrows(uint8_t s[16])	/* state(r,c)←state(r,(c+r)%4) */
{
	uint8_t t[16];
	t[0]=s[0];  t[1]=s[5];   t[2]=s[10];  t[3]=s[15];
	t[4]=s[4];  t[5]=s[9];   t[6]=s[14];  t[7]=s[3];
	t[8]=s[8];  t[9]=s[13];  t[10]=s[2];  t[11]=s[7];
	t[12]=s[12]; t[13]=s[1]; t[14]=s[6];  t[15]=s[11];
	memcpy(s, t, 16);
}

static void aes_inv_shiftrows(uint8_t s[16])	/* state(r,c)←state(r,(c-r)%4) */
{
	uint8_t t[16];
	t[0]=s[0];   t[1]=s[13];  t[2]=s[10];  t[3]=s[7];
	t[4]=s[4];   t[5]=s[1];   t[6]=s[14];  t[7]=s[11];
	t[8]=s[8];   t[9]=s[5];   t[10]=s[2];  t[11]=s[15];
	t[12]=s[12]; t[13]=s[9];  t[14]=s[6];  t[15]=s[3];
	memcpy(s, t, 16);
}

static void aes_mixcolumns(uint8_t s[16])
{
	for (int c = 0; c < 4; c++) {
		uint8_t a0 = s[4*c], a1 = s[4*c+1], a2 = s[4*c+2], a3 = s[4*c+3];
		s[4*c+0] = (uint8_t)(aes_gmul(a0,2) ^ aes_gmul(a1,3) ^ a2 ^ a3);
		s[4*c+1] = (uint8_t)(a0 ^ aes_gmul(a1,2) ^ aes_gmul(a2,3) ^ a3);
		s[4*c+2] = (uint8_t)(a0 ^ a1 ^ aes_gmul(a2,2) ^ aes_gmul(a3,3));
		s[4*c+3] = (uint8_t)(aes_gmul(a0,3) ^ a1 ^ a2 ^ aes_gmul(a3,2));
	}
}

static void aes_inv_mixcolumns(uint8_t s[16])
{
	for (int c = 0; c < 4; c++) {
		uint8_t a0 = s[4*c], a1 = s[4*c+1], a2 = s[4*c+2], a3 = s[4*c+3];
		s[4*c+0] = (uint8_t)(aes_gmul(a0,14) ^ aes_gmul(a1,11) ^ aes_gmul(a2,13) ^ aes_gmul(a3,9));
		s[4*c+1] = (uint8_t)(aes_gmul(a0,9) ^ aes_gmul(a1,14) ^ aes_gmul(a2,11) ^ aes_gmul(a3,13));
		s[4*c+2] = (uint8_t)(aes_gmul(a0,13) ^ aes_gmul(a1,9) ^ aes_gmul(a2,14) ^ aes_gmul(a3,11));
		s[4*c+3] = (uint8_t)(aes_gmul(a0,11) ^ aes_gmul(a1,13) ^ aes_gmul(a2,9) ^ aes_gmul(a3,14));
	}
}

static void aes_add_roundkey(uint8_t s[16], int r, const uint8_t rk[176])
{
	for (int i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
}

void aes_block_enc(const uint8_t in[16], uint8_t out[16], const uint8_t key[16])    /* 非 static：quic_cli.c 复用作 GCM/HP 内核 */
{
	uint8_t rk[176], s[16];
	aes_key_schedule(key, rk);
	memcpy(s, in, 16);
	aes_add_roundkey(s, 0, rk);
	for (int r = 1; r < 10; r++) { aes_subbytes(s); aes_shiftrows(s); aes_mixcolumns(s); aes_add_roundkey(s, r, rk); }
	aes_subbytes(s); aes_shiftrows(s); aes_add_roundkey(s, 10, rk);
	memcpy(out, s, 16);
}

static void aes_block_dec(const uint8_t in[16], uint8_t out[16], const uint8_t key[16])
{
	uint8_t rk[176], s[16];
	aes_key_schedule(key, rk);
	memcpy(s, in, 16);
	aes_add_roundkey(s, 10, rk);
	for (int r = 9; r >= 1; r--) { aes_inv_shiftrows(s); aes_inv_subbytes(s); aes_add_roundkey(s, r, rk); aes_inv_mixcolumns(s); }
	aes_inv_shiftrows(s); aes_inv_subbytes(s); aes_add_roundkey(s, 0, rk);
	memcpy(out, s, 16);
}

/* FIPS-197 向量自测：key=00..0f, pt=0011..ff → ct=69c4..c55a。启动时验证自写 AES 加解密正确。 */
static void aes128_selftest(void)
{
#if OPENP2P_DIAG_ON                                                                  	/* 纯观测（行为监听）：仅取证编译时在场；开=跑 FIPS-197 向量并打印 */
	uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf};
	uint8_t pt[16]  = {0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	uint8_t ct_exp[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
	uint8_t ct[16], rt[16];
	aes_init_tables();
	aes_block_enc(pt, ct, key);
	int enc_ok = (memcmp(ct, ct_exp, 16) == 0);
	aes_block_dec(ct_exp, rt, key);
	int dec_ok = (memcmp(rt, pt, 16) == 0);
	ESP_LOGI(TAG, "AES128 selftest: enc=%s dec=%s", enc_ok ? "OK" : "FAIL", dec_ok ? "OK" : "FAIL");
#endif
}

/* AES-128-CBC + PKCS7（逐字节对齐 Go common.go encryptBytes/decryptBytes）。
 * key16=[app.key LE64]x2，IV 固定 "UHNJUSBACIJFYSQN"。PKCS7：padLen=16-inlen%16，末 padLen 字节填 padLen。
 * out 缓冲：加密需 inlen+16；解密需 inlen。返回 0 成功，*outlen=真实长度。 */
static int app_cipher(p2p_app_t *a, const uint8_t *in, size_t inlen, int enc, uint8_t *out, size_t *outlen)
{
	if (a->app_key == 0) { memcpy(out, in, inlen); *outlen = inlen; return 0; }
	aes_init_tables();
	uint8_t key16[16];
	for (int i = 0; i < 8; i++) { key16[i] = key16[8 + i] = (uint8_t)(a->app_key >> (8 * i)); }
	static const uint8_t iv[17] = "UHNJUSBACIJFYSQN";	/* 16 字节 IV（末位 NUL 不取用，memcpy 只拷 16） */

	if (enc) {
		size_t pad = (size_t)(16 - (inlen % 16));	/* 1..16（inlen%16==0 补整块，对齐 Go） */
		size_t nblocks = (inlen + pad) / 16;
		uint8_t prev[16];
		memcpy(prev, iv, 16);
		for (size_t b = 0; b < nblocks; b++) {
			uint8_t blk[16], cblk[16];
			size_t off = b * 16;
			if (b == nblocks - 1) {	/* 最后一块：剩余明文 + PKCS7 填充 */
				size_t remain = inlen - off;	/* 0..15 */
				memcpy(blk, in + off, remain);
				memset(blk + remain, (int)pad, (size_t)(16 - remain));
			} else {
				memcpy(blk, in + off, 16);
			}
			for (int i = 0; i < 16; i++) blk[i] ^= prev[i];
			aes_block_enc(blk, cblk, key16);
			memcpy(out + off, cblk, 16);
			memcpy(prev, cblk, 16);
		}
		*outlen = nblocks * 16;
	} else {
		if (inlen % 16 != 0) return -1;
		size_t nblocks = inlen / 16;
		uint8_t prev[16];
		memcpy(prev, iv, 16);
		for (size_t b = 0; b < nblocks; b++) {
			uint8_t cblk[16], blk[16];
			memcpy(cblk, in + b * 16, 16);
			aes_block_dec(cblk, blk, key16);
			for (int i = 0; i < 16; i++) blk[i] ^= prev[i];
			memcpy(out + b * 16, blk, 16);
			memcpy(prev, cblk, 16);
		}
		int pad = out[inlen - 1];
		if (pad <= 0 || pad > 16) return -1;
		for (int i = 0; i < pad; i++) { if (out[inlen - 1 - i] != (uint8_t)pad) return -1; }
		*outlen = inlen - (size_t)pad;
	}
	return 0;
}

/* KB 大包足发（lwIP 阻塞 send 对 KB 级帧可返回部分长度，旧"单次 send、w!=n 即败"使
* 上行 KB 包当场拆会话、下行 send(cfd) 单次漏残字节致 TCP 流损坏——mstsc 过 NLA 后停在
* "准备远程桌面"再断开，正是 Client Active 2-4KB 首踩 KB 级流量；Go overlay.go:54 对端明文上限
* ReadBuffLen=4096+16，KB 级双向都走这里）。 */
static esp_err_t send_all(int fd, const uint8_t *buf, size_t n)
{
	size_t sent = 0;
	while (sent < n) {
		ssize_t w = send(fd, buf + sent, n - sent, 0);
		if (w > 0) { sent += (size_t)w; continue; }
		if (w < 0 && errno == EINTR) continue;
		return ESP_FAIL;
	}
	return ESP_OK;
}

/* underlay TCP 帧收发（MsgP2P 数据面，区别于 WSS 的 op2p_send/op2p_recv）。全程小端。 */
static esp_err_t ul_send(p2p_app_t *a, uint16_t mt, uint16_t st, const uint8_t *body, size_t blen)
{
	size_t n = OPENP2P_HEADER_SIZE + blen;
	uint8_t *buf = malloc(n);
	if (!buf) return ESP_ERR_NO_MEM;
	uint32_t dl = (uint32_t)blen;
	buf[0] = dl & 0xFF; buf[1] = (dl >> 8) & 0xFF; buf[2] = (dl >> 16) & 0xFF; buf[3] = (dl >> 24) & 0xFF;
	buf[4] = mt & 0xFF; buf[5] = (mt >> 8) & 0xFF; buf[6] = st & 0xFF; buf[7] = (st >> 8) & 0xFF;
	if (blen) memcpy(buf + OPENP2P_HEADER_SIZE, body, blen);
	if (a->qconn) { int rq = quic_stream_write((quic_conn_t *)a->qconn, buf, (int)n); free(buf); return rq == 0 ? ESP_OK : ESP_FAIL; }    /* QUIC 隧道：stream0 即可靠字节流，等价 TCP socket */
	if (a->txmtx) xSemaphoreTake(a->txmtx, portMAX_DELAY);           /* 11434 多会话并发：同隧道多会话 pup/mux14 的帧互斥入线，防交织 */
	int r = send_all(a->relay_fd, buf, n);
	if (a->txmtx) xSemaphoreGive(a->txmtx);
	free(buf);
	return r;
}

/* relay 模式发：外层 MsgRelayData(10) + [rtid] + 内层{mt,st} + body（对齐 WriteBytes:970）。 */
static esp_err_t ul_send_relay(p2p_app_t *a, uint16_t mt, uint16_t st, const uint8_t *body, size_t blen)
{
	size_t all = 8 + OPENP2P_HEADER_SIZE + blen;   /* rtid(8) + inner头(8) + body */
	size_t n = OPENP2P_HEADER_SIZE + all;
	uint8_t *buf = malloc(n);
	if (!buf) return ESP_ERR_NO_MEM;
	uint32_t dl = (uint32_t)all;
	buf[0] = dl & 0xFF; buf[1] = (dl >> 8) & 0xFF; buf[2] = (dl >> 16) & 0xFF; buf[3] = (dl >> 24) & 0xFF;
	buf[4] = MSG_P2P & 0xFF; buf[5] = 0; buf[6] = MSG_RELAY_DATA & 0xFF; buf[7] = 0;
	size_t p = OPENP2P_HEADER_SIZE;
	for (int i = 0; i < 8; i++) buf[p++] = (uint8_t)(a->rtid >> (8 * i));      /* rtid */
	uint32_t idl = (uint32_t)blen;                                              /* inner 头 */
	buf[p++] = idl & 0xFF; buf[p++] = (idl >> 8) & 0xFF; buf[p++] = (idl >> 16) & 0xFF; buf[p++] = (idl >> 24) & 0xFF;
	buf[p++] = mt & 0xFF; buf[p++] = (mt >> 8) & 0xFF; buf[p++] = st & 0xFF; buf[p++] = (st >> 8) & 0xFF;
	if (blen) memcpy(buf + p, body, blen);
	if (a->qconn) { int rq = quic_stream_write((quic_conn_t *)a->qconn, buf, (int)n); free(buf); return rq == 0 ? ESP_OK : ESP_FAIL; }    /* relay 外层裹好后同走 QUIC（WriteBytes:970 relay 分支） */
	if (a->txmtx) xSemaphoreTake(a->txmtx, portMAX_DELAY);           /* 11434 多会话并发：同隧道多会话 pup/mux14 的帧互斥入线，防交织 */
	int r = send_all(a->relay_fd, buf, n);
	if (a->txmtx) xSemaphoreGive(a->txmtx);
	free(buf);
	return r;
}

/* 收一帧（带 SO_RCVTIMEO 超时）。body 缓冲须 ≥ 帧长，否则返回 INVALID_SIZE。 */
static esp_err_t ul_recv(p2p_app_t *a, uint16_t *mt, uint16_t *st, uint8_t *body, size_t body_sz, int timeout_ms)
{
	/* 原此二行每帧私改共享 relay_fd 的 SO_RCVTIMEO（Go 无对位：读者自设 deadline p2ptunnel.go:601）——窗口已改 recv_n_to 自管 */
	uint8_t h[8];
	if ((a->qconn ? quic_stream_read((quic_conn_t *)a->qconn, h, 8, timeout_ms) : recv_n_to(a->relay_fd, h, 8, timeout_ms)) != 8) return ESP_ERR_TIMEOUT;
	uint32_t dl; uint16_t m, s;
	memcpy(&dl, h, 4); memcpy(&m, h + 4, 2); memcpy(&s, h + 6, 2);
	if (m == MSG_P2P && s == MSG_RELAY_DATA) {                  /* relay 外层 [4/10][rtid8B][内层8B头]：剥出内层帧再交给调用方（对端数据/心跳 ack 都裹这层，p2ptunnel.go:677-683 的 relay server 行为） */
		uint8_t pre[16];                                         /* rtid 已由 relay server 配对，无需校验值 */
		if ((a->qconn ? quic_stream_read((quic_conn_t *)a->qconn, pre, 16, timeout_ms) : recv_n_to(a->relay_fd, pre, 16, timeout_ms)) != 16) return ESP_ERR_TIMEOUT;
		memcpy(&dl, pre + 8, 4); memcpy(&m, pre + 12, 2); memcpy(&s, pre + 14, 2);
		}
	if (dl > body_sz) return ESP_ERR_INVALID_SIZE;
	if (dl && (a->qconn ? quic_stream_read((quic_conn_t *)a->qconn, body, (int)dl, timeout_ms) : recv_n_to(a->relay_fd, body, (int)dl, timeout_ms)) != (int)dl) return ESP_ERR_TIMEOUT;
	*mt = m; *st = s;
	return ESP_OK;
}

static void ul_tunnel_hb(p2p_app_t *a)
{
	uint64_t nid = node_name_to_id(OPENP2P_NODE);
	uint8_t b[8];
	for (int i = 0; i < 8; i++) b[i] = (uint8_t)(nid >> (8 * i));
	ul_send(a, MSG_P2P, MSG_TUNNEL_HEARTBEAT, b, 8);
}
static void ul_tunnel_hb_ack(p2p_app_t *a)
{
	uint64_t nid = node_name_to_id(OPENP2P_NODE);
	uint8_t b[8];
	for (int i = 0; i < 8; i++) b[i] = (uint8_t)(nid >> (8 * i));
	ul_send(a, MSG_P2P, MSG_TUNNEL_HEARTBEAT_ACK, b, 8);
}

/* relay 隧道保活（对齐 relayHeartbeatLoop p2papp.go:696-718）：[4/10][rtid][4/11][RelayHeartbeat]。
  * relay server 靠它刷 app hbTime；Go 侧 TunnelHeartbeatTime=10s 一发、*2=20s 无则判死拆对，
  * 所以 accept 空转期也必须发（见 app_listen_task），否则用户首次连接必踩死隧道。 */
static void ul_relay_hb(p2p_app_t *a)
{
	char j[160];
	int jl = snprintf(j, sizeof(j),
				"{\"from\":\"%s\",\"relayTunnelID\":%llu,\"relayTunnelID2\":%llu,\"appID\":%llu}",
			OPENP2P_NODE, (unsigned long long)a->tunnel_id,
			(unsigned long long)a->rtid, (unsigned long long)a->app_id);
	ul_send_relay(a, MSG_P2P, MSG_RELAY_HEARTBEAT, (const uint8_t *)j, (size_t)jl);
}

/* QUIC/TCP 统一精确读 need 字节：QUIC 先尽 stream0 rxbuf 缓存，再收 UDP 解密补（pump/排空共用）。 */
static int ul_readn(p2p_app_t *a, uint8_t *d, int need)
{
	return a->qconn ? quic_stream_read((quic_conn_t *)a->qconn, d, need, 3000) : recv_n_to(a->relay_fd, d, need, 20000);   /* 读窗自管 20s=Go readLoop :601 SetReadDeadline(TunnelHeartbeatTime*2) 同值，不再被共享选项私改 */
}

/* 四路映射表：ESP32 本地端口 → 对端 OverlayConnectReq 后代拨的目标 IP（经网页配置）。
   目标 IP 由用户经网页填；可为 SD-WAN 网内地址（对端经 tun0 可达）或站点 LAN 地址。
   ESP32 从不直连此表地址——只经 OverlayConnectReq 交对端 dial，数据全走已打通的 underlay 隧道。 */
static const char *app_dstip_for(uint16_t local_port)
{
	switch (local_port) {
	case 22:    return g_cfg.dst22[0] ? g_cfg.dst22 : OPENP2P_APP_DSTIP;                                          /* SD-WAN 网内节点 SSH */
	case 3389:  return g_cfg.dst3389[0] ? g_cfg.dst3389 : OPENP2P_APP_DSTIP;                                      /* 站点 LAN 上 PC 的 Windows RDP */
	case 8080:  return g_cfg.dst8080[0] ? g_cfg.dst8080 : OPENP2P_APP_DSTIP;                                           /* 站点 LAN 节点 HTTP（原 8000 改口） */
	case 11434: return g_cfg.dst11434[0] ? g_cfg.dst11434 : OPENP2P_APP_DSTIP;                                      /* 站点 LAN 上 ollama */
	default:   return OPENP2P_APP_DSTIP;                                    /* 兜底 OPENP2P_APP_DSTIP */
	}
}

/* OverlayConnectReq(MT=4 ST=6)：body=JSON，经 relay 发（对齐 p2papp.go:554-565）。 */
static esp_err_t overlay_connect_req(p2p_app_t *a, uint64_t ovid)
{
	char json[256];
	int jlen = snprintf(json, sizeof(json),
			"{\"id\":%llu,\"token\":%s,\"dstIP\":\"%s\",\"dstPort\":%d,\"protocol\":\"tcp\","
			"\"relayTunnelID\":%llu,\"appID\":%llu}",
			(unsigned long long)ovid, g_cfg.token, app_dstip_for(a->srcport), (int)a->dstport,
			(unsigned long long)(a->direct ? 0 : a->rtid), (unsigned long long)a->app_id);     /* Go p2papp.go:561：tidx==0 不带 relayTunnelID（omitempty→对端解 0）；relay 场景=t.id=AddRelayTunnelRsp 的 rtid——原错填 control-plane tunnel_id 使对端按 relay 请求误处理（EOF 真凶） */
	return (a->direct ? ul_send : ul_send_relay)(a, MSG_P2P, MSG_OVERLAY_CONNECT_REQ, (const uint8_t *)json, (size_t)jlen);
}

/* 会话注销（Go overlay.go:85-86：oConn.run 退出无条件 notify peer disconnect{"id":ovId} → 对端 readLoop
* p2ptunnel.go:733-745 overlayConns.Load(ovId)->oConn.Close() 关 RDP/本地服务 socket）。我方此件
* 全缺：mstsc 断开后对端 Windows 会话僵尸（TermService 持续向死 ovid 灌 [4/9] 位图，串口实锤"overlay id
* 不匹配 e121..."），并发数触顶后新 mstsc 会话过首帧即被踢——"还断/会话已结束"真凶。发不出即隧道已死，忽略。 */
static esp_err_t overlay_disconnect_req(p2p_app_t *a, uint64_t ovid)
{
	char json[48];
	int jlen = snprintf(json, sizeof(json), "{\"id\":%llu}", (unsigned long long)ovid);
	return (a->direct ? ul_send : ul_send_relay)(a, MSG_P2P, MSG_OVERLAY_DISCONNECT_REQ, (const uint8_t *)json, (size_t)jlen);
}

/* 处理单个本地连接：建 overlay 会话 + 双向泵；任一侧 EOF 即返回。
* 架构定罪：Go 上行（本地服务→隧道）是 oConn.run 独立 goroutine（overlay.go:50-87），下行（隧道→本地
* 服务）在隧道 readLoop goroutine（p2ptunnel.go:597-668）——两向独立互不等待。旧泵单循环把两向串行：首帧位图
* 流把下行 send_all(cfd) 堵死（WiFi 空口+TCP_WND 5760B）时 mstsc 上行没人读 → RDP 协议层超时 →
* "首帧出来后一会儿断开"。对齐 Go 双 goroutine：上行=专任务 pump_up_task，下行=handle_session 内联循环。 */
typedef struct {
	int cfd;                                                    /* 本地客户端（mstsc/ssh/ollama client） */
	p2p_app_t *a;
	uint64_t ovid;                                              /* 本会话 overlay id */
	volatile int dead;                                          /* 任一方向出错/退出即置位，另一方检查后自退 */
	volatile int done;                                          /* 上行任务退出前置位；下行等它之后再关 cfd，防碰已关 fd */
} pump_ctx_t;

/* 上行泵（本地→隧道）：独立任务，下行再堵也照流——Go oConn.run goroutine 语义。 */
static uint8_t *s14_buf_alloc(size_t n)					/* multi 路会话大缓冲 PSRAM 优先（QFN56 内嵌 8MB quad PSRAM，eFuse=quad 实锤），失败回退内部 RAM；单会话路（3389/22/8000）零影响 */
{
	uint8_t *p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM);
	if (!p) p = malloc(n);
	return p;
}
static void pump_up_task(void *arg)
{
	pump_ctx_t *cx = (pump_ctx_t *)arg;
	p2p_app_t *a = cx->a;
	struct timeval rto; rto.tv_sec = 1; rto.tv_usec = 0;
	setsockopt(cx->cfd, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto));      /* 1s 醒来查 dead：下行先退这边也不致死等 */
	uint8_t *lbuf = a->multi ? s14_buf_alloc(4200) : malloc(4200), *ciph = a->multi ? s14_buf_alloc(4224) : malloc(4224);	/* multi 路 PSRAM 优先；3389/22/8000 单会话路原样 */
	if (!lbuf || !ciph) { cx->dead = 1; cx->done = 1; free(lbuf); free(ciph); vTaskDelete(NULL); }
	int nfail = 0;
	for (;;) {
		if (cx->dead) break;                                    /* 下行已退，会话作罢 */
		int n = recv(cx->cfd, lbuf, 4096, 0);      /* 4096=Go ReadBuffLen 安全顶（对端 decryptBytes 无界检查，明文>4096=对端 openp2p 整进程 panic） */
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT)) continue;      /* RCVTIMEO 周期醒 */
		if (n <= 0) break;                                      /* 本地客户端 EOF/RST */
		size_t clen;
		if (app_cipher(a, lbuf, (size_t)n, 1, ciph, &clen) != 0) { ESP_LOGE(TAG, "[port %d] 上行 AES 加密失败", a->srcport); break; }
		uint8_t *data = malloc(8 + clen);
		if (!data) break;
		for (int k = 0; k < 8; k++) data[k] = (uint8_t)(cx->ovid >> (8 * k));
		memcpy(data + 8, ciph, clen);
		esp_err_t sr = (a->direct ? ul_send(a, MSG_P2P, MSG_OVERLAY_DATA, data, 8 + clen) : ul_send_relay(a, MSG_P2P, MSG_OVERLAY_DATA, data, 8 + clen));
		free(data);
		if (sr != ESP_OK) { if (++nfail == 1 || nfail % 30 == 0) ESP_LOGW(TAG, "[port %d] 上行连续%d帧投递失败丢弃续泵（Go overlay.go:75 WriteBytes 连返回值都不看=隧道死时数据丢弃、本地连接保持 ESTAB、重建后原 ovid 续传；判死归 mux14 心跳/rx-silence 20s 钟，上行不再连坐踹会话与隧道）", a->srcport, nfail); continue; }
		if (nfail) nfail = 0;
	}
	cx->dead = 1;
	cx->done = 1;
	free(lbuf); free(ciph);
	vTaskDelete(NULL);
}

/* 会话独占标志：handle_session 进函数置 1、全退出路径清 0——thb 的 idle drain 见 1 即避让，relay_fd recv 单读者。 */
	extern volatile int s_busy[OPENP2P_APP_NUM];                 /* 定义在下方 thb 区（同文件内 extern 前向引用同对象） */

static void handle_session(int cfd, p2p_app_t *a)
{
	struct timeval sto; sto.tv_sec = 15; sto.tv_usec = 0;                                     /* SNDTIMEO 前移 */
	setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &sto, sizeof(sto));                     /* 下行泵 send_all(cfd) 有界：本地客户端半开/不读响应时会话自毁而非永卡 fwd */
	if (a->relay_fd >= 0) { setsockopt(a->relay_fd, SOL_SOCKET, SO_SNDTIMEO, &sto, sizeof(sto)); }     /* 上行/pup/入口 OverlayConnectReq 的 send 全部有界：对端 readLoop 卡 write(目标服务)/sndbuf 满时 15s 内会话自毁，fwd 必回 accept——堵死"SYN 静默丢+request timeout+服务端没看到请求"最后一窗 */
	int nodelay = 1;
	setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));                                /* 双侧关 Nagle：mstsc 按键/HTTP 小包的"响应慢半拍"元凶 */
	if (a->relay_fd >= 0) { setsockopt(a->relay_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)); }	uint64_t ovid = rand64();
	if (overlay_connect_req(a, ovid) != ESP_OK) { ESP_LOGE(TAG, "[port %d] OverlayConnectReq 发送失败", a->srcport); return; }
	ESP_LOGI(TAG, "[port %d] OverlayConnectReq 已发 ovid=%llu，等 OverlayConnectRsp", a->srcport, (unsigned long long)ovid);

	int sidx = (int)(a - g_apps);
	s_busy[sidx] = 1;                                                      /* 从要碰 relay_fd recv 起 thb drain 禁入（防串帧）；本函数所有出口清 0 */
	fcntl(a->relay_fd, F_SETFL, 0);											/* 清非阻塞（）：s2c 命中 fd 继承 O_NONBLOCK，lwIP recv 即返 EAGAIN 无视 SO_RCVTIMEO——清除后 1s 窗真等（Go 原生 conn 阻塞+deadline 语义） */
	int rsp_ok = 0;
	for (int i = 0; i < 10 && !rsp_ok; i++) {
		uint16_t mt = 0, st = 0; uint8_t body[192] = {0};             /* OverlayConnectRsp 是 JSON，剥 [4/10] 外层后内层直落此缓冲 */
		esp_err_t rr7 = ul_recv(a, &mt, &st, body, sizeof(body), 1000);
		if (rr7 != ESP_OK) { ESP_LOGI(TAG, "[port %d] 建连第 %d 轮无帧 err=0x%x（继续满窗等）", a->srcport, i, (unsigned)rr7); continue; }				/* 对端 Go 回 [4/7] 前要先 LookupIP+DialTimeout 目标服务(p2ptunnel.go:763-798)，>1s 即被首轮超时放弃整窗 */
		if (mt == MSG_P2P && st == MSG_TUNNEL_HEARTBEAT) ul_tunnel_hb_ack(a);
		else if (mt == MSG_P2P && st == MSG_OVERLAY_CONNECT_RSP) { rsp_ok = 1; ESP_LOGI(TAG, "[port %d] >>> OverlayConnectRsp 收到=对端 dial 目标服务成功实锤，进入双向泵", a->srcport); }
		else { char hx[65] = {0}; for (int k = 0; k < 24; k++) snprintf(hx + 2 * k, 3, "%02x", body[k]); ESP_LOGI(TAG, "[port %d] 建连期跳过 MT=%u ST=%u hex=%s", a->srcport, mt, st, hx); }
	}
	if (!rsp_ok) ESP_LOGW(TAG, "[port %d] OverlayConnectRsp 未收到（Go p2papp.go:566：head==nil 仅 gLog.w 仍 go oConn.run()——照泵，不终止会话）", a->srcport);

	struct timeval rto; rto.tv_sec = 10; rto.tv_usec = 0;
	if (a->relay_fd >= 0) { setsockopt(a->relay_fd, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto)); }
	pump_ctx_t cx; cx.cfd = cfd; cx.a = a; cx.ovid = ovid; cx.dead = 0; cx.done = 0;      /* 栈上 ctx：handle_session 末尾等 cx.done 才返回，任务引用期间恒存活 */
	if (xTaskCreate(pump_up_task, "pup", 8192, &cx, 5, NULL) != pdPASS) { ESP_LOGE(TAG, "[port %d] 上行泵任务创建失败", a->srcport); s_busy[sidx] = 0; return; }
	uint8_t *plain = malloc(4200);
	if (!plain) { cx.dead = 1; while (!cx.done) vTaskDelay(1); free(plain); s_busy[sidx] = 0; return; }
	int wfd = a->qconn ? quic_udp_fd((quic_conn_t *)a->qconn) : a->relay_fd;     /* 下行只读隧道侧（上行 cfd recv 已交 pup 独立任务，本循环不再碰 cfd） */
	for (;;) {
		if (cx.dead) break;                                     /* 上行任务已退（本地客户端断连） */
		int qr = a->qconn ? quic_rx_ready((quic_conn_t *)a->qconn) : 0;     /* QUIC 缓存期免 select 干等 UDP */
		fd_set rset; FD_ZERO(&rset);
		FD_SET(wfd, &rset);
		struct timeval tv; tv.tv_sec = (qr > 0) ? 0 : 5; tv.tv_usec = 0;
		int sel = select(wfd + 1, &rset, NULL, NULL, &tv);
		if (sel == 0) { if (qr > 0) { vTaskDelay(1); } continue; }
		if (sel < 0) { if (errno == EINTR) continue; break; }
		if (!a->ready) { ESP_LOGW(TAG, "[port %d] session kicked for tunnel rebuild (; Go delTunnel closes oConns)", a->srcport); break; }
		if (qr > 0 || FD_ISSET(wfd, &rset)) {
			uint8_t h[8];
			if (ul_readn(a, h, 8) != 8) { a->tun_dead = 1; break; }
			uint32_t dl; uint16_t mt, st;
			memcpy(&dl, h, 4); memcpy(&mt, h + 4, 2); memcpy(&st, h + 6, 2);
			if (mt == MSG_P2P && st == MSG_RELAY_DATA) {           /* relay 外层 [4/10][rtid][内层头]：剥后按内层 dl 收 body */
				uint8_t pre[16];
				if (ul_readn(a, pre, 16) != 16) { a->tun_dead = 1; break; }
				memcpy(&dl, pre + 8, 4); memcpy(&mt, pre + 12, 2); memcpy(&st, pre + 14, 2);
			}
			uint8_t *body = malloc((dl > 1) ? dl : 1);
			if (dl && ul_readn(a, body, (int)dl) != (int)dl) { free(body); a->tun_dead = 1; break; }
			if (mt == MSG_P2P && st == MSG_OVERLAY_DATA) {
				if (dl >= 8) {
					uint64_t rid; memcpy(&rid, body, 8);
					if (rid == ovid) {
						size_t plen;
						if ((dl - 8) > 0 && app_cipher(a, body + 8, dl - 8, 0, plain, &plen) == 0) {
							if (send_all(cfd, plain, plen) != ESP_OK) { free(body); break; }    /* 下行堵（WiFi 空口/mstsc 5760B 窗）不再拖上行：pup 独立任务照读 mstsc 输入 */
						}
					} else {
						ESP_LOGI(TAG, "overlay id 不匹配 %llx vs %llx", (unsigned long long)rid, (unsigned long long)ovid);
					}
				}
			} else if (mt == MSG_P2P && st == MSG_TUNNEL_HEARTBEAT) {
				ul_tunnel_hb_ack(a);
			} else if (mt == MSG_P2P && st == MSG_OVERLAY_DISCONNECT_REQ) {    /* body 是 JSON {"id":...}：仅 rid==本会话 ovid 才收摊（Go p2ptunnel.go:733-745 Load 查无即忽略，实锤残帧真实存在） */
					char jb[72] = {0}; memcpy(jb, body, (dl < 64) ? dl : 63);
					long long idv = 0;
					if (jget_int(jb, "id", &idv) == 0 && (uint64_t)idv == ovid) { ESP_LOGI(TAG, "[port %d] 收到 OverlayDisconnectReq，结束会话", a->srcport); free(body); break; }
					ESP_LOGI(TAG, "[port %d] DisconnectReq rid 不匹配/非json（残帧），忽略", a->srcport);
			} else {
				ESP_LOGI(TAG, "[port %d] underlay 其它 MT=%u ST=%u", a->srcport, mt, st);
			}
			free(body);
			}
	}
	cx.dead = 1;                                                  /* 通知上行任务收工 */
	while (!cx.done) { vTaskDelay(1); }                           /* 等上行退出再返回（cfd 由调用方 close） */
	free(plain);
	overlay_disconnect_req(a, ovid);                                       /* Go 语义无条件注销（对端查无此 ovid 即忽略，无害），断 mstsc/泵 EOF/收到对端 Disconnect 全部走此出口——断会话不留僵尸 */
	s_busy[sidx] = 0;
}

/* 独立隧道心跳 + idle 排空（双定罪）。泵被 mstsc 首帧位图流堵死，同回界心跳饿死>20s →
* 对端 readLoop TunnelHeartbeatTime*2=20s deadline 拆隧道。反例：thb 全接管+listen idle 不读 relay_fd 后，
* idle 期入帧（对端 writeLoop 的 [4/4]/ack）无人读→接收窗被吃→对端 DefaultWriteBytes 流控阻塞→我方任一
* 阻塞 send 挂死 thb 单任务→四 port 心跳齐停，现场=建链 40s 后 idle 113s 隧道被对端拆光（req 发送失败×4）。
* Go 对位：writeLoop 独立 goroutine 与数据 goroutine 互不等待（p2ptunnel.go:801）；idle 期收包是 readLoop 常驻
* 职责——两者这里都由本任务代打：1s tick 巡四 port，心跳帧 MSG_DONTWAIT 单发（发不出即失败打日志，绝不挂死），
* 无会话期按帧非阻塞排空 relay_fd 保接收窗。 */
volatile int s_busy[OPENP2P_APP_NUM];                   /* handle_session 在跑=1：泵独占 relay_fd 双向，thb 勿碰 recv（防串帧） */

/* ---------- 11434 多会话并发（mux14=Go 隧道 readLoop 按 overlay id 分发到各 oConn 的对位） ----------
* 旧路径每端口一次只服务一个本地连接（会话不结束不回 accept）+ backlog(2) → 第 4 路 SYN 静默丢。
* 新路径：mux14 独占隧道下行（唯一读者，兼管 idle 排空与 的 10s DONTWAIT 心跳），把 [4/9]
* 按 [LE64 rid] 分流进该会话下行队列；每本地连接 = sess14(下行解密写 cfd)+pup(上行) 独立任务对。
* 并发 ≤S14_MAX_SESS 路共享一条隧道；txmtx 使多任务帧整帧原子。thb 对 multi 口整体避让。 */
static esp_err_t tunnel_hb_send_nb(p2p_app_t *a);                   /* 心跳发败恒不判死——Go checkActive(p2ptunnel.go:150-164)对 WriteBytes 返回值完全忽略、只看 ack(hbTime)推进；Go writeHb(809-818) err->close 是其单协程串行 writeLoop(821-842) 的副作用：Go 发心跳瞬间无业务帧并发写同一 conn（同 select 互斥+writeFull common.go:395 循环写尽才返回），sndbuf 满5s 只能=链路真死。C 形 mux14 心跳与 pup 上行泵(:1935)两任务并发写同一 relay_fd，mstsc 上行/多口 burst 下 sndbuf 满是常态（serial100z_mstsc2 实锤：登录8.4s 后 hb send errno=119 一票死+同秒上行帧 send 同败+空闲85min 44拍无恙）=拥塞瞬态非链路死，一票杀=误杀连坐四口。真死判归 recv 侧三道兜底：ul_readn 半帧/EOF(:2189/2194/2201)+rx-silence 20s(:2170, Go :601 readLoop SetReadDeadline(TunnelHeartbeatTime*2) 对位)+select 败(:2185)，心跳不抢判。仅 EINTR 续（Go syscall 自动重启语义）。 */

typedef struct { uint32_t dl; uint8_t *body; } s14_frame_t;            /* [LE64 ovid][AES 密文] 整帧，mux→sess 传指针（sess 释放） */

static void s14_free_frames(s14_sess_t *s)                             /* 排干槽队列，防脏帧流入下一会话 */
{
	void *fr;
	while (s->rq && xQueueReceive(s->rq, &fr, 0) == pdTRUE) { s14_frame_t *f = (s14_frame_t *)fr; free(f->body); free(f); }     /* rq NULL 守卫——cap<S14_MAX_SESS 的槽(22 之 4-7)从未建队列，rebuild@2213 全槽排干勿 assert */
}

static void s14_gone_all(p2p_app_t *a, const char *why)                /* 拆隧日志点（撤销踹人：Go t.close(p2ptunnel.go:171-182) 不碰 overlayConns，oConn.run(overlay.go:60-75) 泵失败连返回值都不看=丢弃保连接，重建后原 ovid 直接续传） */
{
	int live = 0;
	for (int i = 0; i < a->s14_cap; i++) if (a->s14[i].used) live++;
	time_t gn = time(NULL);	/* dead tunnel = recv returns 0 forever-ready; hot loop must throttle its E log (storm: 27 lines/s x 6562) */
	if (!live && gn - a->gone_rep < 10) return;
	a->gone_rep = gn;
	ESP_LOGE(TAG, "[port %d] mux14 %s——拆隧交重建，%d 个在场会话保持占槽续泵(Go overlay.go:60-75 无隧道丢数据不关连接)", a->srcport, why, live);
}

static void sess14_task(void *arg)
{
	struct s14_conn_arg *ca = (struct s14_conn_arg *)arg;
	p2p_app_t *a = ca->a;
	int cfd = ca->cfd;
	s14_sess_t *s = &a->s14[ca->slot];
	int one = 1;
	struct timeval sto; sto.tv_sec = 15; sto.tv_usec = 0;
	setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &sto, sizeof(sto));                     /* 下行 send_all 有界（语义：本地客户端半开→会话自毁不永卡） */
	setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));                    /* 关 Nagle：小包不等 ACK */
	uint64_t ovid = s->ovid;                                                       	/* fwd 抢槽时已原子预赋（防上一会话残帧误杀本会话）；used 已抢置，本函数全出口清 0 */
	ESP_LOGI(TAG, "[port %d] sess14 会话开始 slot=%d ovid=%llu", a->srcport, ca->slot, (unsigned long long)ovid);
	pump_ctx_t cx; cx.cfd = cfd; cx.a = a; cx.ovid = ovid; cx.dead = 0; cx.done = 0;/* 栈 ctx：sess 等 done 后再动 cfd，同 双任务语义 */
	if (overlay_connect_req(a, ovid) != ESP_OK) ESP_LOGE(TAG, "[port %d] sess14 OverlayConnectReq 发送失败（隧道死）", a->srcport);
	for (int w = 0; w < 300 && !s->rsp_ok; w++) vTaskDelay(pdMS_TO_TICKS(10));    /* tick=100Hz——原 vTaskDelay(10) 实为 100ms×300=30s（Go 3s 被放大10倍，30.0s/31.0s），pdMS 归位 3s */      /* 对齐 Go p2papp.go:566 ReadMessage(ConnectRsp,3s)——mux14 收 [4/7] 置 rsp_ok；旧版不等还把对端 ST=7(dl=12) 当"其它"丢，dial 生死不可见 */
	if (!s->rsp_ok) {                                                   /* 对端唯一完全静默失败=memapp 注册竞态丢（handlepush.go:79-84）→ p2ptunnel.go:768-771 apps.Load 吞 [4/6] 不 dial 不回包，死到复位；Go 官方 app 在对端 DB 不吃此竞态，esp32 靠一次性 push */
		ESP_LOGW(TAG, "[port %d] sess14 OverlayConnectRsp no response for 3 sec (suspect peer memapp reg lost, repush SSM+APPKey and re-send [4/6])", a->srcport);
		char ssm[256], ak[96];                                          /* 重推幂等: handlepush.go:92-100 apps.Load 命中即复用 */
		if (a->direct) snprintf(ssm, sizeof(ssm), "{\"from\":\"%s\",\"node\":\"%s\",\"tunnelID\":%llu,\"relayTunnelID\":0,\"relayMode\":\"%s\",\"appID\":%llu,\"appKey\":%llu,\"relayIndex\":0,\"tunnelNum\":2,\"srcPort\":%u}", OPENP2P_NODE, a->relay_name, (unsigned long long)a->tunnel_id, a->relay_mode, (unsigned long long)a->app_id, (unsigned long long)a->app_key, (unsigned)a->srcport);
		else snprintf(ssm, sizeof(ssm), "{\"from\":\"%s\",\"node\":\"%s\",\"tunnelID\":%llu,\"relayTunnelID\":%llu,\"relayMode\":\"%s\",\"appID\":%llu,\"appKey\":%llu,\"relayIndex\":1,\"tunnelNum\":2,\"srcPort\":%u}", OPENP2P_NODE, a->relay_name, (unsigned long long)a->rtid, (unsigned long long)a->tunnel_id, a->relay_mode, (unsigned long long)a->app_id, (unsigned long long)a->app_key, (unsigned)a->srcport);
		snprintf(ak, sizeof(ak), "{\"appID\":%llu,\"appKey\":%llu}", (unsigned long long)a->app_id, (unsigned long long)a->app_key);
		ESP_LOGI(TAG, "sess14 repush SSM: %s", ssm);                    /* 自测探针：串口实锤重推 SSM 内容（tunnelNum:2=不再触对端 :96 DeleteApp 雷，走 :102 幂等 update） */
		op2p_push(g_peer_name, MSG_PUSH_SERVER_SIDE_SAVE_MEMAPP, ssm);
		op2p_push(g_peer_name, MSG_PUSH_APP_KEY, ak);
		vTaskDelay(pdMS_TO_TICKS(1000));                                /* 重推走控制面 WSS 服务器转发，等 1s 就位再重发 [4/6] */
		if (overlay_connect_req(a, ovid) != ESP_OK) ESP_LOGE(TAG, "[port %d] sess14 OverlayConnectReq resend failed (tunnel dead)", a->srcport);
		for (int w = 0; w < 300 && !s->rsp_ok; w++) vTaskDelay(pdMS_TO_TICKS(10));    /* tick=100Hz——原 vTaskDelay(10) 实为 100ms×300=30s（Go 3s 被放大10倍，30.0s/31.0s），pdMS 归位 3s */
		if (!s->rsp_ok) ESP_LOGW(TAG, "[port %d] sess14 still no ConnectRsp after repush (peer dial slow/target dead; run pump anyway per Go p2papp.go:566 head==nil)", a->srcport);       /* 撤 Rsp 判死——Go 从不因 Rsp 失踪杀隧道（并发浏览器任一慢 Rsp 即连坐全隧道）；半死隧道由 mux14 rx-silence 钟（isActive 对位）收口，不在此误杀 */
	}
	                                                                                   /* Go p2papp.go:566：不据 Rsp 定生死（head==nil 仍 go oConn.run）——直接起泵，省旧路径 10s 空窗 */
	BaseType_t pupok = pdFAIL;
	for (int rx = 0; rx < 30 && pupok != pdPASS; rx++) {						/* pup 创建退避同款 fwd sess14（）——瞬时堆紧等 100ms 即回，不再把已收请求的 cfd 关成 RST */
		pupok = xTaskCreate(pump_up_task, "pup", 4096, &cx, 5, NULL);
		if (pupok != pdPASS) vTaskDelay(10);
	}
	if (pupok != pdPASS) { ESP_LOGE(TAG, "pump-create-fail watermark internal=%uB psram=%uB", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM)); ESP_LOGE(TAG, "[port %d] sess14 上行泵创建失败（堆枯竭）", a->srcport); cx.dead = 1; cx.done = 1; }
	uint8_t *plain = s14_buf_alloc(4200);                                                	/* 下行解密缓冲整会话复用，PSRAM 优先 */
	for (;;) {
		if (cx.dead || s->gone) break;                                               /* 上行退（本地断连）或 OverlayDisconnectReq/隧道死 */
		void *fr = NULL;
		if (xQueueReceive(s->rq, &fr, pdMS_TO_TICKS(200)) != pdTRUE) continue;      /* 200ms tick 查 dead/gone；模型加载期 token 长空档不杀会话 */
		s14_frame_t *f = (s14_frame_t *)fr;
		if (f->dl < 8 || f->dl - 8 > 4112) { ESP_LOGW(TAG, "[port %d] sess14 越限弃帧 dl=%u（>4112=对端帧超 Go ReadBuffLen 顶）", a->srcport, (unsigned)f->dl); }       /* 探针 */
		if (f->dl >= 8 && f->dl - 8 <= 4112) {                                     /* [LE64 ovid][密文≤4112]（Go ReadBuffLen=4096+16） */
			size_t plen;
			if (app_cipher(a, f->body + 8, f->dl - 8, 0, plain, &plen) == 0) {                          /* 原 send_all 败即 cx.dead=1 自毁+退场反手发 DisconnectReq 拆对端 oConn——Go p2ptunnel.go:665-668 同一动作只 gLog.e 一行日志，会话/oConn 全保持；3389 点登录瞬间 mstsc 停读最久+下行帧最猛=原版自爆点，SSH/HTTP 轻载永触不了 */
				int sw = 0; esp_err_t se = ESP_FAIL;
				for (;;) {                                                                   /* Go overlayConn.Write 无 deadline=阻塞等位不丢帧（readLoop 停摆背压对端 TCP 窗）；lwIP 用有界重试对位：每轮 send_all 自带 15s SNDTIMEO，10 轮=150s 与 Go 阻塞等价 */
					se = send_all(cfd, plain, plen);
					if (se == ESP_OK || cx.dead || sw >= 10) break;
					if (sw == 0 || sw % 5 == 4) ESP_LOGW(TAG, "[port %d] sess14 本地写未成第%d轮续试(保会话) ovid=%llu len=%u", a->srcport, sw + 1, (unsigned long long)ovid, (unsigned)plen);
					sw++; vTaskDelay(pdMS_TO_TICKS(500));
				}
				if (se != ESP_OK) ESP_LOGW(TAG, "[port %d] sess14 弃帧%uB但会话保持(Go:666-668 write err 不拆会话，本地死活归上行泵 recv 收口=Go oConn.run:61-68 分工)", a->srcport, (unsigned)plen);
			}
		}
		free(f->body); free(f);
	}
	for (;;) {                                         /* DisconnectReq 直置 gone 时 rq 里已到的尾帧不得随 s14_free_frames 误丢（对端 EOF 后立即发 DisconnectReq，丢多少看 sess14 消费速度=长响应尾截断元凶）——退场前排空 rq 保序写 cfd（Go oConn 单 readLoop 顺序写对位） */
		void *fr2 = NULL;
		if (xQueueReceive(s->rq, &fr2, 0) != pdTRUE) break;
		s14_frame_t *f2 = (s14_frame_t *)fr2;
		if (f2->dl >= 8 && f2->dl - 8 <= 4112) {
			size_t plen2;
			if (app_cipher(a, f2->body + 8, f2->dl - 8, 0, plain, &plen2) == 0 && send_all(cfd, plain, plen2) != ESP_OK) { ESP_LOGW(TAG, "[port %d] sess14 drain 弃帧%uB续排(同 Go:666-668 write err 只日志形)", a->srcport, (unsigned)plen2); }    /* 原 send 败即 break=尾帧连坐被丢，恰是"EOF 后尾截断"自伤；Go readLoop 顺序写不据单帧写败弃后续 */
		}
		free(f2->body); free(f2);
	}
	if (plain) free(plain);
	cx.dead = 1;
	while (!cx.done) vTaskDelay(1);                                                  /* 上行泵离场后才碰 cfd/隧道（） */
	overlay_disconnect_req(a, ovid);                                                 /* 无条件注销，对端不留僵尸会话 */
	s14_free_frames(s);
	s->used = 0;                                                                     /* 释放槽位：backlog 里排队的 SYN 下一轮即被 fwd 收进 */
	close(cfd);
	ESP_LOGI(TAG, "[port %d] sess14 会话结束 slot=%d 已释放", a->srcport, ca->slot);
	vTaskDelete(NULL);
}

static void mux14_task(void *arg)
{
	p2p_app_t *a = (p2p_app_t *)arg;
	if (a->relay_fd >= 0) {
		struct timeval sto; sto.tv_sec = 5; sto.tv_usec = 0;                          /* underlay.go:41-56 每帧滚动 SetWriteDeadline(TunnelHeartbeatTime/2=5s) 对位——发窗有界防永堵；EAGAIN≠链路死（Go checkActive 忽略 send err，判死看 ack） */
		struct timeval rto; rto.tv_sec = 5; rto.tv_usec = 0;
		fcntl(a->relay_fd, F_SETFL, 0);                                              /* 语义：清 punch 继承的 O_NONBLOCK，让 RCVTIMEO 真等 */
		setsockopt(a->relay_fd, SOL_SOCKET, SO_SNDTIMEO, &sto, sizeof(sto));         /* 语义：一切发有界 */
		setsockopt(a->relay_fd, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto));         /* 帧中途 5s 无数据=链路死（Go 整帧 Write 不会半帧停发）→ 判字节流断 */
		int one = 1;
		setsockopt(a->relay_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	}
	/* file-static last_hb removed -- it was SHARED by all mux instances (11434/8000/22): each instance that fired a heartbeat refreshed it, so the three tunnels together got ~1 hb per 10s round-robin; idle tunnels (22/8000) starved past the peer readLoop 20s deadline and were torn down (8000 dead at 40.8s, conc22 got 0B) */
	a->last_rx = time(NULL);                                            /* 入口基线（对端首帧到达前不给 rx-silence 可乘之机）；钟源在收帧点 */
	for (;;) {
		if (a->tun_dead) {                                 /* 死隧→退场交 openp2p_task 重建（Go daemonP2PTunnel !isActive→delTunnel→buildDirectTunnel）；mux_alive 退场即清，gone_all 收摊全部会话（部分判死点如心跳连败未带 gone_all） */
			a->mux_alive = 0;
			s14_gone_all(a, "隧道死，重建待启");
			ESP_LOGW(TAG, "[port %d] mux14 dead-tunnel exit (rebuild delegated to control-plane daemon)", a->srcport);
			vTaskDelete(NULL);
			}
		time_t now = time(NULL);
			if (a->last_rx && now - a->last_rx >= 20) {                          /* Go daemonP2PTunnel !isActive 对位——数据面 60s 零收帧=半死隧（对端拆隧无FIN/NAT映射过期；健康空闲每10s 必有 ST=5 帧）；Rsp 失踪场景（撤判死后）唯一合法判死入口 */
			a->tun_dead = 1;
			s14_gone_all(a, "隧道 rx-silence 20s");
			ESP_LOGW(TAG, "[port %d] mux14 rx-silence judged dead (Go daemonP2PTunnel !isActive; rebuild delegated to control-plane daemon)", a->srcport);
			}
		if (now - a->mux_hb >= 10) {                                                   /* 隧道保活：与 thb 同 DONTWAIT 单发语义（fail-fast 不拖 rx 读） */
			if (a->qconn) { if (a->direct) ul_tunnel_hb(a); else ul_relay_hb(a); a->mux_hb = now; }
			else if (tunnel_hb_send_nb(a) == ESP_OK) a->mux_hb = now;                    /* Go writeLoop 心跳一颗不丢（ticker 与业务帧同协程阻塞等 sndbuf 空位，underlay.go:43-63 写败5s=真死才拆）——原 DONTWAIT 单发把 EAGAIN 瞬满当丢拍，对端 readLoop 20s 钟(p2ptunnel.go:601)到点就拆我隧道=churn 制造机。失败不推钟，循环每1s 补发直到成功 */
		}
		int wfd = a->qconn ? quic_udp_fd((quic_conn_t *)a->qconn) : a->relay_fd;
		int qr = a->qconn ? quic_rx_ready((quic_conn_t *)a->qconn) : 0;
		if (wfd < 0) { vTaskDelay(100); continue; }
		fd_set rs; FD_ZERO(&rs); FD_SET(wfd, &rs);
		struct timeval tv; tv.tv_sec = (qr > 0) ? 0 : 1; tv.tv_usec = 0;
		int sel = select(wfd + 1, &rs, NULL, NULL, &tv);
		if (sel < 0) { if (errno == EINTR) continue; a->tun_dead = 1; s14_gone_all(a, "select 失败"); vTaskDelay(100); continue; }
		if (sel == 0) { if (qr > 0) vTaskDelay(1); continue; }
		if (qr == 0 && !FD_ISSET(wfd, &rs)) { vTaskDelay(1); continue; }             /* 伪就绪兜底（教训，fwd 同款） */
		uint8_t h[8];
		if (ul_readn(a, h, 8) != 8) { a->tun_dead = 1; s14_gone_all(a, "下行头读取超时/死"); vTaskDelay(100); continue; }
		uint32_t dl; uint16_t mt, st;
		memcpy(&dl, h, 4); memcpy(&mt, h + 4, 2); memcpy(&st, h + 6, 2);
		if (mt == MSG_P2P && st == MSG_RELAY_DATA) {                                 /* relay 外层 [4/10][rtid8B][内层头]：剥（对齐 ul_recv） */
			uint8_t pre[16];
			if (ul_readn(a, pre, 16) != 16) { a->tun_dead = 1; s14_gone_all(a, "relay 外层剥头死"); vTaskDelay(100); continue; }
			memcpy(&dl, pre + 8, 4); memcpy(&mt, pre + 12, 2); memcpy(&st, pre + 14, 2);
		}
		if (dl > 60000) { a->tun_dead = 1; s14_gone_all(a, "异常帧长→字节流错位"); continue; }         /* 位置已错，body 不可按 dl 读 */
		if (dl == 0) { a->last_rx = time(NULL); continue; }                  /* Go readLoop 每收帧触钟（rx-silence 唯一钟源） */
		uint8_t *body = s14_buf_alloc(dl);   	/* 下行帧体 PSRAM 优先 */
		if (!body) { vTaskDelay(10); continue; }                                     /* 帧内存不足→背压等待（丢帧=TCP 流损坏），等 sess 释放内存后续读 */
		if (ul_readn(a, body, (int)dl) != (int)dl) { free(body); a->tun_dead = 1; s14_gone_all(a, "body 读取中途死"); vTaskDelay(100); continue; }
			a->last_rx = time(NULL);                                           /* 整帧到手触钟 */ live_relay_touch(a);               /* 整帧到手=本口 relay underlay 双向活，续期全局活 relay 缓存（Go app.hbTime[1] readLoop 触钟对位） */
		if (mt == MSG_P2P && st == MSG_OVERLAY_DATA && dl >= 8) {
			uint64_t rid; memcpy(&rid, body, 8);
			s14_sess_t *hit = NULL;
			for (int i = 0; i < a->s14_cap; i++) if (a->s14[i].used && a->s14[i].ovid == rid) { hit = &a->s14[i]; break; }
			if (hit) {
				s14_frame_t *fr = malloc(sizeof(s14_frame_t));
				if (!fr) { free(body); vTaskDelay(10); continue; }
				fr->dl = dl; fr->body = body;
				int sent = 0;
				for (;;) {
					if (xQueueSend(hit->rq, &fr, 0) == pdTRUE) { sent = 1; break; }
					if (!hit->used || hit->gone) break;
					vTaskDelay(2);                                                   /* 队列满=本地客户端不读响应，背压到此（队头阻塞其他会话，LAN 客户端快，可接受） */
				}
				if (!sent) { free(body); free(fr); }                                 /* sess 已亡：弃帧 */
			} else {
				char hx[49] = {0}; for (int k = 0; k < 24 && k < (int)dl; k++) snprintf(hx + 2 * k, 3, "%02x", body[k]);
				ESP_LOGI(TAG, "[port %d] mux14 无会话丢帧 rid=%llx hex=%s", a->srcport, (unsigned long long)rid, hx);
				free(body);
			}
		} else if (mt == MSG_P2P && st == MSG_TUNNEL_HEARTBEAT) {
			ul_tunnel_hb_ack(a); free(body);
		} else if (mt == MSG_P2P && st == MSG_OVERLAY_CONNECT_RSP && dl >= 8) {
			uint64_t aid; memcpy(&aid, body, 8);                          /* 对端 WriteMessageWithAppID(nil) body=appID8B+null（22 口实锤 dl=12）；校验 appID 防伪配 */
			if (aid == a->app_id) for (int i = 0; i < a->s14_cap; i++) if (a->s14[i].used && !a->s14[i].rsp_ok) { a->s14[i].rsp_ok = 1; break; }    /* Go 客户端串行 ReadMessage 无歧义；并发下给最早等待会话 */
			free(body);
			} else if (mt == MSG_P2P && st == MSG_OVERLAY_DISCONNECT_REQ && dl >= 8) {
			char jb[72] = {0}; memcpy(jb, body, (dl < 64) ? dl : 63);    /* body 是 JSON {"id":...}（protocol.go:354 json.Marshal），非二进制 rid */
			long long idv = 0;
			int hitd = 0;
			if (dl > 0 && jget_int(jb, "id", &idv) == 0) {
				for (int i = 0; i < a->s14_cap; i++) if (a->s14[i].used && a->s14[i].ovid == (uint64_t)idv) { a->s14[i].gone = 1; hitd = 1; ESP_LOGI(TAG, "[port %d] mux14 收到 OverlayDisconnectReq rid=%llx", a->srcport, (unsigned long long)idv); break; }
				if (!hitd) ESP_LOGI(TAG, "[port %d] mux14 DisconnectReq rid=%llx 无槽，忽略（Go Load 查无即弃，脏帧防误杀）", a->srcport, (unsigned long long)idv);
					} else {
				char hx[49] = {0}; for (int k = 0; k < 24 && k < (int)dl; k++) snprintf(hx + 2 * k, 3, "%02x", body[k]);
				ESP_LOGI(TAG, "[port %d] mux14 DisconnectReq JSON 解析失败 hex=%s", a->srcport, hx);
					}
			free(body);
		} else {
			ESP_LOGI(TAG, "[port %d] mux14 其它 MT=%u ST=%u dl=%u", a->srcport, mt, st, dl);
			free(body);
		}
	}
}

static void app_listen_task(void *arg);                           /* 前向声明——rebuild_one_app 需给 boot 失败口补建 fwd 监听任务 */
static void rebuild_one_app(int idx)                             /* Go daemonDirectTunnel 对位(p2papp.go:177-232)——死隧重建：setup_one_app 全链含重推 APPKey/SSM（=buildDirectTunnel:264/275 语义）；控制面主任务执行（heartbeat_loop 已让位=控制面 recv 唯一读者空闲，控制面收帧无竞争无抢帧） */
{
	p2p_app_t *a = &g_apps[idx];
	if (a->srcport == S14_PORT || a->srcport == 8080 || a->srcport == 22 || a->srcport == 3389) a->multi = 1;   /* boot 失败口 fwd 从未跑过、multi/cap/txmtx/rq 全空 → rebuild 中 xQueueReceive(NULL) assert 实锤(queue.c:1531)——multi 判定+基础件在此幂等预建（fwd 入口同款 if(!) 守卫，双跑安全） */
	a->s14_cap = (a->srcport == 22) ? 4 : S14_MAX_SESS;
	if (a->multi) {
		if (!a->txmtx) a->txmtx = xSemaphoreCreateMutex();
		for (int m = 0; m < a->s14_cap; m++) if (!a->s14[m].rq) a->s14[m].rq = xQueueCreate(S14_RQ_LEN, sizeof(void *));
	}
	extern volatile int s_busy[OPENP2P_APP_NUM];                  /* 同文件 extern 前向引用同对象（handle_session 同款先例）；等普通路泵退场再碰 fd */
	ESP_LOGW(TAG, "[port %d] tunnel rebuild start (Go delTunnel->buildDirectTunnel; port keeps listen, SYN queues in backlog)", a->srcport);
	a->ready = 0;                                                  /* fwd 暂停 accept（判死点同构）：新 SYN 留 backlog 排队等重建（Go goroutine 便宜，客户端可再试）；handle_session 轮查 ready=0 自退（select 5s tick 有界） */
	for (int w = 0; w < 120 && s_busy[idx]; w++) { vTaskDelay(5); }    /* tick=100Hz 5tick=50ms→120×50ms=6s 兑现"至多6s"（原1200实拖60s）*/                              /* 至多 6s 等普通路(3389) handle_session 退场再 close fd：防 fd 号回收错位（旧 recv 残留读新隧道帧）；multi 路 s_busy 恒 0 秒过 */
	if (a->multi) for (int w = 0; w < 160 && a->mux_alive; w++) { vTaskDelay(5); }    /* 160×50ms=8s 兑现"至多8s"（原1600实拖80s）*/                        /* 至多 8s 等 mux14 死隧自退（隧道下行唯一读者）；退场检查在循环头，5s recv 有界足够 */
	if (a->relay_fd >= 0) { close(a->relay_fd); a->relay_fd = -1; }
	for (int s = 0; s < S14_MAX_SESS; s++) s14_free_frames(&a->s14[s]);                /* 不清 used——Go delTunnel 只关隧道不触 overlayConns：在场会话由新隧 mux14 按 ovid 续下行；used 唯一清零点=sess14 自身出口（旧形强清=僵尸占槽 22s listen 虚设，3389 案实锤） */             /* Go delTunnel 关全部 oConn；rq 不销毁（boot fwd 创建一次，复用）；残留 sess14 见 used=0 自退 */
	a->tunnel_id = 0; a->rtid = 0;                        /* Go 重建=新隧道对象新 tid（rand.Uint64 每隧道生成一次）——留同 tid 会被对端未到期(>20s)旧隧道命中"同重试"忽略新隧道，使对端隧道记录与我方新 underlay fd 错配 */
	a->hb_fail = 0; a->tun_dead = 0; a->mux_hb = time(NULL); a->last_rx = time(NULL);                  /* 重建重开 rx 钟（同 mux14 入口基线语义） */
	for (int k = 0; k < 5; k++) {
		if (g_ctrl_dead) { ESP_LOGW(                                                        /* 一票判死对位原 >=3 短路 */TAG, "[port %d] 控制面WSS写连败=%d 判死——跳过rebuild余轮，短路交 heartbeat_loop 见败触发外层'连接断开10s后重连'全链重登（Go 控制面 goroutine 死即重连对位；rebuild RPC 全打空转≈3min/口=3389 listen 高挂黑洞元凶）", a->srcport, g_ctl_send_fail); a->tun_dead = 1; a->ready = 1; a->next_rebuild = time(NULL) + 30; return; }      /* 保持挂牌：重登后 boot 环/daemon 接手重建 */
		if (k > 0) { peer_feedback(0); g_peer_black_idx = g_peer_idx;   /* 失败即换 dial 方（同 boot 环，用户令 2026-11-18）：上轮失败的 dial peer 本轮排除+记失败，peer_select 改挑下一个在线 natType=1 */ vTaskDelay(pdMS_TO_TICKS(3000));                   /* 3s=Go PunchTsDelay 量级；保活发退役——ctrl_rx 30s ticker 常驻，k-loop 不再自发心跳 */    /* 15s→3s=Go PunchTsDelay 量级（boot/rebuild k-loop 同款；窗对齐靠 punchTs 不靠拖15s，慢轮=少抽奖） */ }                 /* 15s 退避期心跳保活（开机 setup 重试环同款手法）：控制面 WSS 54s idle 踢防——22 未监听教训（）勿复现；此窗控制面 recv 仍单读者（heartbeat_loop 未跑） */
		if (setup_one_app(a, "") == ESP_OK) { peer_feedback(1);   /* 成功：记当前 dial 方成功（供 peer_select 评分与跨口学习） */
			ESP_LOGW(TAG, "[port %d] tunnel rebuild OK (listen resumed; APPKey/SSM re-pushed within setup = Go buildDirectTunnel:264/275)", a->srcport);
			{                                                                                                                           /* 对位 Go buildDirectTunnel:278-289 建隧即同步双推 APPKey+SSM——rebuild 已在 @2301 换新 tid/rtid，对端 memapp 的 tunnelID/relayTunnelID 还指旧隧，首连 Rsp 恰正常到达时 sess14 的 repush 分支永不触发，对端按旧隧记录读写 underlay=静默死（@2285 注释宣称"setup 内已重推"不实，setup 从不推） */
				char ssm[256], ak[96];                                                                                                    /* 载荷与 sess14 @2121-2123 逐字同形（tunnelNum:2 幂等 update 走 handlepush.go:102，不触 :96 DeleteApp） */
				if (a->direct) snprintf(ssm, sizeof(ssm), "{\"from\":\"%s\",\"node\":\"%s\",\"tunnelID\":%llu,\"relayTunnelID\":0,\"relayMode\":\"%s\",\"appID\":%llu,\"appKey\":%llu,\"relayIndex\":0,\"tunnelNum\":2,\"srcPort\":%u}", OPENP2P_NODE, a->relay_name, (unsigned long long)a->tunnel_id, a->relay_mode, (unsigned long long)a->app_id, (unsigned long long)a->app_key, (unsigned)a->srcport);
				else snprintf(ssm, sizeof(ssm), "{\"from\":\"%s\",\"node\":\"%s\",\"tunnelID\":%llu,\"relayTunnelID\":%llu,\"relayMode\":\"%s\",\"appID\":%llu,\"appKey\":%llu,\"relayIndex\":1,\"tunnelNum\":2,\"srcPort\":%u}", OPENP2P_NODE, a->relay_name, (unsigned long long)a->rtid, (unsigned long long)a->tunnel_id, a->relay_mode, (unsigned long long)a->app_id, (unsigned long long)a->app_key, (unsigned)a->srcport);
				snprintf(ak, sizeof(ak), "{\"appID\":%llu,\"appKey\":%llu}", (unsigned long long)a->app_id, (unsigned long long)a->app_key);
				op2p_push(g_peer_name, MSG_PUSH_SERVER_SIDE_SAVE_MEMAPP, ssm);
				op2p_push(g_peer_name, MSG_PUSH_APP_KEY, ak);
				ESP_LOGI(TAG, "[port %d] keyfix rebuild 建隧即推 SSM+APPKey(对位 Go:278-289，新 tid=%llu rtid=%llu 重指对端 memapp)", a->srcport, (unsigned long long)a->tunnel_id, (unsigned long long)a->rtid);
			}			a->retry_num = 0;                                                   /* Go retryNum 成功清零——后续再死从10s/轮重抽 */
			if (a->multi && !a->mux_alive) { BaseType_t mok = pdFAIL;                 /* 旧mux14未退场(唯一读者仍活)则跳过——双建必抢帧;@2287等8s耗尽即此窗 */ for (int rx = 0; rx < 30 && mok != pdPASS; rx++) { mok = xTaskCreate(mux14_task, "mux14", 4096, a, 6, NULL); if (mok != pdPASS) vTaskDelay(10); } if (mok == pdPASS) a->mux_alive = 1; else ESP_LOGE(TAG, "[port %d] mux14 rebuild create failed (heap)", a->srcport); }
			if (!a->listen_on) { a->listen_on = 1; xTaskCreatePinnedToCore(app_listen_task, "fwd", 12288, a, 5, NULL, 0); }   /* boot 失败口从未建过 fwd（监听盲区定罪）——rebuild 成功在此补建，端口才真正开听；multi 未置时由 fwd 入口自置并建 mux14（开机首建同款序） */
			return;
			}
	}
	{ int rn = a->retry_num++; double bk = 10.0 + exp(0.8 * (double)(rn - 3.6)); if (bk > 300.0) bk = 300.0; a->next_rebuild = time(NULL) + (time_t)bk; ESP_LOGI(TAG, "[port %d] rebuild backoff=%ds (retryNum=%d = Go calcRetryTimeRelay common.go:302)", a->srcport, (int)bk, rn); }                              /* 5 轮全败→Go calcRetryTimeRelay 形退避：heartbeat_loop 30s 心跳 tick 再扫+此钟时间门（约 150s/轮）——对端长期离线不忙重试；端口 listen 不拆，SYN 留 backlog */
	a->tun_dead = 1; a->ready = 1;                                       /* 保持死标待下轮（Go daemon 无限重试语义）——reopen accept 让 backlog 里 SYN 排队等新隧道 */
}
static void rebuild_dead_apps(void)                             /* 扫一遍置了 tun_dead 的 app 逐个重建（Go daemonP2PTunnel 每轮全扫描）；由 openp2p_task 内层重建环调用 */
{
	for (int i = 0; i < OPENP2P_APP_NUM; i++) if (g_apps[i].tun_dead && time(NULL) >= g_apps[i].next_rebuild) rebuild_one_app(i);     /* 逐口时间门——Go daemon p2papp.go:191/:318 nextRetryTime[idx].After(now) 则 skip 对位；旧形 A 口见死把 B 口退避窗一并拉建（setup≈3min/口打空+SSM 重推风暴） */
}

static esp_err_t tunnel_hb_send_nb(p2p_app_t *a)                   /* 心跳发败恒不判死——Go checkActive(p2ptunnel.go:150-164)对 WriteBytes 返回值完全忽略、只看 ack(hbTime)推进；Go writeHb(809-818) err->close 是其单协程串行 writeLoop(821-842) 的副作用：Go 发心跳瞬间无业务帧并发写同一 conn（同 select 互斥+writeFull common.go:395 循环写尽才返回），sndbuf 满5s 只能=链路真死。C 形 mux14 心跳与 pup 上行泵(:1935)两任务并发写同一 relay_fd，mstsc 上行/多口 burst 下 sndbuf 满是常态（serial100z_mstsc2 实锤：登录8.4s 后 hb send errno=119 一票死+同秒上行帧 send 同败+空闲85min 44拍无恙）=拥塞瞬态非链路死，一票杀=误杀连坐四口。真死判归 recv 侧三道兜底：ul_readn 半帧/EOF(:2189/2194/2201)+rx-silence 20s(:2170, Go :601 readLoop SetReadDeadline(TunnelHeartbeatTime*2) 对位)+select 败(:2185)，心跳不抢判。仅 EINTR 续（Go syscall 自动重启语义）。 */
{
	uint64_t nid = node_name_to_id(OPENP2P_NODE);
	uint8_t f[16];
	uint32_t dl = 8;
	memcpy(f, &dl, 4);
	f[4] = MSG_P2P & 0xFF; f[5] = (MSG_P2P >> 8) & 0xFF; f[6] = MSG_TUNNEL_HEARTBEAT & 0xFF; f[7] = (MSG_TUNNEL_HEARTBEAT >> 8) & 0xFF;
	for (int i = 0; i < 8; i++) f[8 + i] = (uint8_t)(nid >> (8 * i));
	for (;;) {
		if (send(a->relay_fd, f, sizeof(f), MSG_DONTWAIT) == (ssize_t)sizeof(f)) { a->hb_fail = 0; return ESP_OK; }	/* MSG_DONTWAIT 零阻塞——Go writeHb 5s 阻塞窗(underlay.go:43)由独立 writeLoop 背；C 形 mux14 单任务读者=心跳，阻塞 send(共享 SNDTIMEO 还被互踩 5s/15s)会冻下行最坏15s；心跳幂等，发不出即 defer 下拍补发(:2177 败不推钟)，判死归 rx-silence/ack 钟(Go checkActive p2ptunnel.go:150-164 只看 ack) */
		if (errno == EINTR) continue;                                   /* Go syscall EINTR 自动重启 */
		if (++a->hb_fail == 1 || a->hb_fail % 5 == 0) ESP_LOGW(TAG, "[port %d] tunnel hb send deferred errno=%d x%d (sndbuf jammed, no kill; Go checkActive p2ptunnel.go:150-164 忽略 send err，判死归 ack/rx-silence 钟)", a->srcport, errno, a->hb_fail);
		return ESP_FAIL;
				}
}

static void tunnel_idle_drain(p2p_app_t *a)                    /* 无会话期排空入帧（对端 [4/4]/ack/残留）：不读=接收窗枯竭，把对端 writeLoop 流控堵死（链）。每 tick 最多 4 帧，剩余下 tick 继续 */
{
	for (int k = 0; k < 4; k++) {
		uint8_t h[8];
		if (recv(a->relay_fd, h, 8, MSG_DONTWAIT) != 8) return;   /* 无完整头即停（EAGAIN/半帧下 tick 续） */
		uint32_t dl; uint16_t m, s;
		memcpy(&dl, h, 4); memcpy(&m, h + 4, 2); memcpy(&s, h + 6, 2);
		if (m == MSG_P2P && s == MSG_RELAY_DATA && dl >= 16) {     /* relay 外层 [4/10][rtid8B][内层8B头]：一起丢掉，内层 dl 定 body */
			uint8_t pre[16];
			if (recv(a->relay_fd, pre, 16, MSG_DONTWAIT) != 16) return;
			memcpy(&dl, pre + 8, 4);
		}
		while (dl > 0) {                                           /* body 逐字节吃掉，跳一个字节即串头 */
			uint8_t scratch[64];
			int c = (dl > sizeof(scratch)) ? (int)sizeof(scratch) : (int)dl;
			if (recv(a->relay_fd, scratch, c, MSG_DONTWAIT) != c) return;
			dl -= (uint32_t)c;
		}
	}
}

static void tunnel_hb_task(void *arg)
{
	static time_t last[OPENP2P_APP_NUM];                         /* 独立节拍，不与泵共享 last_hb */
	for (;;) {
		time_t now = time(NULL);
		for (int p = 0; p < OPENP2P_APP_NUM; p++) {
			p2p_app_t *a = &g_apps[p];
			if (!a->ready || a->relay_fd < 0) continue;                           /* 会话期心跳照发（Go writeLoop p2ptunnel.go:801 与数据 goroutine 互不等待、readLoop 无活动 20s 即拆隧道——会话空闲>20s 不停跳就断隧道）；drain 才避让（见 B3） */
			if (a->multi) continue;                                              /* 11434：mux14 接管 rx（idle 排空+ack）与 10s 心跳（同 DONTWAIT 单发语义），thb 整体避让防串帧 */
			if (a->qconn) {                                          /* QUIC 隧道未启用路（rx=0），维持原阻塞语义不动 */
				if (s_busy[p]) continue;                                          /* QUIC 路心跳是阻塞 ul_tunnel_hb，会话期发它会重蹈 反例挂死——该路未启用(rx=0)，维持旧避让语义 */
				if (now - last[p] >= 10) { if (a->direct) ul_tunnel_hb(a); else ul_relay_hb(a); last[p] = now; }
				continue;
			}
			if (now - last[p] >= 10) { if (tunnel_hb_send_nb(a) != ESP_OK) ESP_LOGW(TAG, "[port %d] thb 心跳发送失败（underlay 链路死/sndbuf 满）", a->srcport); last[p] = now; }
			if (!s_busy[p]) { tunnel_idle_drain(a); }                             /* 排空才需会话避让（recv 单读者防串帧）；DONTWAIT 心跳与会话并发 send 帧原子（lwIP netconn 一 send 一排队） */
		}
		vTaskDelay(pdMS_TO_TICKS(1000));
	}
}

/* ---------- 端口转发：每端口一个 App/一条 relay 隧道，常驻监听，透传经对端代拨四路目标(app_dstip_for) ----------
 * 一个 App 内可并发多 overlayConn（源码 listenTCP:506），但本端每端口只需串行接一个本地连接。
 * 监听常驻：accept 阻塞等本地连接，逐个 handle_session；一条隧道同时只承载一个 overlay 会话。 */
static void app_listen_task(void *arg)
{
	p2p_app_t *a = (p2p_app_t *)arg;
	int lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) { ESP_LOGE(TAG, "[port %d] listener socket 失败", a->srcport); vTaskDelete(NULL); }
	int one = 1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in lsa; memset(&lsa, 0, sizeof(lsa));
	lsa.sin_family = AF_INET; lsa.sin_addr.s_addr = htonl(INADDR_ANY);
	lsa.sin_port = htons(a->srcport);
	if (bind(lfd, (struct sockaddr *)&lsa, sizeof(lsa)) != 0) { ESP_LOGE(TAG, "[port %d] bind 失败", a->srcport); close(lfd); vTaskDelete(NULL); }
	if (a->srcport == S14_PORT || a->srcport == 8080 || a->srcport == 22 || a->srcport == 3389) a->multi = 1;	/* 3389 归队 multi/sess14（与 @2279 同条件）——单会话路缺 Rsp失踪repush 救活=memapp 竞态首连必死()，Go 原生单路=readLoop 按 ovid 分发(multi=对位)；multi instance reuse -- 8000 same as 11434, 22 SSH long-lived (x4); 原"3389 sole user of single-session path"判罚撤销 */
	a->s14_cap = (a->srcport == 22) ? 4 : S14_MAX_SESS;	/* long-lived SSH holds slots long; cap 4 saves ~35K internal RAM stacks; value unused on single-path ports */
	if (listen(lfd, a->multi ? a->s14_cap : 2) != 0) { ESP_LOGE(TAG, "[port %d] listen 失败", a->srcport); close(lfd); vTaskDelete(NULL); }
	ESP_LOGI(TAG, ">>> [port %d] 已监听 0.0.0.0:%d（连本机此端口 → 透传到 %s:%d）", a->srcport, a->srcport, app_dstip_for(a->srcport), a->dstport);
	if (a->multi) {                                                      /* 多会话基础件：txmtx 隧道帧发送锁 + 每槽下行队列 + mux14 独占 rx（接管心跳与排空） */
		if (!a->txmtx) a->txmtx = xSemaphoreCreateMutex();
		for (int m14 = 0; m14 < a->s14_cap; m14++) if (!a->s14[m14].rq) a->s14[m14].rq = xQueueCreate(S14_RQ_LEN, sizeof(void *));
		if (!a->mux_alive && (xTaskCreate(mux14_task, "mux14", 4096, a, 6, NULL) != pdPASS ? (a->mux_alive = 0, 1) : (a->mux_alive = 1, 0))) ESP_LOGE(TAG, "[port %d] mux14 任务创建失败", a->srcport);    /* rebuild_one_app 已拉起 mux14 时跳过——隧道下行唯一读者，双建必抢帧 */
	}
	for (;;) {
		/* select 轮询代替阻塞 accept：accept 空转期也必须每 10s 发 relay 隧道
		   保活 [4/11]（relayHeartbeatLoop 对齐；relay server *2=20s 无则拆对）。 */
				int wfd2 = a->qconn ? quic_udp_fd((quic_conn_t *)a->qconn) : -1;     /* direct idle 期 watch 死 relay_fd = select 秒就绪+recv 秒错 0-sleep 忙转（tick100Hz 把上轮 pdMS_TO_TICKS(5) 截成 0）→饿死 accept+wdt，"一连就断开"。Go listenTCP 只有阻塞 accept，隧道层保活归 thb 任务 */
		int qr2 = a->qconn ? quic_rx_ready((quic_conn_t *)a->qconn) : 0;
		fd_set rs; FD_ZERO(&rs); FD_SET(lfd, &rs); int mf = lfd;
		if (!a->ready || a->tun_dead) FD_CLR(lfd, &rs);    /* 重建窗不把 lfd 放进读集——backlog 有 SYN 时 listen 恒可读，accept 被 ready=0 跳过后 select 0-sleep 忙转饿死 IDLE0（task_wdt@245s 实锤）；SYN 仍留 backlog，rebuild 回来即收 */
		if (wfd2 >= 0) { FD_SET(wfd2, &rs); if (wfd2 > mf) mf = wfd2; }
		struct timeval tv; tv.tv_sec = (qr2 > 0) ? 0 : 1; tv.tv_usec = 0;    /* qr2>0 走 tv=0 真 poll：伪造 sel=1 让 FD_ISSET(lfd) 恒真，且 drain 无进展时不自旋 */
		int sel = select(mf + 1, &rs, NULL, NULL, &tv);
		if (sel == 0 && qr2 > 0) vTaskDelay(1);                               /* poll 空转让出 CPU（wdt 根因） */
		if (sel < 0) { if (errno == EINTR) continue; a->listen_on = 0; ESP_LOGW(TAG, "[port %d] select 失败，退出(listen_on归零交rebuild补建——原退场不清标记=rebuild永不补建该口)", a->srcport); break; }
			if (sel > 0 && qr2 == 0 && !FD_ISSET(lfd, &rs) && !(wfd2 >= 0 && FD_ISSET(wfd2, &rs))) vTaskDelay(1);      /* 兜底：sel 伪就绪无位置位=0-sleep 忙转，让出 CPU 再轮 */
				if (qr2 > 0 || (sel > 0 && wfd2 >= 0 && FD_ISSET(wfd2, &rs))) {    /* idle drain：hb ack/杂帧，QUIC 走 rxbuf/UDP */
			uint8_t h[8];
			if (ul_readn(a, h, 8) == 8) {
				uint32_t dl; memcpy(&dl, h, 4);
				uint8_t scratch[64];
				while (dl > 0) { int c = (dl > sizeof(scratch)) ? (int)sizeof(scratch) : (int)dl; if (ul_readn(a, scratch, c) != c) break; dl -= (uint32_t)c; }
			}
			  else { vTaskDelay(2); }                     /* tick=100Hz 时 pdMS_TO_TICKS(5)=0 tick 节流失效（wdt 现场实锤），改按 tick≥1 睡 */
		}
		if (sel > 0 && FD_ISSET(lfd, &rs) && a->ready && !a->tun_dead) {
			int slot = -1;
			if (a->multi) {                                                   /* 11434：先抢槽再 accept；槽位全忙=本轮不收（SYN 在 backlog 里等，下一轮再收），拒不丢 */
				for (int i = 0; i < a->s14_cap; i++) if (!a->s14[i].used) { slot = i; break; }
				if (slot < 0) {
					static time_t lastfull;
					if (time(NULL) - lastfull >= 5) { ESP_LOGI(TAG, "[port %d] sess14 槽位 %d 全忙，排队等待", a->srcport, a->s14_cap); lastfull = time(NULL); }
					vTaskDelay(5);
					continue;
				}
				s14_free_frames(&a->s14[slot]);                                 	/* 残帧先排干，再原子初始化槽（Go overlayConns.Store 原子的本端对位）： */
					a->s14[slot].ovid = rand64(); a->s14[slot].gone = 0; a->s14[slot].rsp_ok = 0;                     	/*   消"used=1 但 ovid=旧值"窗口——上一会话迟到的 [4/8]/[4/9] 不再命中新会话（RST 定罪） */
					a->s14[slot].used = 1;                                        	/* 抢置：防下一轮抢同槽（sess 仅在出口清 0） */
			}
			struct sockaddr_in ca; socklen_t cl = sizeof(ca);
			int cfd = accept(lfd, (struct sockaddr *)&ca, &cl);
			if (cfd < 0) { if (slot >= 0) a->s14[slot].used = 0; ESP_LOGW(TAG, "[port %d] accept 失败，退出", a->srcport); break; }
			/* inet_ntoa 正确处理网络字节序（ESP32 小端逐字节提取会反序） */
			ESP_LOGI(TAG, "[port %d] 本地连接 %s → 透传到 %s:%d", a->srcport, inet_ntoa(ca.sin_addr), app_dstip_for(a->srcport), a->dstport);
			if (a->multi) {                                                   /* 多会话：sess14(下行)+pup(上行) 独立任务对，同隧道 txmtx 防帧交织 */
				a->s14_args[slot].cfd = cfd; a->s14_args[slot].a = a; a->s14_args[slot].slot = slot;
				BaseType_t s14ok = pdFAIL;
					for (int rx = 0; rx < 30 && s14ok != pdPASS; rx++) {                   	/* RST=建任务堆枯竭失败即close（rst76 实锤 20304 时恰 1 路）。Go 对位 goroutine 2K 按需栈——4096+退避 100ms×6 等旧会话缓冲归还，不再 RST 第 4 路 */
						s14ok = xTaskCreate(sess14_task, "s14s", 5120, &a->s14_args[slot], 6, NULL);
						if (s14ok != pdPASS) vTaskDelay(10);
						}
					if (s14ok != pdPASS) { ESP_LOGE(TAG, "[port %d] sess14 任务创建失败（堆枯竭）", a->srcport); close(cfd); a->s14[slot].used = 0; }
			} else {
				handle_session(cfd, a);
				close(cfd);
				ESP_LOGI(TAG, "[port %d] 会话结束，等待下一个本地连接", a->srcport);
			}
			}
	}
	close(lfd);
	vTaskDelete(NULL);
}

/* ---------- 任务 ---------- */

static void openp2p_task(void *arg)
{
	if (!s_wtx) s_wtx = xSemaphoreCreateMutex();                        /* 单线程期建锁，之后一切任务发 WSS 互斥 */
	aes128_selftest();
	quic_selftest();    /* SHA256/HMAC/GCM/HKDF/X25519 已知答案自检（日志看 QUIC selftest: OK） */    /* FIPS-197 向量验自写 AES；下接 QUIC 原语自检 */	/* 启动自检：FIPS-197 向量验证自写 AES 加解密正确（日志看 enc/dec=OK） */
	nat_detect();           /* 登录前 NAT 探测（对齐 Go：getNATType 先于 login，URL 带 ipv4/nattype） */
	xTaskCreate(tunnel_hb_task, "thb", 4096, NULL, 5, NULL);      /* 心跳与数据解耦——泵堵死也不误心跳（对端 20s deadline） */
	while (1) {
		esp_err_t e = openp2p_login_once();
		if (e == ESP_OK) {
			g_ctrl_dead = 0; g_ctl_send_fail = 0; g_ctrl_last_rx_msg = time(NULL);       /* 新连接清判死旗标 */
			g_ctrl_rx_up = 1;                                                             /* 先置标记再建任务（mux_alive 同款：退场等"归零"） */
			xTaskCreate(ctrl_rx_task, "crx", 16384, NULL, 6, NULL);                        /* Go readLoop+ticker 合体常驻唯一读者——栈16K：读路径过 mbedtls 记录层+PSA AES-GCM（WSS 栈深教训，登录任务 32K 因含完整握手） */
			report_basic_once();                 /* 登录后上报节点信息（控制面"注册"） */
			request_sdwan();                     /* 查本节点虚拟 IP + 下发 peer 池（Nodes[] 剔自身） */
			{ int w = 0; while (g_peer_count == 0 && w < 60) { vTaskDelay(pdMS_TO_TICKS(100)); w++; } }  /* 等 SDWANInfo 填充 peer 池（至多 6s） */
			if (g_peer_count == 0) ESP_LOGW(TAG, "SDWANInfo peer 池未填充（6s 超时），继续尝试");
			ESP_LOGI(TAG, "==== 查询目标 peer 在线状态（池 %d 个） ====", g_peer_count);
			esp_err_t r_target = peer_select() ? ESP_OK : ESP_FAIL;
			ESP_LOGI(TAG, "==== 目标 peer 状态: %s ====", r_target == ESP_OK ? g_peer_name : "(全离线/池空)");

			/* 数据面：4 个端口 = 4 个 App = 4 条独立 relay 隧道（源码 App.ID()=SrcPort*10）。
			   逐端口建链；每条成功就起一个常驻监听任务，本地连该端口 → 透传到目标主机同端口。 */
			int ready_num = 0;
			for (int i = 0; i < OPENP2P_APP_NUM; i++) {
				g_apps[i].srcport = g_app_ports[i];
				g_apps[i].dstport = g_app_ports[i];
				if (g_apps[i].relay_fd >= 0) { close(g_apps[i].relay_fd); g_apps[i].relay_fd = -1; }     /* 泄漏修复(审计实锤#2)：重登曾裸弃上轮建立的 underlay socket，每次重登最多泄4口≈2.5KB+4 fd 槽——先关再清标记 */
				g_apps[i].ready = 0;
				esp_err_t r_app = ESP_FAIL; char excl[128] = "";    /* 定案：初值排除某 peer 是自杀——relay==目标即 Go 官方 tcp4 直连（direct 拨 v4l）；Go excludeNodes=单值（对侧 tunnel 的 PeerNode），失败者由 last_fail 逐个追加 */         /* 已知 dial 不通的中继先排除，逼服务器派线路可达的官方中继 */ for (int k = 0; k < 5 && r_app != ESP_OK; k++) { if (k > 0 && g_ctrl_dead) break;                                                    /* Go 写败一票判死对位（send_heartbeat/op2p_send 写败即置 g_ctrl_dead） */      /* 控制面写连败=重登刚成功又死，逐口5轮打空≈75s×4口——快败挂牌交 heartbeat_loop 重登 */ if (k > 0) { ESP_LOGW(TAG, "[port %d] 第%d次重试建链(退避Go形3s)，excludeNodes=%s", g_apps[i].srcport, k, excl); vTaskDelay(pdMS_TO_TICKS(3000));                   /* 3s=Go PunchTsDelay 量级；保活发退役——ctrl_rx 30s ticker 常驻，k-loop 不再自发心跳 */    /* 15s→3s=Go PunchTsDelay 量级（boot/rebuild k-loop 同款；窗对齐靠 punchTs 不靠拖15s，慢轮=少抽奖） */ } g_apps[i].last_fail[0] = 0; r_app = setup_one_app(&g_apps[i], excl); if (r_app != ESP_OK) { peer_feedback(0);   /* 本次 dial 方记一次失败（g_peer_idx=刚拨的那个），供评分与换人 */ g_peer_black_idx = g_peer_idx;   /* 失败即换 dial 方（用户令 2026-11-18）：刚失败的 dial peer 下轮排除，peer_select 改挑下一个在线 natType=1 节点 */ } if (r_app != ESP_OK && g_apps[i].last_fail[0] && !strstr(excl, g_apps[i].last_fail)) { size_t el = strlen(excl); snprintf(excl + el, sizeof(excl) - el, el ? ",%s" : "%s", g_apps[i].last_fail); } } if (r_app == ESP_OK) { peer_feedback(1); ready_num++; if (!g_apps[i].listen_on) { g_apps[i].listen_on = 1; xTaskCreatePinnedToCore(app_listen_task, "fwd", 12288, &g_apps[i], 5, NULL, 0); } }     /* listen_on 防外层重连再入时双 fwd 监听（旧 fwd 任务永不退场） */ else { g_apps[i].tun_dead = 1; { int rn = g_apps[i].retry_num++; double bk = 10.0 + exp(0.8 * (double)(rn - 3.6)); if (bk > 300.0) bk = 300.0; g_apps[i].next_rebuild = time(NULL) + (time_t)bk; } ESP_LOGW(TAG, "[port %d] boot setup 5轮全败 → tun_dead 挂牌，Go形退避后 daemon 自动重建（Go per-app goroutine 无限重试对位；原盲区：开机失败口无人再管只能复位）", g_apps[i].srcport); }   /* 建成一条立刻监听：不等其余端口，22 先就绪用户即可连 */
			}
			ESP_LOGI(TAG, ">>> 数据面建链 %d/%d 条隧道成功", ready_num, OPENP2P_APP_NUM);

			for (;;) { int hb = heartbeat_loop(); if (hb != 1) break; rebuild_dead_apps(); }    /* Go daemonP2PTunnel 常驻重建环对位——heartbeat_loop 返 1=见死隧，控制面单线程 rebuild_dead_apps（不拆 WSS 不重登录，隧道级重建免复位），建完续心跳 */                    /* 内部循环，直到断开返回 */
			g_ctrl_dead = 1;                                                               /* 重登先停唯一读者——等 ctrl_rx 退场再 wss_close（:2298 同款教训：fd 号回收错位让旧读者读新连接帧） */
			for (int w = 0; w < 80 && g_ctrl_rx_up; w++) vTaskDelay(10);                   /* 至多 8s（实际秒退：recv 1s 片+循环头查 g_ctrl_dead） */
			wss_close(&s_ws);
			ESP_LOGW(TAG, "连接断开，10s 后重连");
		} else {
			ESP_LOGE(TAG, "登录失败 0x%x，10s 后重试", e);
		}
		vTaskDelay(pdMS_TO_TICKS(10000));
	}
}

void openp2p_start(void)
{
	/* 栈必须够大：TLS1.3 + ESP32-S3 硬件 PSA 透明驱动（esp_hmac/esp_sha）
	   调用链极深，8KB 会越界踩坏堆里的 FreeRTOS TCB/事件列表，表现为取锁时
	   xTaskRemoveFromEventList(pxUnblockedTCB) 断言。栈占 RAM 不占 flash。 */
	xTaskCreatePinnedToCore(openp2p_task, "openp2p", 32768, NULL, 5, NULL, 1);
}
