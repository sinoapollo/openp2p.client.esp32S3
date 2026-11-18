/*
 * OpenP2P 二进制协议 —— 消息头与消息类型常量
 *
 * 对齐 protocol.go (v3.25.11) 与 第三章。
 * 全程小端序 (LittleEndian)。
 *
 * 注：proxy.c 原版的 MsgPush 子类型自 16 起整体错位（16=ReportHeap、17=杜撰的
 *     ReportResponse 等），此文件按 §3.3 逐一更正。
 */
#ifndef P2P_PROTOCOL_H
#define P2P_PROTOCOL_H

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* 客户端版本声明                                                      */
/*   3.15.5 = 上游 SupportDualTunnelVersion。                          */
/*   依据 §6.6 版本门控：                                      */
/*     >= 3.0.0  (LeastSupportVersion，低于被拒)                        */
/*     >= 3.14.5 (启用 Intranet 内网直连)                               */
/*     <  3.25.1 (不触发“多直连隧道”分支，ESP32 未实现该特性)          */
/*   原则：只声明本端确实做得到的特性。                                  */
/* ------------------------------------------------------------------ */
#define OPENP2P_CLIENT_VERSION "3.15.5"

/* ------------------------------------------------------------------ */
/* 服务器端口 (§5.1)。                                         */
/*   注意：上游 UDPPort1/2 是死常量（无任何读写），不引入。             */
/* ------------------------------------------------------------------ */
#define OPENP2P_NAT_DETECT_PORT1   27180
#define OPENP2P_NAT_DETECT_PORT2   27181
#define OPENP2P_WS_PORT            27183   /* WSS 主登录端口 */
#define OPENP2P_WS_PORT2           465     /* WSS 备用端口 */
#define OPENP2P_LOGIN_PATH         "/api/v1/login"
#define OPENP2P_LOGIN_HOST         "api.openp2p.cn"

/* ------------------------------------------------------------------ */
/* 通用消息头：8 字节，packed，小端 (§3.1)                    */
/* ------------------------------------------------------------------ */
typedef struct {
	uint32_t DataLen;   /* 数据长度（不含这 8 字节头） */
	uint16_t MainType;  /* 主类型 MSG_* */
	uint16_t SubType;   /* 子类型（各 Main 内独立编号） */
} __attribute__((packed)) openp2p_header;

#define OPENP2P_HEADER_SIZE 8

/* MsgPush 路由头：From/To 节点 ID（各 8B 小端）。见 core/protocol.go PushHeader、
 * p2pnetwork.go push()。请求体与多数响应体前带这 16B；sub=0(PushRsp) 响应不带。 */
typedef struct {
	uint64_t From;   /* 源节点 ID = NodeNameToID(源节点名) */
	uint64_t To;     /* 目的节点 ID = NodeNameToID(目的节点名) */
} __attribute__((packed)) openp2p_push_header;

#define OPENP2P_PUSH_HEADER_SIZE 16

/* ------------------------------------------------------------------ */
/* 主消息类型 (§3.2)                                          */
/* ------------------------------------------------------------------ */
enum {
	MSG_LOGIN     = 0,
	MSG_HEARTBEAT = 1,
	MSG_NATDETECT = 2,
	MSG_PUSH      = 3,
	MSG_P2P       = 4,
	MSG_RELAY     = 5,
	MSG_REPORT    = 6,
	MSG_QUERY     = 7,
	MSG_SDWAN     = 8,
};

/* ------------------------------------------------------------------ */
/* MsgPush 子类型 —— 对齐 Go core/protocol.go:100-125 (0-23)          */
/* ------------------------------------------------------------------ */
enum {
	MSG_PUSH_RSP                      = 0,
	MSG_PUSH_CONNECT_REQ              = 1,
	MSG_PUSH_CONNECT_RSP              = 2,
	MSG_PUSH_HANDSHAKE_START          = 3,
	MSG_PUSH_ADD_RELAY_TUNNEL_REQ     = 4,
	MSG_PUSH_ADD_RELAY_TUNNEL_RSP     = 5,
	MSG_PUSH_UPDATE                   = 6,
	MSG_PUSH_REPORT_APPS              = 7,
	MSG_PUSH_UNDERLAY_CONNECT         = 8,
	MSG_PUSH_EDIT_APP                 = 9,
	MSG_PUSH_SWITCH_APP               = 10,
	MSG_PUSH_RESTART                  = 11,
	MSG_PUSH_EDIT_NODE                = 12,
	MSG_PUSH_APP_KEY                  = 13,
	MSG_PUSH_REPORT_LOG               = 14,
	MSG_PUSH_DST_NODE_ONLINE          = 15,  /* Go MsgPushDstNodeOnline=15 */
	MSG_PUSH_REPORT_GOROUTINE         = 16,
	MSG_PUSH_REPORT_MEM_APPS          = 17,
	MSG_PUSH_SERVER_SIDE_SAVE_MEMAPP  = 18,
	MSG_PUSH_CHECK_REMOTE_SERVICE     = 19,
	MSG_PUSH_SPEC_TUNNEL              = 20,
	MSG_PUSH_REPORT_HEAP              = 21,
	MSG_PUSH_SDWAN_REFRESH            = 22,  /* Go MsgPushSDWanRefresh=22 */
	MSG_PUSH_NAT4_DETECT              = 23,  /* Go MsgPushNat4Detect=23   */
};

/* ------------------------------------------------------------------ */
/* MsgP2P 子类型 (§3.4)                                       */
/* ------------------------------------------------------------------ */
enum {
	MSG_PUNCH_HANDSHAKE         = 0,
	MSG_PUNCH_HANDSHAKE_ACK     = 1,
	MSG_TUNNEL_HANDSHAKE        = 2,
	MSG_TUNNEL_HANDSHAKE_ACK    = 3,
	MSG_TUNNEL_HEARTBEAT        = 4,
	MSG_TUNNEL_HEARTBEAT_ACK    = 5,
	MSG_OVERLAY_CONNECT_REQ     = 6,
	MSG_OVERLAY_CONNECT_RSP     = 7,
	MSG_OVERLAY_DISCONNECT_REQ  = 8,
	MSG_OVERLAY_DATA            = 9,
	MSG_RELAY_DATA              = 10,
	MSG_RELAY_HEARTBEAT         = 11,
	MSG_RELAY_HEARTBEAT_ACK     = 12,
	MSG_NODE_DATA               = 13,
	MSG_RELAY_NODE_DATA         = 14,
	MSG_NODE_DATA_MP            = 15,
	MSG_NODE_DATA_MP_ACK        = 16,
	MSG_RELAY_HEARTBEAT_ACK2    = 17,
};

/* ------------------------------------------------------------------ */
/* MsgRelay 子类型 (§3.5)                                     */
/* ------------------------------------------------------------------ */
enum {
	MSG_RELAY_NODE_REQ = 0,
	MSG_RELAY_NODE_RSP = 1,
};

/* ------------------------------------------------------------------ */
/* MsgReport 子类型 (§3.5)                                    */
/* ------------------------------------------------------------------ */
enum {
	MSG_REPORT_BASIC       = 0,
	MSG_REPORT_QUERY       = 1,
	MSG_REPORT_CONNECT     = 2,
	MSG_REPORT_APPS        = 3,
	MSG_REPORT_LOG         = 4,
	MSG_REPORT_MEM_APPS    = 5,
	MSG_REPORT_RESPONSE    = 6,
	MSG_REPORT_BASIC_RSP   = 7,
};

/* ------------------------------------------------------------------ */
/* MsgQuery 子类型 (§3.5)                                     */
/* ------------------------------------------------------------------ */
enum {
	MSG_QUERY_PEER_INFO_REQ = 0,
	MSG_QUERY_PEER_INFO_RSP = 1,
};

/* ------------------------------------------------------------------ */
/* MsgSDWAN 子类型 (§3.5)                                     */
/* ------------------------------------------------------------------ */
enum {
	MSG_SDWAN_INFO_REQ = 0,
	MSG_SDWAN_INFO_RSP = 1,
};

/* ------------------------------------------------------------------ */
/* MsgNATDetect 子类型 (§3.5)                                 */
/* ------------------------------------------------------------------ */
enum {
	MSG_NAT_DETECT_NAT       = 0,
	MSG_NAT_DETECT_PUBLIC_IP = 1,
};

/* ------------------------------------------------------------------ */
/* 心跳间隔 / 超时 (§5.8)                                     */
/*   客户端每 30s 发一次 MsgHeartbeat；90s（3x）无回包判离线重连。     */
/*   注：心跳 body 为 LE64 时间戳（非 JSON），服务器回 LE64 t2，       */
/*       时差 dt = t1 + rtt/2 - t2。详见控制面实现。           */
/* ------------------------------------------------------------------ */
#define OPENP2P_HEARTBEAT_INTERVAL_MS  30000
#define OPENP2P_HEARTBEAT_TIMEOUT_MS  90000

#endif /* P2P_PROTOCOL_H */
