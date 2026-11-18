/*
 * config.h —— 部署配置模板
 *
 * 克隆本仓库后，先在这里填自己的值，再编译烧录（见 Readme.md 环境设置/编译章节）。
 *
 * 必填（空则对应功能首启不可用）：
 *   OPENP2P_WIFI_SSID / OPENP2P_WIFI_PASS   要连的 WiFi
 *   OPENP2P_TOKEN                           OpenP2P 登录 token（OpenP2P 后台账号的凭据）
 *   OPENP2P_NODE                            本节点名（OpenP2P 后台可见/可映射的节点名）
 *   OPENP2P_DST_22/3389/8080/11434          要映射到目标主机的 IP（或统一填 OPENP2P_APP_DSTIP）
 *
 * 可选：
 *   OPENP2P_STA_IP                          本机固定 IP（空=DHCP）
 *   OPENP2P_LOG_ON / OPENP2P_DIAG_ON        串口日志开关（0=release 静默，1=全量取证日志）
 *
 * 优先级：本文件是"编译期默认值"；首启经 80 口网页配置台（http://<板子IP>/）保存后，
 *         配置写入 NVS 并成为运行时权威（优先于本文件）。开源仓库默认全留空，勿提交真实凭据。
 */
#ifndef CONFIG_H
#define CONFIG_H

#define OPENP2P_WIFI_SSID     ""              /* 出厂无默认 SSID（开源不含作者网络信息）：首启经 80 口网页配置台填，NVS 权威。空=板子暂连不上网，需先配 */
#define OPENP2P_WIFI_PASS     ""              /* 出厂无默认密码；经网页填 */
#define OPENP2P_STA_IP        ""              /* 出厂无默认固定 IP（开源不留作者内网 IP）：空=DHCP；需固定 IP 经网页填，wifi.c GOT_IP 后归位并停 dhcpc */
#define OPENP2P_LOG_ON       0              /* 1=编译全部日志（取证态，串口全量输出，bin 变大）；0=ESP_LOGx 编译期整段剔除（oplog.h 空宏，release 交付态，用户 2026-11-18 令"直接上 release"） */
#define OPENP2P_DIAG_ON      0              /* 1=编译纯观测/行为监听块（idle heap 打印环、AES/QUIC 已知答案自检）；0=只保留实际功能（release 交付态） */
#define OPENP2P_TOKEN    ""                   /* 出厂无默认 token（开源不含作者账号）：经 80 口网页配置台填，NVS 权威 g_cfg.token */
#define OPENP2P_NODE        ""                /* 出厂无默认节点名（开源不含作者节点名）：经网页/登录填，OpenP2P 后台里可见/可映射 */

/* ---------- 端口映射（L4 p2pApp）目标参数：对齐用户真实 Go 命令 ----------
 * 本地 0.0.0.0:SRCPORT 监听 → relay(RELAY_NODE) → 对端(PEER_NODE) dial DstIP:DstPort。
 * app.id/app.key 运行时随机（源码 rand.Uint64），不在此固定。whitelist 空=对任意地址开放。 */
/* peer 池不硬编码：登录后从 SDWANInfo Nodes[] 动态取，剔自身，任一在线即 dial。
   透传目标 IP 由用户经网页配置（NVS g_cfg），开源不含作者目标主机信息。 */
/* 中继不再写死：运行时发 MsgRelayNodeReq 让服务器按 peer 分配在线中继（源码 addRelayTunnel:312-331。
 * ）。本宏当前未使用，留作"强制指定某中继"备用。 */
#define OPENP2P_RELAY_NODE         ""    					/* 置空 => RelayNodeReq 由服务器派官方公共中继(addRelayTunnel:312-331)。定案：双CGNAT(我4G<->对端家宽)下对端 tcp4 直连物理不可能——对端在 NAT 后、其出口 IP 无对应端口转发，直拨全 RST。唯一活路=双方各自 ACTIVE dial 公共中继节点的 v4l 公网口，零入站 */
/* 要映射到目标主机的本地端口（= 对端 dial 的目标端口，一一对应）。
 * 每端口一个 App、一条独立 relay 隧道（源码：App.ID()=SrcPort*10, P2PTunnel 绑 AppConfig）。 */
#define OPENP2P_FWD_PORT_NUM  4
#define OPENP2P_FWD_PORTS     { 22, 3389, 8080, 11434 }
#define OPENP2P_DST_22        ""           /* 22 映射目标 IP：出厂无默认（开源不含作者目标），经网页填，NVS g_cfg.dst22 权威 */
#define OPENP2P_DST_3389      ""           /* 3389 映射目标 IP：经网页填 */
#define OPENP2P_DST_8080      ""           /* 8080 映射目标 IP：经网页填 */
#define OPENP2P_DST_11434     ""           /* 11434 映射目标 IP：经网页填 */
#define OPENP2P_APP_DSTIP   ""           /* 透传目标 IP 兜底：出厂无默认，经网页填；对端 dial 目标主机同端口服务 */

#endif /* CONFIG_H */
