#ifndef OPENP2P_H
#define OPENP2P_H

#include <stdint.h>
#include "esp_err.h"

/* 单次登录：WSS 连接 + Upgrade + 收登录响应。
 * 成功 ESP_OK（已拿到 user/node，见日志）；失败返回错误码并关闭连接。
 * 调用前须已连上 WiFi。成功后连接保持，可继续发/收。 */
esp_err_t openp2p_login_once(void);

/* 创建控制面任务：登录 + 心跳保活 + 数据面（4 端口 relay 隧道 + 监听），断开自动重连（独立任务）。 */
void openp2p_start(void);

/* 对等节点池快照（供 80 口网页只读展示，2026-11-18 用户令）。 */
typedef struct {
	char name[48];       /* 节点名（SDWANInfo Nodes[] 剔自身） */
	int  online;         /* 1=在线 0=离线/未查 */
	int  nattype;        /* 1=FullCone(punch通) 2=Symmetric 99=未查 -1=离线 */
	int  ok;             /* 建链成功次数（评分依据） */
	int  fail;           /* 建链失败次数（评分依据） */
	int  active;         /* 1=当前 dial 方（正在使用） */
} p2p_peer_info_t;

int p2p_peer_snapshot(p2p_peer_info_t *out, int max);   /* 填充 peer 池快照，返回填充个数（0=服务器 Nodes[] 未到） */

#endif /* OPENP2P_H */
