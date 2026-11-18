/*
  * 运行时配置仓库（SSID/密码/IP 策略/四口目标改网页可配）。
  * 内存态 g_cfg + NVS 命名空间 "cfg" 持久化；NVS 空/损坏 → config.h 编译期默认
  * （默认档为出厂占位，具体 SSID/密码经网页配置台填，NVS 权威）。
  */
#ifndef CFG_STORE_H
#define CFG_STORE_H

#include "esp_err.h"
#include <stdint.h>

#define CFG_MAX_PROF 8                                  /* SSID 档上限（页固定渲染 8 行，SSID 空=停用） */
#define CFG_SSID_LEN 33                                 /* 对齐 esp_wifi MAX_SSID_LEN(32)+1 */
#define CFG_PASS_LEN 65                                 /* 对齐 MAX_PASSPHRASE_LEN(64)+1 */
#define CFG_IPSTR    16                                 /* "255.255.255.255"+1 */
#define CFG_TOKEN_LEN 40                                /* OpenP2P 登录 token 数字串（现 19 位）+ 余量；NVS 权威，网页可改（2026-11-18 用户令） */

typedef struct {
	char ssid[CFG_SSID_LEN];
	char pass[CFG_PASS_LEN];                            /* 空=开放网络 */
	uint8_t ipmode;                                     /* 0=DHCP 1=STATIC——IP 策略跟着 SSID 走 */
	char ip[CFG_IPSTR];                                 /* STATIC：本机固定 IPv4 */
	char gw[CFG_IPSTR];                                 /* 空=沿用 DHCP 派网关（实测语义） */
	char dns[CFG_IPSTR];                                /* 空=沿用 DHCP 派 DNS；非空=强制覆盖（部分路由器派 0.0.0.0 毒 DNS 的对策） */
} cfg_prof_t;

typedef struct {
	int nprof;                                          /* 在用档数（=非空 ssid 行数，表序=连接优先级） */
	cfg_prof_t prof[CFG_MAX_PROF];
	char dst22[CFG_IPSTR];                              /* 四口映射目标 IP（空=兜底 OPENP2P_APP_DSTIP） */
	char dst3389[CFG_IPSTR];
	char dst8080[CFG_IPSTR];
	char dst11434[CFG_IPSTR];
	char token[CFG_TOKEN_LEN];                          /* OpenP2P 登录 token（NVS 权威，网页可改；空/缺=OPENP2P_TOKEN 编译默认） */
} cfg_t;

extern cfg_t g_cfg;

void cfg_init(void);                                    /* 开机载入 NVS；空/损坏 → config.h 默认 */
esp_err_t cfg_store_commit(const cfg_t *c);             /* 写 NVS 成功才 g_cfg=*c（提交点唯一） */
int cfg_match_profile(const char *ssid);                /* 已关联 SSID → 档下标；无 -1 */

#endif /* CFG_STORE_H */
