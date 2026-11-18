/*
   * HTTP 网页配置台（80 端口）：WiFi 档表（SSID/密码/DHCP|静态+IP/网关/DNS）+
   * 四口映射目标 IP。手写 HTTP，不引 esp_http_server。
   */
#ifndef HTTP_CFG_H
#define HTTP_CFG_H

void http_cfg_start(void);                    /* 起 hcfg 任务；WiFi 未上也起——连通即达 */

#endif /* HTTP_CFG_H */
