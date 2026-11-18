/*
  * 日志编译期总开关（用户 2026-11-07 令：预定义开关选择是否编译所有日志）。
  * config.h OPENP2P_LOG_ON=0 时：本文件把 esp_log.h 的 ESP_LOGI/W/E/D/V 五个宏
  * undef 后重定义为空语句——调用整体从编译单元消失：无函数调用、格式字符串不入
  * 镜像（rodata 由 gc-sections 整段回收），不是运行时静音。=1 时原样透传，行为与
  * ESP-IDF 原生一致（取证编译，串口全量输出）。
  * 用法：各 .c 在 #include "esp_log.h" 之后 #include "oplog.h"（必须后置，否则被
  * esp_log.h 重定义回去）。ESP_ERROR_CHECK/abort/panic 走 esp_log_write API 非此
  * 宏，不受影响（abort 行为保留）。
  * 空宏里 (void)(tag) 只为让 TAG 变量保持"被引用"免 -Wunused-variable；纯读取，
  * 死代码消除后零代码。已核查：全工程无 ESP_LOGx 实参带副作用（++/赋值均在调用外）。
  */
#ifndef OPLOG_H
#define OPLOG_H

#include "config.h"

#if !OPENP2P_LOG_ON
#undef ESP_LOGI
#undef ESP_LOGW
#undef ESP_LOGE
#undef ESP_LOGD
#undef ESP_LOGV
#define ESP_LOGI(tag, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, ...) do { (void)(tag); } while (0)
#define ESP_LOGE(tag, ...) do { (void)(tag); } while (0)
#define ESP_LOGD(tag, ...) do { (void)(tag); } while (0)
#define ESP_LOGV(tag, ...) do { (void)(tag); } while (0)
#endif

#endif /* OPLOG_H */
