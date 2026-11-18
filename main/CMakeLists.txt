# OpenP2P ESP32-S3 客户端 —— 组件注册
#
# 骨架 + 配置 + 控制面（手写 WSS 登录/心跳）。
# 证书 bundle 通过 EMBED_TXTFILES 内嵌，供 TLS CA 校验（wss.c 里 extern 引用）。
#
# 组件名以 ESP-IDF v6.1 实测为准：
#   - TLS = "esp-tls"（连字符），日志 = "log"（非 esp_tls / esp_log）。
#   - 手写 WSS 直接用 mbedTLS（net/ssl/sha1/base64），无需 esp_websocket_client。
#   - esp_fill_random 来自 esp_system（硬件 RNG，生成 WS mask / key）。
idf_component_register(
    SRCS "app_main.c" "wifi.c" "wss.c" "openp2p.c" "quic_cli.c" "cfg_store.c" "http_cfg.c"
    INCLUDE_DIRS "." "p2p"
    EMBED_TXTFILES "../certs/ca_bundle.pem"
    REQUIRES
        esp_wifi
        esp_netif
        esp_event
        esp-tls
        mbedtls
        nvs_flash
        lwip
        esp_system
        esp_common
        log
        esp_timer
)
