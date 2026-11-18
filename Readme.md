# OpenP2P 客户端（ESP32-S3）

在 ESP32-S3 上运行 OpenP2P 客户端，经 SD-WAN 中继隧道把远端主机的 4 个端口映射到本机，本地连对应端口即透传到目标。

## 首次使用：先配置 `main/config.h`

**编译烧录前，必须先编辑 `main/config.h` 填入你自己的值**——本文件是编译期配置，仓库默认全留空，空值对应功能首启不可用。

| 宏 | 必填 | 填什么 |
|----|------|--------|
| `OPENP2P_WIFI_SSID` / `OPENP2P_WIFI_PASS` | 是 | 要连的 WiFi 名称 / 密码 |
| `OPENP2P_TOKEN` | 是 | 你的 OpenP2P 登录 token |
| `OPENP2P_NODE` | 是 | 本节点名（OpenP2P 后台可见/可映射） |
| `OPENP2P_DST_22/3389/8080/11434` 或 `OPENP2P_APP_DSTIP` | 是 | 要映射到目标主机的 IP |
| `OPENP2P_STA_IP` | 否 | 本机固定 IP（留空=DHCP） |
| `OPENP2P_LOG_ON` / `OPENP2P_DIAG_ON` | 否 | 串口日志开关（`0`=静默 release，`1`=全量取证） |

> 不必记牢：编译时 CMake 会自动检测 `config.h` 的关键值是否仍为空，留空则在构建开头醒目提示"先设置 config.h"，并给出两种补法（编辑 config.h 或首启后走 80 口网页配置台）。

## 环境设置

本工程基于 **ESP-IDF v6.1** 构建，目标芯片 **ESP32-S3**。构建前需装齐以下工具：

- **ESP-IDF v6.1**：可用官方 [ESP-IDF 安装程序](https://docs.espressif.com/projects/esp-idf/zh_CN/latest/esp32/get-started/esp-idf-install-guide.html) 一键安装（会自动装齐下方工具链），或手动安装。
- **xtensa 工具链**：`xtensa-esp-elf`（ESP-IDF 安装程序会自动装）。
- **cmake** + **ninja**：构建系统。
- **Python 3.9+**：ESP-IDF 依赖（建议用安装程序创建的独立 venv）。

装好后，把 IDF 加入当前 shell 环境（Windows 用 `export.ps1`，Linux/macOS 用 `export.sh`，都在 `<ESP-IDF 安装目录>/export.*`）。验证：`idf.py version` 能输出版本号即环境就绪。

> 说明：`CMakeLists.txt` / `main/idf_component.yml` 会在首次构建时自动从 Espressif 组件仓库拉取 `esp_websocket_client`、`json`(cJSON) 等依赖，无需手动安装。

## 编译与烧录

环境就绪后，在工程根目录（`CMakeLists.txt` 所在目录）执行：

```
idf.py build                        # 编译
idf.py -p <COM口> flash             # 烧录（<COM口> 换成本机实际串口）
idf.py -p <COM口> monitor           # 串口监控（Ctrl+] 退出）
```

- **查 COM 口**：Windows 用设备管理器看端口号，或用 `esptool.py chip_id` 逐口探测；Linux/macOS 一般是 `/dev/ttyUSB*` 或 `/dev/ttyACM*`。串口波特率 115200。
- **烧录失败提示复位**：手动按一下板子 BOOT 键进入下载模式，或按 RESET 键复位后再 `idf.py flash`。

## 运行时改配置（可选）

板上电连上 WiFi 后，访问 `http://<板子IP>/`（80 口网页配置台）可在线改 SSID/密码/token/目标 IP（敏感值掩码显示），保存即写入 NVS，**优先于 config.h**。页面还实时展示对等节点池与当前 dial 方。

## 主要功能

- **控制面**：WiFi 多 SSID 重连、SNTP 对时、WSS 登录、心跳保活、断线自动重连。
- **动态对端**：从服务器下发节点池（零硬编码），按 NAT 类型 + 成功率自动选 dial 方，失败自动换节点。
- **数据面**：22/3389/8080/11434 四口独立 relay 隧道，隧道级自愈重建。
- **release**：日志编译期可剔除，串口静默。

## 参考的 OpenP2P 客户端版本

本客户端的协议与行为对齐 OpenP2P 官方客户端 **v3.25.11**——二进制协议、relay/直连隧道建链时序、NAT 探测、心跳与退避等，均以官方 Go 实现（`core/` 下的 `protocol.go`、`p2pnetwork.go`、`p2ptunnel.go` 等）为准实现。

- **上报版本**：客户端对外标识为 `3.15.5`（上游 `SupportDualTunnelVersion`），刻意低于 `3.25.1` 的版本门限，使服务器不为其分配"多直连隧道"特性（本端未实现该特性）。
- **对端要求**：对端需为同 OpenP2P 网络中的在线节点；本参考实现验证时，对端节点为 **v3.25.14**。

## 目录

`main/` 业务源码（`config.h` 配置模板 · `openp2p.c` 核心 · `wss.c` · `quic_cli.c` · `wifi.c` · `http_cfg.c` · `cfg_store.c`）；`certs/ca_bundle.pem` 为 WSS 的 TLS 信任锚（公开 CA 根证书）；`build/` 编译产物（不发布）。
