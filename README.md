<div align="center">
<img src="./Elise%20Logo.png" alt="Elise Logo" width="160" />

# Elise 节点后端

**面向生产级的高性能、纯 Rust 异步原生的多协议代理节点服务端**

`Rust 1.80+` &nbsp;•&nbsp; `PolyForm Noncommercial License`

<p>
  原生支持 <b>XBoard</b>、<b>XiaoV2Board</b>、<b>PPanel</b>、<b>V2Board</b>、<b>SSPanel-UIM</b> 等主流面板<br/>
  内置支持 <b>VLESS、VMess、Trojan、Shadowsocks、Shadowsocks 2022、Hysteria 1/2、TUIC V4/V5、AnyTLS、NaiveProxy、Mieru</b> 全协议栈
</p>
</div>

---

## 协议与面板支持矩阵

| 协议类型 | 支持的传输层 / 特性 | TLS / 安全模式 | ECH / uTLS 协同 | 支持的对接面板 |
|---|---|---|---|---|
| **VLESS** | TCP, WebSocket, gRPC, HTTPUpgrade, SplitHTTP(XHTTP) | TLS 1.3, REALITY, Vision | ✅ ECH (服务端解密) / ✅ uTLS 指纹 | XBoard, XiaoV2Board, PPanel, V2Board |
| **VMess** | TCP, WebSocket, gRPC, HTTPUpgrade, SplitHTTP | TLS 1.3, AEAD 强制, Legacy MD5 | ✅ ECH (服务端解密) / ✅ uTLS 指纹 | XBoard, XiaoV2Board, PPanel, V2Board |
| **Trojan** | TCP, WebSocket, gRPC, SplitHTTP | 原生 TLS 1.3, 自签, ACME | ✅ ECH (服务端解密) / ✅ uTLS 指纹 | 全面板 |
| **Shadowsocks** | AEAD (AES-GCM, ChaCha20-Poly1305), 2022 规范, Stream | 单端口多用户, 防探测封禁 | 不适用 (UDP/TCP 纯密文) | 全面板 |
| **ShadowsocksR** | SSR 常用协议与混淆 | 多用户单端口 | 不适用 | SSPanel-UIM, V2Board |
| **Hysteria 1/2** | UDP / QUIC 原生自适应 BBR, 端口跳跃 | 原生 TLS, Salamander 混淆 | 内置 QUIC TLS | XBoard, XiaoV2Board, PPanel |
| **TUIC V4/V5** | UDP / QUIC, 0-RTT 握手, 流控窗口精细化调节 | TLS 1.3, RFC 5705 认证导出 | ✅ ECH 服务端解密 | XBoard, XiaoV2Board, PPanel |
| **AnyTLS** | TCP 原生明文与 TLS 自动识别自适应 | TLS 1.3, 自签, ACME | ✅ ECH (服务端解密) | XBoard, XiaoV2Board |
| **NaiveProxy** | HTTP/2 CONNECT 双向流式填充穿透 | 原生 TLS 1.3 | ✅ ECH (服务端解密) | XBoard, XiaoV2Board |
| **Mieru** | TCP / UDP 双模, TrafficPattern 特征混淆 | 低熵防封锁私有加密 | 不适用 (私有安全协议) | XBoard, XiaoV2Board |
| **SOCKS5 / HTTP** | 纯代理中继, 用户名密码鉴权, UDP ASSOCIATE | 可选前置挂载 TLS / Nginx | 不适用 | 全面板 |

---

## 目录

- [1. 快速安装与运维](#1-快速安装与运维)
  - [1.1 一键脚本安装](#11-一键脚本安装)
  - [1.2 Elise 管理命令体系](#12-elise-管理命令体系)
  - [1.3 面板对接实战示例](#13-面板对接实战示例)
  - [1.4 手动编辑配置文件](#14-手动编辑配置文件)
  - [1.5 Docker 与容器化编排](#15-docker-与容器化编排)
  - [1.6 pprof 性能诊断调试端口](#16-pprof-性能诊断调试端口)
- [2. 三层配置优先级与节点独立配置体系](#2-三层配置优先级与节点独立配置体系)
  - [2.1 架构原理](#21-架构原理)
  - [2.2 主配置文件 elise.conf](#22-主配置文件-eliseconf)
  - [2.3 节点独立配置 (/etc/elise/nodes/node_{id}.conf)](#23-节点独立配置-etcelisenodesnode_idconf)
  - [2.4 可在 [USER] 区生效的参数表](#24-可在-user-区生效的参数表)
  - [2.5 多节点独立配置示例](#25-多节点独立配置示例)
  - [2.6 节点独立 Nginx TLS 卸载 (force_close_ssl)](#26-节点独立-nginx-tls-卸载-force_close_ssl)
  - [2.7 节点独立证书配置示例](#27-节点独立证书配置示例)
  - [2.8 混合协议运行机制](#28-混合协议运行机制)
- [3. 全量配置参数详解](#3-全量配置参数详解)
  - [3.1 核心对接参数](#31-核心对接参数)
  - [3.2 网络监听与多节点策略](#32-网络监听与多节点策略)
  - [3.3 路由、DNS 与出站分流](#33-路由dns-与出站分流)
    - [3.3.1 基础路由与 DNS 参数](#331-基础路由与-dns-参数)
    - [3.3.2 多路由多出口负载均衡体系 (routes.toml)](#332-多路由多出口负载均衡体系-routestoml)
  - [3.4 PROXY Protocol 真实 IP 透传](#34-proxy-protocol-真实-ip-透传)
  - [3.5 TLS、四种证书模式与 ECH / uTLS](#35-tls四种证书模式与-ech--utls)
  - [3.6 用户限速、设备限制与 Redis 增强](#36-用户限速设备限制与-redis-增强)
  - [3.7 审计黑白名单与 Geo 路由数据库](#37-审计黑白名单与-geo-路由数据库)
  - [3.8 监控审计与高级网络安全](#38-监控审计与高级网络安全)
- [4. 生产环境性能基准参考](#4-生产环境性能基准参考)
- [5. 常见问题与排错指南](#5-常见问题与排错指南)
- [开源许可与使用条款](#开源许可与使用条款)

---

# 1. 快速安装与运维

### 1.1 一键脚本安装

Elise 提供了官方一键管理脚本，全面适配 Debian / Ubuntu / CentOS / AlmaLinux / RockyLinux / Alpine 等主流 Linux 发行版：

```bash
# 自动安装或更新最新正式版
bash <(curl -Ls https://raw.githubusercontent.com/Grandova/Elise-Backend/master/scripts/install.sh)

# 安装指定发布版本
bash <(curl -Ls https://raw.githubusercontent.com/Grandova/Elise-Backend/master/scripts/install.sh) v1.0.0

# 安装最新测试版 (Beta)
bash <(curl -Ls https://raw.githubusercontent.com/Grandova/Elise-Backend/master/scripts/install.sh) --beta
```

安装完成后，脚本会自动注册 `elise.service` 系统服务，并创建系统软链接 `/usr/local/bin/elise`，在任意终端输入 `elise` 即可唤出控制台。

---

### 1.2 Elise 管理命令体系

直接在终端执行 `elise` 会进入图形化交互菜单；生产环境推荐直接使用 CLI 子命令操作：

#### 基础管理
| 命令 | 作用 | 示例 / 说明 |
|---|---|---|
| `elise start` | 启动 Elise 代理服务 | 后台守护运行 |
| `elise stop` | 停止 Elise 代理服务 | 优雅终止连接 |
| `elise restart` | 优雅重启服务 | 自动 Flush 未上报流量并重载新二进制 |
| `elise status` | 查看运行状态 | 显示主进程 PID、常驻内存、运行时间 |
| `elise log` | 查看服务日志 | 跟踪日志输出 (`journalctl -u elise -f`) |
| `elise enable` | 设置开机自启 | 注册 systemd 开机服务 |
| `elise disable` | 取消开机自启 | 关闭自动启动 |
| `elise version` | 查看版本信息 | 打印核心与管理脚本版本 |
| `elise help` | 查看命令帮助 | 输出 CLI 参数用法 |

#### 配置与节点
| 命令 | 作用 | 示例 / 说明 |
|---|---|---|
| `elise config` | 查看当前主配置文件 | 打印 `/etc/elise/elise.conf` |
| `elise config k=v ...` | 快速修改配置项 | `elise config node_id=2 check_interval=30` |
| `elise modify` | 交互式修改主配置 | 逐步修改各项连接参数 |
| `elise setup` | 首次配置向导 | 引导填写面板地址、Token 与节点 ID |
| `elise node list` | 查看配置的节点列表 | 列出已接管的所有 node ID |
| `elise node add <ID>` | 向配置追加新节点 | `elise node add 5` |
| `elise node del <ID>` | 从配置删除指定节点 | `elise node del 5` |

#### 多实例管理 (Multi-Instance)
支持单台服务器运行多个完全隔离的 Elise 实例（独立配置文件 `/etc/elise/instance_<N>/` 与服务 `elise@<N>`）：
| 命令 | 作用 | 说明 |
|---|---|---|
| `elise instance list` | 查看多实例状态列表 | 列出所有实例及其运行状态 |
| `elise instance add <N> [k=v]` | 新建并初始化实例 `<N>` | 创建独立配置目录并设置参数 |
| `elise instance setup <N>` | 引导式配置实例 `<N>` | 设定专属面板信息与节点 ID |
| `elise instance start <N>` | 启动实例 `<N>` | `systemctl start elise@<N>` |
| `elise instance stop <N>` | 停止实例 `<N>` | `systemctl stop elise@<N>` |
| `elise instance restart <N>` | 重启实例 `<N>` | 优雅重载指定实例 |
| `elise instance status <N>` | 查看实例 `<N>` 状态 | 显示该实例 PID 与资源占用 |
| `elise instance log <N>` | 实时查看实例 `<N>` 日志 | `journalctl -u elise@<N> -f` |
| `elise instance enable <N>` | 设置实例 `<N>` 开机自启 | 注册 systemd 模板服务 |

#### 证书与 Reality 密钥工具
| 命令 | 作用 | 说明 |
|---|---|---|
| `elise reality` / `elise reality gen` | 生成全新 Reality 密钥对 | 自动生成 x25519 私钥、公钥与 Short ID |
| `elise reality show` | 查看当前节点 Reality 密钥 | 打印公私钥及 Short ID |
| `elise x25519` | 生成标准 x25519 密钥对 | 输出匹配的私钥与公钥 |
| `elise cert` | 证书管理菜单 | 申请、续期、更换证书 |

---

### 1.3 面板对接实战示例

Elise 会在与面板通信后，**自动精准识别节点协议（VLESS、Trojan、SS、Hysteria2、TUIC 等）、端口、TLS 设置与用户列表**，主配置中只需填妥面板类型、地址、通信密钥与节点 ID：

```bash
# XBoard 对接示例 (通用 API)
elise config type=xboard node_id=1 panel_url=https://panel.example.com panel_key=your_token_here

# XiaoV2Board 对接示例
elise config type=xiaov2board node_id=1 panel_url=https://panel.example.com panel_key=your_token_here

# PPanel 对接示例 (panel_key 对应 secret_key)
elise config type=ppanel node_id=1 panel_url=https://panel.example.com panel_key=your_secret_key

# V2board 对接示例 (Legacy API)
elise config type=v2board node_id=2 panel_url=https://v2b.example.com panel_key=v2b_key

# SSPanel-UIM 对接示例
elise config type=sspanel-uim node_id=3 panel_url=https://sspanel.example.com panel_key=uim_key
```

> [!TIP]
> 配置完成后，运行 `elise restart` 即可完成对接启动。节点具体协议完全由面板后台设定驱动，无需在本地配置文件中反复改动协议字段。

---

### 1.4 手动编辑配置文件

主配置文件位于 `/etc/elise/elise.conf`（支持标准 `key = value` 语法）：

```ini
# /etc/elise/elise.conf
type = xboard
panel_url = https://panel.example.com
panel_key = your_secure_api_key
node_id = 1

# 同步与上报周期（秒，最低 10，默认 60）
check_interval = 60
submit_interval = 60

# 监听地址与性能调试端口（留空默认 127.0.0.1:6060，设为 off 可关闭）
listen_addr = 0.0.0.0
pprof_addr = 127.0.0.1:6060
```

---

### 1.5 Docker 与容器化编排

Elise 原生支持多架构容器化运行（`linux/amd64` 与 `linux/arm64`），支持纯环境变量启动，**环境变量优先级高于本地配置文件**：

#### 快捷启动单容器
```bash
docker run -d \
  --name elise \
  --restart always \
  --network host \
  -e type=xboard \
  -e node_id=1 \
  -e panel_url=https://panel.example.com \
  -e panel_key=your_secret_token \
  -e dns_strategy=prefer_ipv4 \
  grandova/elise:latest
```

#### Docker Compose 编排模板 (`docker-compose.yml`)
```yaml
services:
  elise:
    image: grandova/elise:latest
    container_name: elise
    restart: always
    network_mode: host
    environment:
      - type=xboard
      - node_id=1,2
      - panel_url=https://panel.example.com
      - panel_key=your_secret_token
      - dns_strategy=prefer_ipv4
      - auto_tls=true
      - pprof_addr=127.0.0.1:6060
    volumes:
      - /etc/elise:/etc/elise
      - /var/log/elise:/var/log/elise
```

---

### 1.6 pprof 性能诊断调试端口

Elise 内置了标准高性能 HTTP 诊断端点，用于快速定位高并发场景下的协程分布、内存堆栈与连接热点：

- **默认端口**：`127.0.0.1:6060`；
- **智能防冲突**：若默认端口被占用，Elise 会自动切换到本地可用端口并输出告警日志，**绝对不影响核心业务代理服务的监听**；
- **开关配置**：
  ```ini
  pprof_addr = 127.0.0.1:6060   # 自定义端口
  pprof_addr = off               # 彻底关闭诊断接口
  ```
- **端点列表**：
  - `http://127.0.0.1:6060/debug/pprof/`：诊断控制台首页
  - `http://127.0.0.1:6060/debug/pprof/heap`：内存分配与堆栈采样
  - `http://127.0.0.1:6060/debug/stats`：实时连接与吞吐量监控

---

# 2. 三层配置优先级与节点独立配置体系

### 2.1 架构原理

Elise 采用严密的三层配置体系，确保多节点与复杂网络环境下的确定性运行：

```mermaid
graph TD
    Panel[第 1 层：面板 API 下发数据<br/>最高优先级] -->|下发协议、主端口、TLS/Reality、流控与用户列表| Core(NodeRunner 节点核心管线)
    NodeConf[第 2 层：节点独立配置 node_ID.conf [USER]<br/>中优先级] -->|覆盖独立监听IP、独立证书、Proxy Protocol、分流| Core
    GlobalConf[第 3 层：主配置文件 elise.conf<br/>基础优先级] -->|提供全局共享面板参数、路由文件路径、全局默认行为| Core
    Core --> Inbound[多协议并发接入管线]
    Inbound --> Limiter[并发控制 & 设备去重]
    Limiter --> Router[内置 GeoIP/GeoSite 智能路由]
    Router --> Outbound[Direct 直连 / Block 阻断 / SOCKS5 出站]
```

---

### 2.2 主配置文件 `elise.conf`

路径：`/etc/elise/elise.conf`  
所有节点共享的全局基础配置，定义面板地址、通信密钥、轮询间隔以及未单独覆盖参数的默认全局回退值。

---

### 2.3 节点独立配置 (`/etc/elise/nodes/node_{id}.conf`)

当服务启动并成功与面板建立同步后，会在 `/etc/elise/nodes/` 目录下自动维护各节点的独立配置 `node_{id}.conf`。文件分为两个清晰区域：

- **`[AUTO]` 区**：每次同步自动重写，展示面板当前下发的协议、端口、证书配置等，**仅供状态查阅，请勿手动编辑**；
- **`[USER]` 区**：**用户自定义的节点级覆盖参数**。在此写入的参数在服务重启、面板规则更新后**永久保留**，且优先级高于全局 `elise.conf`。

---

### 2.4 可在 `[USER]` 区生效的参数表

| 参数名 | 默认值 | 说明 |
|---|---|---|
| `listen_addr` | 无 | 节点独立监听 IP（支持多 IP 服务器为该节点独占绑定指定外网 IP） |
| `port_offset` | `0` | 端口偏移量（实际监听端口 = 面板端口 + 偏移量） |
| `proxy_protocol` | `false` | 独立启用 TCP PROXY Protocol v1/v2 解析（TCP / Mieru TCP 可用） |
| `udp_proxy_protocol`| `false` | 独立接收 UDP PROXY Protocol v2 报头（SS / Mieru UDP 可用） |
| `force_proxy_protocol`| `false` | 强制代理协议头校验（未带协议头的直连流量直接丢弃） |
| `force_close_ssl` | `false` | 关闭 Elise 原生 TLS 处理（前端挂载 Nginx/Caddy 进行 TLS 卸载时使用） |
| `cert_file` | 无 | 节点专属自定义证书公钥路径 (`.crt` / `.pem`) |
| `key_file` | 无 | 节点专属自定义证书私钥路径 (`.key`) |
| `cert_domain` | 无 | 节点专属证书域名 |
| `cert_mode` | 无 | 证书模式：`http` / `dns` / `self` / `none` |
| `cert_key_length` | 无 | 私钥类型：推荐填写 `ec-256` 或 `ec-384` |
| `acme_server` | `letsencrypt` | ACME CA 服务商：`letsencrypt`、`zerossl` 或自定义 URL |
| `dns_provider` | 无 | 专属 DNS 验证提供商代号（仅 `cert_mode=dns` 时使用） |
| `reality_private_key`| 无 | 节点专属 VLESS Reality 私钥（覆盖面板下发私钥） |
| `tuic_ech_server_keys`| 无 | 专属 TUIC / TLS ECH 服务端 keyset (Base64 编码) |
| `check_interval` | `60` | 该节点独立的用户与状态轮询周期（秒） |
| `submit_interval` | `60` | 该节点独立的流量上报周期（秒） |
| `domain_audit_enable` | `false` | 该节点独立的域名/IP 访问审计开关 |
| `domain_audit_domains`| 空 | 该节点独立的关注域名或 IP 目标（逗号分隔） |
| `domain_audit_log_dir`| 空 | 该节点独立的审计 JSONL 保存目录 |
| `tuic_initial_stream_window` | `2` | TUIC 单 Stream 初始接收窗口（MB） |
| `tuic_max_stream_window` | `6` | TUIC 单 Stream 最大接收窗口（MB） |
| `tuic_initial_conn_window` | `3` | TUIC 单 Connection 初始接收窗口（MB） |
| `tuic_max_conn_window` | `15` | TUIC 单 Connection 最大接收窗口（MB） |

---

### 2.5 多节点独立配置示例

**实战场景**：主配置 `elise.conf` 中接管了 3 个节点（`node_id = 250,251,252`）：

```ini
# /etc/elise/elise.conf
type = xboard
node_id = 250,251,252
proxy_protocol = false
check_interval = 60
```

针对各节点独立配置进行精细化覆盖：

1. `/etc/elise/nodes/node_250.conf` 的 `[USER]` 区：
   ```ini
   [USER]
   proxy_protocol = true
   udp_proxy_protocol = true
   check_interval = 30
   ```
2. `/etc/elise/nodes/node_251.conf` 的 `[USER]` 区（多 IP 独立外网网卡绑定）：
   ```ini
   [USER]
   listen_addr = 198.51.100.2
   ```
3. `/etc/elise/nodes/node_252.conf` 的 `[USER]` 区保持为空，全量沿用全局默认值。

**运行效果**：
- **节点 250**：开启 Proxy Protocol 且以 30 秒高频轮询；
- **节点 251**：独占绑定 `198.51.100.2` 外网 IP；
- **节点 252**：遵循 `elise.conf` 全局配置。

---

### 2.6 节点独立 Nginx TLS 卸载 (`force_close_ssl`)

**实战场景**：节点 300 前端挂载 Nginx 统一监听 443 并卸载 TLS，向后端反向代理明文流量；其它节点正常由 Elise 原生承载 TLS：

在 `/etc/elise/nodes/node_300.conf` 的 `[USER]` 区配置：
```ini
[USER]
force_close_ssl = true
```

> [!NOTE]
> `force_close_ssl` 适用于基于 TCP 的协议（VMess / VLESS / Trojan / AnyTLS / NaiveProxy）。对于 QUIC 协议（Hysteria / TUIC），由于 QUIC 协议内置强制 TLS 握手加密，因此无法进行外部四层明文卸载。

---

### 2.7 节点独立证书配置示例

在 `/etc/elise/nodes/node_401.conf` 的 `[USER]` 区配置：
```ini
[USER]
cert_domain = node401.yourdomain.com
cert_mode = http
cert_key_length = ec-256
acme_server = zerossl
```

若使用外部签发好的商业证书：
```ini
[USER]
cert_mode = none
cert_file = /etc/ssl/my_cert.crt
key_file = /etc/ssl/my_cert.key
```

---

### 2.8 混合协议运行机制

Elise 具备完全的混合协议并发托管能力。单进程内可以同时承载不同协议的节点，底层 Inbound 工厂会根据面板下发的数据精准分发，彼此互不干扰，零额外进程开销。

---

# 3. 全量配置参数详解

### 3.1 核心对接参数

| 参数名 | 默认值 | 允许值 / 说明 |
|---|---|---|
| `panel_type` / `type` | `xboard` | 面板类型：`xboard` / `xiaov2board` / `ppanel` / `v2board` / `sspanel-uim` |
| `api_host` / `panel_url` | 必填 | 面板 WebAPI 接口根地址（如 `https://panel.example.com`，末尾无需加斜杠） |
| `api_key` / `panel_key` | 必填 | 面板通信 Token 密钥（对应 PPanel 的 `secret_key`） |
| `node_id` / `node_ids` | `1` | 接管的节点 ID，多节点使用英文逗号分隔（如 `1,2,3`） |
| `node_sync_interval` / `check_interval` | `60` | 从面板拉取节点配置与用户列表的周期（秒，最低 10） |
| `node_report_interval` / `submit_interval` | `60` | 向上报送流量与在线设备列表的周期（秒，最低 10） |

---

### 3.2 网络监听与多节点策略

| 参数名 | 默认值 | 说明 |
|---|---|---|
| `listen_addr` / `listen` | `0.0.0.0` | 监听 IP；留空或 `0.0.0.0` 为通配监听；支持填写单个 IPv4/IPv6 或逗号分隔的多 IP 列表 |
| `listen_strategy` / `multi_node_listen_strategy` | `auto` | 多节点端口冲突分配策略：`auto`（智能分组偏移）、`shared`（Linux SO_REUSEPORT 共享监听）、`split`（严格报错分离） |
| `tcp_timeout` | `300` | TCP 空闲连接保持超时时间（秒） |
| `udp_timeout` | `300` | UDP 关联会话空闲老化超时时间（秒） |
| `mptcp` | `false` | 是否启用 Linux 原生多路径 TCP（MPTCP）支持 |

---

### 3.3 路由、DNS 与出站分流

#### 3.3.1 基础路由与 DNS 参数

| 参数名 | 默认值 | 说明 |
|---|---|---|
| `routes_file` | `/etc/elise/routes.toml` | 动态路由分流规则文件路径（文件改动 10 秒内热重载） |
| `dns_file` | `/etc/elise/dns.yml` | 独立 DNS 解析器分流规则文件路径 |
| `default_dns` | 无 | 上游默认 DNS 解析器地址（支持 `udp://8.8.8.8:53`、`tcp://`、`https://dns.google/dns-query`） |
| `dns_strategy` | `prefer_ipv4` | 出站解析偏好策略：`prefer_ipv4`（推荐）/ `prefer_ipv6` / `ipv4_only` / `ipv6_only` |
| `dns_cache_time` | `10` | 本地 DNS 结果缓存时长（分钟） |
| `out_ip_ipv4` | 无 | 指定直连出站的源 IPv4 地址（留空由 OS 自动选择路由） |
| `out_ip_ipv6` | 无 | 指定直连出站的源 IPv6 地址 |
| `auto_out_ip` | `false` | **源进源出**：出站连接强制绑定入站连接时的本地 IP（多 IP 独立出口服务器必备） |

---

#### 3.3.2 多路由多出口负载均衡体系 (`routes.toml`)

Elise 原生内置完整的 `routes.toml` 路由分流与多出口负载均衡引擎，用于将入口节点接收到的用户流量，按规则精准转发到不同的代理出口。

```
客户端 -> Elise 入口节点 (配置 routes.toml) -> 代理出口节点 (Direct / Redirect / SOCKS5 / HTTP) -> 目标网络
```

> [!NOTE]
> **生效边界**：`routes.toml` 仅作用于 Elise 节点接收到的代理用户流量，**不会改写整台宿主服务器系统的全局网络路由**（服务器本机的 `curl`、`apt`、Docker 容器等流量保持原有系统路由不变）。

##### 1. 配置文件加载机制与优先级
1. **启动参数指定**：`elise run -r /path/to/routes.toml`（最高优先级）
2. **全局主配置指定**：`elise.conf` 中配置 `routes_file = /path/to/routes.toml`
3. **默认回退路径**：若均未显式指定，默认加载与 `elise.conf` 同目录下的 `routes.toml`（或 `/etc/elise/routes.toml`）
4. **10 秒自动热重载**：修改本地 `routes.toml` 时，Elise 会每 10 秒自动检测文件时间戳并动态重载规则，**无需重启进程**，新规则载入后毫秒级生效；
5. **面板路由协同机制**：对于对接 XBoard / XiaoV2Board 面板下发的运行时路由（`routes` / `custom_outbounds`），Elise 遵循**面板路由优先**原则；若流量未命中面板路由，则继续匹配本地 `routes.toml`；若本地未配置或未命中且面板无默认出口，最终执行 `direct` 直连兜底。

##### 2. 匹配规则语法 (`rules = [...]`)
每个 `[[routes]]` 区块支持定义一组匹配规则，满足**任意一条**即判定命中：

| 规则前缀 | 示例 | 说明 |
|---|---|---|
| `geosite:` | `"geosite:netflix"`, `"geosite:cn"` | 匹配 Loyalsoldier `geosite.dat` 分类规则 |
| `geoip:` | `"geoip:cn"`, `"geoip:private"` | 匹配 Loyalsoldier `geoip.dat` 国家与内网网段规则 |
| `domain:` | `"domain:google.com"` | 匹配域名后缀（如 `www.google.com` 与 `google.com` 均命中） |
| `domain-keyword:` | `"domain-keyword:telegram"` | 域名关键字子串匹配 |
| `full:` | `"full:api.openai.com"` | 域名全匹配（必须完全一致） |
| `regexp:` | `"regexp:^.*\\.edu\\.cn$"` | 正则表达式匹配目标域名 |
| `ip:` | `"ip:1.2.3.4/24"`, `"ip:8.8.8.8"` | 匹配目标单 IP 或 CIDR 网段 |
| `port:` | `"port:80,443"`, `"port:1000-2000"` | 匹配目标单端口或端口范围 |
| `node_id:` | `"node_id:1,2,3"` | **按入口节点 ID 分流**（单进程多节点模式下区分不同节点） |
| `network:` | `"network:tcp"`, `"network:udp"` | 过滤传输协议类型 |
| `*` | `"*"` | 通配规则（通常放在最后一条 `[[routes]]` 作为全量兜底） |

##### 3. 支持的代理出口类型 (`[[routes.Outs]]`)

| 出口类型 | 参数字段 | 说明 |
|---|---|---|
| `direct` | `listen=""` | 直连目标网络，支持绑定指定出口网卡 IP，支持多 IP 源进源出与 PROXY Protocol 透传 |
| `redirect` | `server="1.2.3.4"`, `port=8080` | 地址与端口重定向；若 `port=0` 则保持用户原本访问的端口 |
| `socks` / `socks5`| `server`, `port`, `username`, `password` | 转发至上游 SOCKS5 代理，支持无密或用户密码认证，支持 TCP 与 UDP ASSOCIATE |
| `http` | `server`, `port`, `username`, `password` | 转发至上游 HTTP CONNECT 代理，支持 Basic 认证（仅限 TCP） |
| `block` / `reject`| 无 | 阻断并立即断开连接（如拦截黑名单、BT 下载端口等） |

##### 4. 多出口随机负载均衡原理
当在同一个 `[[routes]]` 规则下方配置了多个 `[[routes.Outs]]` 出口时：
- Elise 内部会自动采用 **真随机负载均衡（Random Load Balancing）** 算法，每次新连接建立时从中随机选择一个出口；
- 该机制可用于多个同构/异构出口代理之间的流量平摊与中继分流（非冷备主备切换）。

##### 5. 典型配置实战示例

**示例一：单个节点，按域名与地理区域分流到不同出口**
```toml
# /etc/elise/routes.toml
enable = true

# 规则 1：流媒体 Netflix 走专线 SOCKS5 出口
[[routes]]
rules = ["geosite:netflix"]
[[routes.Outs]]
type = "socks"
server = "us-proxy.example.com"
port = 1080
username = "myuser"
password = "mypassword"

# 规则 2：Google 与 Telegram 流量走专用中继
[[routes]]
rules = ["geosite:telegram", "domain:google.com"]
[[routes.Outs]]
type = "socks"
server = "sg-proxy.example.com"
port = 1080

# 规则 3：通配兜底全量直连
[[routes]]
rules = ["*"]
[[routes.Outs]]
type = "direct"
```

**示例二：一个节点，多个出口多路随机负载均衡**
```toml
# /etc/elise/routes.toml
enable = true

[[routes]]
rules = ["*"]

# 在同一个路由下配置多个出口，Elise 会随机分配流量
[[routes.Outs]]
type = "socks"
server = "hk-exit-1.example.com"
port = 1080

[[routes.Outs]]
type = "socks"
server = "hk-exit-2.example.com"
port = 1080

[[routes.Outs]]
type = "socks"
server = "hk-exit-3.example.com"
port = 1080
```

**示例三：单进程承载多个面板节点，各自绑定独立出口**
当 `elise.conf` 中配置了 `node_id = 1,2,3` 且运行在同一台服务器时，可通过 `node_id:` 实现各节点出口完全隔离：
```toml
# /etc/elise/routes.toml
enable = true

# 节点 1 流量全部转发至 SOCKS5 出口 A
[[routes]]
rules = ["node_id:1"]
[[routes.Outs]]
type = "socks"
server = "out-node1.example.com"
port = 1080

# 节点 2 流量全部转发至 HTTP CONNECT 出口 B
[[routes]]
rules = ["node_id:2"]
[[routes.Outs]]
type = "http"
server = "out-node2.example.com"
port = 8080

# 节点 3 流量全部走本地网卡直连
[[routes]]
rules = ["node_id:3"]
[[routes.Outs]]
type = "direct"
```

> [!WARNING]
> **同机回环死循环安全避坑（Loopback Deadlock Prevention）**：  
> 如果**入口节点**与**出口目标**部署在**同一台机器**上（或指向了 `127.0.0.1` / 本机绑定的公网 IP），**出口端口绝不能配置为入口节点自身的监听端口**！  
> 否则会导致：客户端连接入口 -> 路由出站将流量再次发给自己 -> 形成无限递归嵌套循环，迅速耗尽系统的文件描述符与连接池。请务必确认出口目标端口与入口监听端口彼此独立。

---

### 3.4 PROXY Protocol 真实 IP 透传

当 Elise 位于前置 CDN、负载均衡器或 HAProxy 之后时，可启用 PROXY Protocol 提取客户端真实原始 IP：

| 参数名 | 默认值 | 说明 |
|---|---|---|
| `proxy_protocol` | `false` | 是否接收入站 TCP PROXY Protocol v1/v2 报头（可设 `true`、`false` 或 `auto`） |
| `udp_proxy_protocol` | `false` | 是否开启入站 UDP PROXY Protocol v2 DGRAM 报头解析 |
| `force_proxy_protocol` | `false` | 强制代理协议校验；未携带有效代理协议头的请求将被直接断开 |
| `trusted_proxies` | 无 | 信任的前置代理 CIDR 白名单（逗号分隔，如 `127.0.0.1/32,10.0.0.0/8`） |

---

### 3.5 TLS、四种证书模式与 ECH / uTLS

#### 3.5.1 四种基础证书模式
Elise 内置原生 TLS 引擎与自签证书自动签发器：

```ini
# 模式 ①：使用自定义商业证书路径
cert_file = /etc/ssl/certs/fullchain.pem
key_file = /etc/ssl/private/privkey.pem

# 模式 ②：HTTP 80 端口 ACME 自动申请 (Let's Encrypt / ZeroSSL)
cert_domain = node.yourdomain.com
cert_mode = http
cert_key_length = ec-256
acme_server = letsencrypt

# 模式 ③：DNS 验证 ACME 自动申请 (支持 Cloudflare 等 100+ 提供商)
cert_domain = node.yourdomain.com
cert_mode = dns
dns_provider = dns_cf
DNS_CF_Email = admin@example.com
DNS_CF_Key = your_cloudflare_global_api_key

# 模式 ④：零配置自动自签证书 (auto_tls = true)
auto_tls = true
fake_sni = www.microsoft.com
```

#### 3.5.2 ECH (Encrypted Client Hello) 原生抗探测解密
Elise 服务端原生支持 RFC draft-18 (0xfe0d) 规范的 **ECH 握手解密**，用于彻底消除 TLS 握手阶段明文 SNI 泄露问题：

- **状态与密钥获取**：**由面板 API 动态下发**。当面板在节点的 `tls_settings` 中启用了 ECH 时，Elise 会自动加载服务端私钥并完成握手解密：
  - `enabled`：是否激活 ECH；
  - `server_keys` / `key`：服务端用于解密 Outer ClientHello 的 Base64 编码私钥；
  - `config` / `config_list`：供客户端订阅使用的 ECHConfigList 字节；
  - `query_server_name`：客户端通过 DoH 解析 ECH 公钥的目标域名。
- **Fail-Fast 安全机制**：如果面板配置了开启 ECH 但未下发对应的服务端私钥，Elise 会主动拒绝非法配置，防止由于私钥缺失导致握手静默降级为明文 SNI。
- **节点级覆盖**：支持在 `/etc/elise/nodes/node_{id}.conf` 的 `[USER]` 区中配置 `tuic_ech_server_keys` 显式注入节点专属 ECH 密钥。

#### 3.5.3 uTLS 客户端指纹与订阅协同
- **指纹获取与解析**：Elise 服务端从面板 API（`node_info.utls`）自动同步节点指纹配置，支持完整指纹枚举：
  - `chrome`、`firefox`、`safari`、`ios`、`android`、`edge`、`qq`、`360`、`random`、`randomized`。
- **工作机制**：uTLS 指纹是针对客户端出站 ClientHello 握手报文的伪装特征。面板通过订阅将该指纹下发给客户端（Clash Meta / Sing-box / Xray 等），Elise 服务端在内部 `ClientTlsProfile` 中进行严格隔离与对齐，并确保出站链式转发具有一致特征。

---

### 3.6 用户限速、设备限制与 Redis 增强

#### 3.6.1 速率与并发连接限制
| 参数名 | 默认值 | 说明 |
|---|---|---|
| `user_speed_limit` | `0` | 用户限速（Mbps，0 表示由面板下发值决定；若大于 0 则与面板值取较小者严格生效） |
| `node_speed_limit` | `0` | 节点总带宽上限（Mbps，0 表示不限速） |
| `user_tcp_limit` | `0` | 单用户最大允许并发 TCP 流数（0 表示不限） |
| `user_conn_limit` | `0` | 单用户最大并发连接 / 在线 IP 数限制 |

#### 3.6.2 在线设备限制与 Redis 集群去重
通过滑动窗口算法精准统计并限制每个用户的同时在线设备数，支持单机内存统计与多节点 Redis 跨机集群同步：

| 参数名 | 默认值 | 说明 |
|---|---|---|
| `device_limit_window` | `300` | 设备活跃滑动窗口时长（秒，默认 5 分钟） |
| `device_limit_prefix_ipv4` | `32` | IPv4 子网聚合掩码（默认 32 单 IP 单设备；设为 24 则同一 /24 网段视作同设备） |
| `device_limit_prefix_ipv6` | `64` | IPv6 子网聚合掩码（默认 /64 网段） |
| `redis_enable` | `false` | 是否开启 Redis 分布式设备跨节点去重 |
| `redis_addr` | 无 | Redis 连接地址（如 `127.0.0.1:6379` 或 `redis://...`） |
| `redis_password` | 无 | Redis 认证密码 |
| `redis_db` | `0` | Redis 数据库索引号 |
| `conn_limit_expiry` | `60` | Redis 在线设备记录键的过期刷新时间（秒） |
| `redis_timeout_ms` | `300` | Redis 响应超时时间（毫秒） |

> [!TIP]
> **自动故障降级**：若 Redis 发生瞬时网络闪断或超时，Elise 会自动切换至单机内存限制模式，**绝对不会阻断正常用户的连接建立**。

#### 3.6.3 在线 IP 磁盘持久化缓存
```ini
ip_user_cache_time = 1             # 缓存保留时长（小时）
ip_user_cache_save_enable = true   # 开启定时持久化
ip_user_cache_save_dir = /etc/elise/ # 缓存持久化目录
```
服务重启时自动加载历史在线 IP 状态，防止服务重启瞬间造成设备数重置与误杀。

---

### 3.7 审计黑白名单与 Geo 路由数据库

#### 3.7.1 审计黑名单 (`blockList`) 与白名单 (`whiteList`)
- **黑名单**：支持域名后缀、IP CIDR 网段、目标端口范围过滤，支持从远程 URL 定期拉取（`block_list_url`）；
- **白名单**：**白名单规则享有绝对优先放行权**，命中白名单时跳过所有审计阻断；
- **秒级热重载**：修改本地 `/etc/elise/blockList` 或 `/etc/elise/whiteList`，**10 秒内自动检测并热生效**。

#### 3.7.2 GeoIP 与 GeoSite 数据库
Elise 内置原生高效二进制 dat 解析器（单次匹配仅耗时微秒级），按以下优先序自动检测加载：
1. 配置文件显式指定的 `geoip_file` 与 `geosite_file`；
2. `/etc/elise/geoip.dat` 与 `/etc/elise/geosite.dat`；
3. 程序当前目录 `./geoip.dat` 与 `./geosite.dat`；
4. 系统公共目录 `/usr/local/share/elise/geoip.dat`。

在 `routes.toml` 与 `blockList` 中支持直接使用标签语法：
```toml
[[rules]]
outbound = "direct"
geoip = ["cn", "private"]

[[rules]]
outbound = "block"
geosite = ["category-ads-all"]
```

---

### 3.8 监控审计与高级网络安全

#### 3.8.1 系统日志与结构化审计日志
```ini
log_level = info                   # debug, info, warn, error, none
log_file = /var/log/elise/elise.log    # 留空输出至 stdout / journal
log_retention_days = 7             # 日志保留天数
log_max_size_mb = 100              # 单文件切分大小 (MB)

audit_log_file = /var/log/elise/audit.log # 结构化审计日志文件
```

每当代理连接建立与关闭时，以标准 **JSON Lines (JSONL)** 格式无锁异步追加记录：
```json
{
  "time": "2026-09-18T16:00:00.123Z",
  "node_id": 1,
  "user_id": 108,
  "protocol": "vless",
  "network": "tcp",
  "client_ip": "1.2.3.4",
  "target_host": "example.com",
  "target_port": 443,
  "upload_bytes": 1042,
  "download_bytes": 15820,
  "duration_ms": 320,
  "outbound": "direct",
  "status": "connected"
}
```

#### 3.8.2 高级网络安全与防扫描控制
| 参数名 | 默认值 | 说明 |
|---|---|---|
| `domain_sniff` | `true` | 首包域名嗅探：当客户端直接发起目标 IP 连接时，从 TLS ClientHello (SNI) 或 HTTP Host 中嗅探原始域名用于精准路由和审计 |
| `sniff_redirect` | `false` | 嗅探出真实域名后，强制使用本地/面板 DNS 重新解析目标 IP 出站 |
| `forbidden_ports` | 无 | 全局禁止代理的敏感端口（如 `25,465,587,6881-6889` 封禁垃圾邮件与 BT） |
| `forbidden_bit_torrent` | `true` | 是否启用内置 BitTorrent / P2P 特征流量阻断 |
| `ban_private_ip` | `false` | 是否禁止代理出站访问私有内网 IP（防止 SSRF 攻击） |
| `submit_traffic_min_traffic` | `0` | 流量上报缓冲阈值（KB），低于此阈值的微小流量在本地缓存累计，减少面板 API 请求压力 |

#### 3.8.3 协议专有安全防爆破机制
- **Shadowsocks 单端口多用户并发解密与防暴力破解**：
  ```ini
  ss_decrypt_concurrency = 8            # 多用户单端口并发解密线程数
  ss_invalid_access_enable = true        # 开启非法探测 IP 自动封锁
  ss_invalid_access_count = 30           # 连续失败 30 次触发封锁
  ss_invalid_access_duration = 60        # 统计时间窗口（秒）
  ss_invalid_access_forbidden_time = 600 # 封禁时长（秒）
  ```
- **VMess AEAD 强制与抗重放防探测**：
  ```ini
  force_vmess_aead = false               # 强制客户端使用 AEAD 头部（拒绝不安全的旧版 MD5 认证）
  force_vmess_md5 = false                # 强制允许旧版 MD5 兼容模式
  vmess_aead_invalid_access_enable = true # 开启探测 IP 自动封禁
  vmess_aead_invalid_access_count = 30   # 连续失败阈值
  vmess_aead_invalid_access_duration = 60 # 统计窗口（秒）
  vmess_aead_invalid_access_forbidden_time = 600 # 封禁时长（秒）
  ```

---

# 4. 生产环境性能基准参考

基于 Linux 真实云服务器（2 vCPU, Debian 13 / Linux 6.12 内核）实机全量压测基准数据：

| 压测指标 | 500 人在册用户 / 10,000 TCP 并发 | 1,000 人在册用户 / 10,000 TCP 并发 | 备注 |
|---|---|---|---|
| **空载基线物理内存 (RSS)** | **8.75 MB** | **10.95 MB** | 极小初始内存开销 |
| **10,000 并发长连接常驻内存 (RSS)** | **119.82 MB** | **109.33 MB** | **单连接净物理开销仅 ~10~11 KB** |
| **峰值最高水位内存 (VmHWM)** | 246.43 MB | 264.68 MB | 包含瞬时缓冲区峰值 |
| **静默保活 CPU 占用 (Keep-Alive)** | **0.0% ~ 0.3%** | **0.0% ~ 0.3%** | 原生 epoll 边缘触发驱动，无无效轮询 |
| **活跃全量数据中继 CPU 占用 (Active)**| 4.6% (峰值 8.3%~10.7%) | 4.6% (峰值 8.3%~10.7%) | 零拷贝双向异步 IO 中继 |
| **打开系统句柄 (FDs)** | 20,124 | 20,124 | 1w 入站 + 1w 出站 + 124 系统基础句柄，**零句柄泄漏** |
| **100MB 真实通量大文件传输** | SHA-256 全量精确匹配 | SHA-256 全量精确匹配 | PCAP 抓包零二进制明文泄露 |

---

# 5. 常见问题与排错指南

### Q1: 大并发场景下出现 `Too many open files` 错误？
系统默认的文件描述符（ulimit）限制过低。请在 `/etc/security/limits.conf` 中追加以下调优配置：
```ini
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
```

### Q2: 高并发或小内存服务器推荐的网络内核调优？
编辑 `/etc/sysctl.conf` 并执行 `sysctl -p`：
```ini
# 提高系统并发半连接与全连接队列深度
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# 调整 socket 缓冲区以在高并发长连接下显著节省物理内存
net.ipv4.tcp_rmem = 4096 87380 4194304
net.ipv4.tcp_wmem = 4096 65536 4194304

# 扩大本地可用出站端口范围
net.ipv4.ip_local_port_range = 10240 65535

# 开启 TCP 连接快速回收与复用
net.ipv4.tcp_tw_reuse = 1
```

### Q3: 端口被占用导致启动失败？
查看占用端口的具体进程：
```bash
lsof -i :443   # 或 netstat -tlpn | grep 443
```
若需要前端挂载 Nginx 并共用 443 端口，可开启 `force_close_ssl = true`，并将 Elise 的监听端口偏移或配置为其它本地端口（如 8443）。

---

## 开源许可与使用条款

本项目遵循 [PolyForm Noncommercial License 1.0.0](LICENSE) 开源发布。

- **非商业用途**：个人学习、研究及非盈利场景可免费自由使用、修改与分发本软件；
- **商业用途限制**：严禁将本软件用于任何直接或间接产生财务收益、商业营运或商业托管服务。
