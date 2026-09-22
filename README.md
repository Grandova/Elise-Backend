<div align="center">
<img src="./Elise%20Logo.png" alt="Elise Logo" width="160" />




# Elise 节点后端

**Rust 异步多协议代理节点后端 · 面板对接 · 套餐限速 · 路由与流量上报**

`Rust stable` &nbsp;•&nbsp; `PolyForm Noncommercial License`

<p>
  提供 <b>测试基于Xboard 详细支持请查看 [支持协议测试查看](https://github.com/Grandova/Elise-Backend/blob/main/Support%20protocol.md)</b><br><b><strong>以西面板支持需自行测试 <strong></strong>XiaoV2Board</b>、<b>PPanel</b>、<b>V2Board</b>、<b>SSPanel-UIM</b> 等主流面板<br/>
  协议实现涵盖 <b>VLESS、VMess、Trojan、Shadowsocks、Shadowsocks 2022、Hysteria2、AnyTLS、Mieru</b>
</p>



</div>

---

<a id="section-1"></a>

# 1. 快速安装与运维

<a id="section-1-1"></a>

### 1.1 一键脚本安装

安装脚本面向 Linux amd64 / arm64，需要 root、Bash、curl、python3、CA 证书及运行中的 systemd 或 OpenRC。Debian / Ubuntu / CentOS / AlmaLinux / RockyLinux / Alpine 等环境仍需确认发布包的 libc 与系统版本匹配。

```bash
# 自动安装或更新最新正式版
bash <(curl -fsSL https://raw.githubusercontent.com/Grandova/Elise-Backend/main/scripts/install.sh)

# 安装指定发布版本
bash <(curl -fsSL https://raw.githubusercontent.com/Grandova/Elise-Backend/main/scripts/install.sh) v1.0.0

# 安装最新测试版 (Beta)
bash <(curl -fsSL https://raw.githubusercontent.com/Grandova/Elise-Backend/main/scripts/install.sh) --beta
```

脚本下载 GitHub Release 并核对 SHA-256。原生程序安装到 `/usr/local/elise/elise`，配置在 `/etc/elise/elise.conf`。systemd/OpenRC 使用各自服务文件。`/usr/local/bin/elise` 优先安装管理脚本，获取不到时可能链接原生二进制；只有前者提供交互菜单。本地源码与线上 Release 可能不同。

---

<a id="section-1-2"></a>

### 1.2 Elise 管理命令体系

下面的服务管理、交互菜单、多实例与证书工具来自 [scripts/elise.sh](scripts/elise.sh)，主要面向 systemd。安装管理脚本后运行 `elise` 进入终端菜单。OpenRC 使用 `rc-service elise start|stop|restart|status`。

原生二进制 `/usr/local/elise/elise` 不提供这些全部子命令；其 `run/start` 在前台运行，原生命令清单见第 6 章。

#### 基础管理

| 命令            | 作用                | 示例 / 说明                                      |
| --------------- | ------------------- | ------------------------------------------------ |
| `elise start`   | 启动 Elise 代理服务 | 后台守护运行                                     |
| `elise stop`    | 停止 Elise 代理服务 | 优雅终止连接                                     |
| `elise restart` | 优雅重启服务        | 停止旧进程并启动新进程；停止阶段尝试最终流量上报 |
| `elise status`  | 查看运行状态        | 显示主进程 PID、常驻内存、运行时间               |
| `elise log`     | 查看服务日志        | 跟踪日志输出 (`journalctl -u elise -f`)          |
| `elise enable`  | 设置开机自启        | 注册 systemd 开机服务                            |
| `elise disable` | 取消开机自启        | 关闭自动启动                                     |
| `elise version` | 查看版本信息        | 打印核心与管理脚本版本                           |
| `elise help`    | 查看命令帮助        | 输出 CLI 参数用法                                |

管理脚本还提供 `elise update stable`、`elise update --beta`、`elise update <版本>` 和交互确认的 `elise uninstall`。更新前保留配置和上一份二进制。

#### 配置与节点

| 命令                   | 作用               | 示例 / 说明                                |
| ---------------------- | ------------------ | ------------------------------------------ |
| `elise config`         | 查看当前主配置文件 | 打印 `/etc/elise/elise.conf`               |
| `elise config k=v ...` | 快速修改配置项     | `elise config node_id=2 check_interval=30` |
| `elise modify`         | 交互式修改主配置   | 逐步修改各项连接参数                       |
| `elise setup`          | 首次配置向导       | 引导填写面板地址、Token 与节点 ID          |
| `elise node list`      | 查看配置的节点列表 | 列出已接管的所有 node ID                   |
| `elise node add <ID>`  | 向配置追加新节点   | `elise node add 5`                         |
| `elise node del <ID>`  | 从配置删除指定节点 | `elise node del 5`                         |

#### 多实例管理 (Multi-Instance)

支持单台服务器运行多个独立配置和服务进程的 Elise 实例（独立配置文件 `/etc/elise/instance_<N>/` 与服务 `elise@<N>`）：

| 命令                           | 作用                    | 说明                         |
| ------------------------------ | ----------------------- | ---------------------------- |
| `elise instance list`          | 查看多实例状态列表      | 列出所有实例及其运行状态     |
| `elise instance add <N> [k=v]` | 新建并初始化实例 `<N>`  | 创建独立配置目录并设置参数   |
| `elise instance setup <N>`     | 引导式配置实例 `<N>`    | 设定专属面板信息与节点 ID    |
| `elise instance start <N>`     | 启动实例 `<N>`          | `systemctl start elise@<N>`  |
| `elise instance stop <N>`      | 停止实例 `<N>`          | `systemctl stop elise@<N>`   |
| `elise instance restart <N>`   | 重启实例 `<N>`          | 优雅重载指定实例             |
| `elise instance status <N>`    | 查看实例 `<N>` 状态     | 显示该实例 PID 与资源占用    |
| `elise instance log <N>`       | 实时查看实例 `<N>` 日志 | `journalctl -u elise@<N> -f` |
| `elise instance enable <N>`    | 设置实例 `<N>` 开机自启 | 注册 systemd 模板服务        |

#### 证书与 Reality 密钥工具

| 命令       | 作用                                              |
| ---------- | ------------------------------------------------- |
| `elise 11` | Reality 密钥管理 (X25519)                         |
| `elise 12` | VLESS Encryption 密钥管理 (decryption/encryption) |

---

<a id="section-1-3"></a>

### 1.3 面板对接实战示例

Elise 根据适配器解析面板下发的**节点协议、端口、TLS 设置与用户列表**，主配置中只需填妥面板类型、地址、通信密钥与节点 ID：

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
> 配置完成后，运行 `elise restart` 即可完成对接启动。`node_id` 是面板节点 ID，不是端口；`panel_key` 是节点对接密钥，不是订阅用户密码。多面板实例使用独立配置目录。

---

<a id="section-1-4"></a>

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

# 监听地址与诊断端口；pprof_addr 省略时使用默认地址，显式空值或 off 关闭
listen_addr = 0.0.0.0
pprof_addr = 127.0.0.1:6060
```

---

<a id="section-1-5"></a>

### 1.5 pprof 性能诊断调试端口

默认监听 `127.0.0.1:6060`。显式设置空值、`off`、`false` 或 `0` 可关闭；指定地址绑定失败时尝试回环随机端口，以日志显示的实际地址为准。

~~~ini
pprof_addr = 127.0.0.1:6060
~~~

关闭示例：

~~~ini
pprof_addr = off
~~~

| 路径                                                         | 当前返回内容                                           |
| ------------------------------------------------------------ | ------------------------------------------------------ |
| `/debug/pprof/`                                              | 诊断首页                                               |
| `/debug/pprof/cmdline`                                       | 当前进程启动参数                                       |
| `/debug/stats`、`/metrics`                                   | JSON：版本、平台、PID、运行时长、诊断请求数            |
| `/debug/pprof/heap`、`allocs`                                | 文本诊断信息；不是实际分配栈采样                       |
| `/debug/pprof/goroutine`、`tasks`、`threadcreate`、`profile` | 当前为静态说明，不能用于判断任务数、CPU profile 或泄漏 |

名称沿用 pprof，但目前不是完整 Go pprof 采样服务，`/metrics` 也不是 Prometheus 文本指标。不要据此推断节点流量、真实在线连接或内存热点。

---

<a id="section-2"></a>

# 2. 三层配置优先级与节点独立配置体系

### 最少配置与面板自动下发

XBoard 节点只需在主配置填写 `panel_url`、`panel_key` 和 `node_id`；其他面板还需选择对应 `type`。协议、端口、传输和用户信息由面板 API 下发，节点 `[AUTO]` 会显示已接入的参数，面板配置成功更新后同步刷新，`[USER]` 保留。

Reality 优先使用面板私钥并校验公钥是否匹配。没有下发任何密钥时，Elise 自动生成并持久保存 `nodes/node_<id>.reality.key`；重启不会重新生成。ECH 启用时优先读取面板的 PEM/Base64 密钥或 `key_path`，否则生成 `nodes/node_<id>.ech.key`，并校验下发的客户端配置。私钥不会输出到 `[AUTO]` 或日志。

**自动生成不等于自动下发到客户端。** 现有节点 API 未提供写回公钥的接口；后端生成的新 Reality 公钥或 ECH config 会出现在节点 `[AUTO]` 的 `tls_settings` 中，需要一次性填回面板。面板已有公钥但没有对应私钥时会明确报错，不能用另一套随机密钥替代。面板已提供完整密钥时无需这个步骤。

VLESS、VMess、Trojan、HTTP、AnyTLS的 TLS 从面板 `tls_settings.allow_insecure` 读取客户端信任策略。只有 `auto_tls=true` 且面板明确 `allow_insecure=true`、又未提供证书时，后端才自动自签；默认/false 时必须提供证书。无效证书不会回退到全局自签证书。此开关不会禁用 TLS，也不会改变已下发客户端的实际校验行为。

普通 TLS 仍需要可信证书，或客户端明确配置的证书信任方式。当前 `auto_tls` 生成的是自签名证书，并非 ACME 公共证书；不能承诺任意面板、域名和 TLS 配置都仅填三项即可通过客户端证书校验。面板不提供的协议功能和密钥回写接口也不能由后端凭空补全。


<a id="section-2-1"></a>

### 2.1 架构原理

面板、主配置和节点配置各有职责，**不存在适用于所有键的“面板永远最高”规则**：

~~~mermaid
flowchart TD
    Panel["面板 API：协议、端口、用户、套餐"] --> Core["NodeRunner"]
    Global["主配置 + 环境变量：共享参数"] --> Core
    Node["节点 USER 区：已接入的独立覆盖项"] --> Core
    Core --> Inbound["协议认证与会话"]
    Inbound --> Shared["限速、设备/连接限制、计费和生命周期"]
    Shared --> Router["路由与审计"]
    Router --> Outbound["Direct / Redirect / SOCKS5 / HTTP / Block"]
~~~

| 字段                                   | 当前选择顺序                                             |
| -------------------------------------- | -------------------------------------------------------- |
| 面板 API 凭据、接管节点列表            | 环境变量覆盖主配置                                       |
| 节点协议、面板端口、用户凭据与套餐速度 | 面板下发；监听端口可加节点 `port_offset`                 |
| 监听 IP                                | 节点 `listen_addr` → 面板 `listen_ip` → 主配置           |
| 同步/上报周期                          | 节点 `check_interval/submit_interval` → 主配置           |
| 证书、Reality/ECH 等                   | 按具体传输适配路径读取，不能把任意 `[USER]` 键当成已生效 |

本地配置修改后重启对应实例；面板轮询更新、路由文件定时重载与本地配置重启加载是不同机制。

---

<a id="section-2-2"></a>

### 2.2 主配置文件 `elise.conf`

路径：`/etc/elise/elise.conf`  
所有节点共享的全局基础配置，定义面板地址、通信密钥、轮询间隔以及未单独覆盖参数的默认全局回退值。

---

<a id="section-2-3"></a>

### 2.3 节点独立配置 (`/etc/elise/nodes/node_{id}.conf`)

当服务启动并成功与面板建立同步后，会在 `/etc/elise/nodes/` 目录下自动维护各节点的独立配置 `node_{id}.conf`。文件分为两个清晰区域：

- **`[AUTO]` 区**：每次同步自动重写，展示节点 ID、协议和端口，**仅供状态查阅，请勿手动编辑**；
- **`[USER]` 区**：**用户自定义的节点级覆盖参数**。在此写入的参数在服务重启、面板规则更新后保留，但仅运行时已接入的键能覆盖，详见下表。

---

<a id="section-2-4"></a>

### 2.4 可在 [USER] 区配置的参数与生效范围

| 参数                                                         | 默认 / 未填写行为  | 当前说明                                                  |
| ------------------------------------------------------------ | ------------------ | --------------------------------------------------------- |
| `listen_addr` / `listen`                                     | 使用面板或全局地址 | 节点监听地址；填写一个本机 IP                             |
| `port_offset`                                                | `0`                | 实际监听端口 = 面板端口 + 偏移，结果必须为 1–65535        |
| `proxy_protocol`                                             | 沿用全局           | 节点 TCP PROXY Protocol 开关；可信代理策略仍来自全局      |
| `udp_proxy_protocol`                                         | 沿用全局           | 接入公共 UDP 路径的协议使用；不代表 Mieru 底层 UDP 已实现 |
| `mptcp`                                                      | 沿用全局           | 接入公共 TCP listener 的路径使用                          |
| `check_interval`                                             | 全局 `60` 秒       | 节点用户同步周期                                          |
| `submit_interval`                                            | 全局 `60` 秒       | 节点流量上报周期                                          |
| `mieru_traffic_pattern`                                      | 空                 | 非空值覆盖主配置/面板；空值继续使用上一级                 |
| `force_close_ssl` / `disable_tls`                            | `false`            | 当前仅关闭此节点的自动自签开关，**不保证关闭面板 TLS**    |
| `cert_file`、`key_file`、`cert_domain`                       | 无                 | 可以解析保存；尚未接入此节点的 TLS 配置覆盖               |
| `cert_mode`、`cert_key_length`、`acme_server`、`dns_provider` | 无                 | 自定义字段会保存；未接通内置 ACME 工作流                  |
| `reality_private_key`                                        | 无                 | 此处保存不等于覆盖面板 Reality 私钥                       |
| `tuic_ech_server_keys`                                       | 无                 | 此处保存不等于注入 TUIC 服务端 ECH keyset                 |
| `force_proxy_protocol`                                       | 全局 `false`       | 请在主配置设置，未接通节点独立覆盖                        |
| `domain_audit_enable`、`domain_audit_domains`、`domain_audit_log_dir` | 无                 | 未接通此处的独立审计覆盖                                  |

保留这些字段的说明是为了避免“配置能保存所以已生效”的误解；未接通的键不是推荐部署配置。证书和 ECH 优先通过实际面板字段传入。

---

<a id="section-2-5"></a>

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

- **节点 250**：开启 Proxy Protocol，并以 30 秒轮询用户；
- **节点 251**：独占绑定 `198.51.100.2` 外网 IP；
- **节点 252**：遵循 `elise.conf` 全局配置。

---

<a id="section-2-6"></a>

### 2.6 节点独立 Nginx TLS 卸载 (force_close_ssl)

该字段的写法：

~~~ini
[USER]
force_close_ssl = true
~~~

当前实现只把该节点的 `auto_tls` 设为 false，未统一改写面板下发的 TLS 模式。**不能仅设置此项就认为所有 TCP 协议都变成明文。**

部署 Nginx/Caddy 前置 TLS 时，必须让面板传输配置与实际后端明文入口相匹配，并分别验证直连后端、前置转发和客户端。前后端监听端口应分开。QUIC 的 TLS 属于协议组成部分，不能套用普通 TCP TLS 卸载方式。

---

<a id="section-2-7"></a>

### 2.7 节点独立证书配置示例

以下列出保留的配置字段，便于检查已有配置；当前它们在 `[USER]` 中仅被解析/保存，尚未完整注入 TLS 配置，**不是可直接依赖的证书覆盖方式**：

~~~ini
[USER]
cert_file = /etc/ssl/my_cert.crt
key_file = /etc/ssl/my_cert.key
cert_domain = node401.example.com
cert_mode = none
~~~

`cert_mode=http/dns`、`cert_key_length=ec-256`、`acme_server=zerossl` 也不代表已有自动申请/续期服务。当前可用的文件证书加载路径来自面板的 `cert_config/tls_settings`，示例见 3.5。若使用外部 ACME 工具，签发与续期由该工具管理。

---

<a id="section-2-8"></a>

### 2.8 混合协议运行机制

单进程可按面板节点列表创建多个协议入站，每个节点保留自己的用户集合、监听与上报状态。多个节点仍共享进程资源；这不是进程级故障隔离。

不同面板或需要独立服务生命周期时，使用 `elise instance` 的独立实例配置。端口冲突应显式调整监听地址/端口；不要假定自动端口偏移或共享监听策略已接通。

---

<a id="section-3"></a>

# 3. 全量配置参数详解

<a id="section-3-1"></a>

### 3.1 核心对接参数

| 参数名                                     | 默认值   | 允许值 / 说明                                                |
| ------------------------------------------ | -------- | ------------------------------------------------------------ |
| `panel_type` / `type`                      | `xboard` | 面板类型：`xboard` / `xiaov2board` / `ppanel` / `v2board` / `sspanel-uim` |
| `api_host` / `panel_url`                   | 必填     | 面板 WebAPI 接口根地址（如 `https://panel.example.com`，末尾无需加斜杠） |
| `api_key` / `panel_key`                    | 必填     | 面板通信 Token 密钥（对应 PPanel 的 `secret_key`）           |
| `node_id` / `node_ids`                     | `1`      | 接管的节点 ID，多节点使用英文逗号分隔（如 `1,2,3`）          |
| `node_sync_interval` / `check_interval`    | `60`     | 从面板拉取节点配置与用户列表的周期（秒，最低 10）            |
| `node_report_interval` / `submit_interval` | `60`     | 向上报送流量与在线设备列表的周期（秒，最低 10）              |

---

<a id="section-3-2"></a>

### 3.2 网络监听与多节点策略

| 参数                                             | 默认值    | 说明                                                         |
| ------------------------------------------------ | --------- | ------------------------------------------------------------ |
| `listen_addr` / `listen`                         | `0.0.0.0` | 一个监听 IP；IPv6 使用对应地址，不要写逗号分隔多 IP          |
| `listen_strategy` / `multi_node_listen_strategy` | `auto`    | 配置保留字段；尚无公共运行时分配器落实 `auto/shared/split` 三种策略 |
| `tcp_timeout`                                    | `300`     | 公共 TCP 空闲超时，秒；不等同于连接总寿命                    |
| `udp_timeout`                                    | `300`     | 公共 UDP 会话空闲超时，秒                                    |
| `mptcp`                                          | `false`   | 公共 listener 的 Linux MPTCP 开关；平台/内核不支持时会报错   |

多节点共享同一 IP 时应使用不同监听端口；多 IP 部署用节点 `listen_addr` 分别绑定。MPTCP 仅影响使用相应 listener 的 TCP 路径，不改变 UDP/QUIC。

---

<a id="section-3-3"></a>

### 3.3 路由、DNS 与出站分流

安装脚本和容器镜像不会自动创建 `/etc/elise/routes.toml`；文件不存在时使用默认直连。有分流需求时请手动创建，或参考 `example/routes.toml`。示例中的 WARP 路由默认注释，确认对应 SOCKS5 服务可用后再启用。

<a id="section-3-3-1"></a>

#### 3.3.1 基础路由与 DNS 参数

| 参数名           | 默认值                   | 说明                                                         |
| ---------------- | ------------------------ | ------------------------------------------------------------ |
| `routes_file`    | `/etc/elise/routes.toml` | 路由文件；本地模式约每 10 秒检查修改                         |
| `dns_file`       | `/etc/elise/dns.yml`     | 独立 DNS 解析器分流规则文件路径                              |
| `default_dns`    | 无                       | 上游默认 DNS 解析器地址（支持 `udp://8.8.8.8:53`、`tcp://`、`https://dns.google/dns-query`） |
| `dns_strategy`   | `ipv4_first`             | 出站解析偏好策略：`prefer_ipv4`（推荐）/ `prefer_ipv6` / `ipv4_only` / `ipv6_only` |
| `dns_cache_time` | `10`                     | 本地 DNS 结果缓存时长（分钟）                                |
| `out_ip_ipv4`    | 无                       | 指定直连出站的源 IPv4 地址（留空由 OS 自动选择路由）         |
| `out_ip_ipv6`    | 无                       | 指定直连出站的源 IPv6 地址                                   |
| `auto_out_ip`    | `false`                  | **源进源出**：出站连接强制绑定入站连接时的本地 IP（多 IP 独立出口服务器必备） |

---

<a id="section-3-3-2"></a>

#### 3.3.2 多路由多出口负载均衡体系 (`routes.toml`)

Elise 提供 `routes.toml` 路由分流与多出口随机选择，用于将入口节点接收到的用户流量，按规则转发到不同的代理出口。

```
客户端 -> Elise 入口节点 (配置 routes.toml) -> 代理出口节点 (Direct / Redirect / SOCKS5 / HTTP) -> 目标网络
```

> [!NOTE]
> **生效边界**：`routes.toml` 仅作用于 Elise 节点接收到的代理用户流量，**不会改写整台宿主服务器系统的全局网络路由**（服务器本机的 `curl`、`apt`、Docker 容器等流量保持原有系统路由不变）。

##### 1. 配置文件加载机制与优先级

1. **启动参数指定**：`elise run -r /path/to/routes.toml`（最高优先级）
2. **全局主配置指定**：`elise.conf` 中配置 `routes_file = /path/to/routes.toml`
3. **默认回退路径**：若均未显式指定，默认加载与 `elise.conf` 同目录下的 `routes.toml`（或 `/etc/elise/routes.toml`）
4. **约 10 秒检测本地改动**：修改本地 `routes.toml` 时，Elise 会每 10 秒自动检测文件时间戳并动态重载规则；未配置 routes_url 时使用本地重载，新连接使用新规则，既有连接不迁移；
5. **面板路由协同机制**：对于对接 XBoard / XiaoV2Board 面板下发的运行时路由（`routes` / `custom_outbounds`），Elise 遵循**面板路由优先**原则；若流量未命中面板路由，则继续匹配本地 `routes.toml`；若本地未配置或未命中且面板无默认出口，最终执行 `direct` 直连兜底。

##### 2. 匹配规则语法 (`rules = [...]`)

同一 `[[routes]]` 中，`node_id:`、`network:`、`port:` 不同范围维度是 **AND**，同维度候选是 **OR**；域名/IP/Geo 目的规则之间是 **OR**。例如 `["node_id:2", "network:tcp", "domain:example.com"]` 只匹配节点 2 的 TCP 目标 example.com 及其子域名。

| 规则前缀          | 示例                                | 说明                                                       |
| ----------------- | ----------------------------------- | ---------------------------------------------------------- |
| `geosite:`        | `"geosite:netflix"`, `"geosite:cn"` | 匹配 Loyalsoldier `geosite.dat` 分类规则                   |
| `geoip:`          | `"geoip:cn"`, `"geoip:private"`     | 匹配 Loyalsoldier `geoip.dat` 国家与内网网段规则           |
| `domain:`         | `"domain:google.com"`               | 匹配域名后缀（如 `www.google.com` 与 `google.com` 均命中） |
| `domain-keyword:` | `"domain-keyword:telegram"`         | 域名关键字子串匹配                                         |
| `full:`           | `"full:api.openai.com"`             | 域名全匹配（必须完全一致）                                 |
| `regexp:`         | `"regexp:^.*\\.edu\\.cn$"`          | 正则表达式匹配目标域名                                     |
| `ip:`             | `"ip:1.2.3.4/24"`, `"ip:8.8.8.8"`   | 匹配目标单 IP 或 CIDR 网段                                 |
| `port:`           | `"port:80,443"`, `"port:1000-2000"` | 匹配目标单端口或端口范围                                   |
| `node_id:`        | `"node_id:1,2,3"`                   | **按入口节点 ID 分流**（单进程多节点模式下区分不同节点）   |
| `network:`        | `"network:tcp"`, `"network:udp"`    | 过滤传输协议类型                                           |
| `*`               | `"*"`                               | 通配规则（通常放在最后一条 `[[routes]]` 作为全量兜底）     |

##### 3. 支持的代理出口类型 (`[[routes.Outs]]`)

| 出口类型           | 参数字段                                 | 说明                                                         |
| ------------------ | ---------------------------------------- | ------------------------------------------------------------ |
| `direct`           | `listen=""`                              | 直连目标网络，支持绑定指定出口网卡 IP，源地址选择受全局出站设置影响 |
| `redirect`         | `server="1.2.3.4"`, `port=8080`          | 地址与端口重定向；若 `port=0` 则保持用户原本访问的端口       |
| `socks` / `socks5` | `server`, `port`, `username`, `password` | 转发至上游 SOCKS5 代理，支持无密或用户密码认证，支持 TCP 与 UDP ASSOCIATE |
| `http`             | `server`, `port`, `username`, `password` | 转发至上游 HTTP CONNECT 代理，支持 Basic 认证（仅限 TCP）    |
| `block` / `reject` | 无                                       | 阻断并立即断开连接（如拦截黑名单、BT 下载端口等）            |

##### 4. 多出口随机负载均衡原理

当在同一个 `[[routes]]` 规则下方配置了多个 `[[routes.Outs]]` 出口时：

- Elise 内部会自动采用 **随机出口选择（Random Load Balancing）** 算法，每次新连接建立时从中随机选择一个出口；
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
当 `elise.conf` 中配置了 `node_id = 1,2,3` 且运行在同一台服务器时，可通过 `node_id:` 为各节点分别指定出口：

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

# 节点 2 的 TCP 流量转发至 HTTP CONNECT 出口 B
[[routes]]
rules = ["node_id:2", "network:tcp"]
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

<a id="section-3-4"></a>

### 3.4 PROXY Protocol 真实 IP 透传

当 Elise 位于前置 CDN、负载均衡器或 HAProxy 之后时，可启用 PROXY Protocol 提取客户端真实原始 IP：

| 参数名                 | 默认值  | 说明                                                         |
| ---------------------- | ------- | ------------------------------------------------------------ |
| `proxy_protocol`       | `false` | 是否接收入站 TCP PROXY Protocol v1/v2 报头（可设 `true`、`false` 或 `auto`） |
| `udp_proxy_protocol`   | `false` | 是否开启入站 UDP PROXY Protocol v2 DGRAM 报头解析            |
| `force_proxy_protocol` | `false` | 强制代理协议校验；未携带有效代理协议头的请求将被直接断开     |
| `trusted_proxies`      | 无      | 信任的前置代理 CIDR 白名单（逗号分隔，如 `127.0.0.1/32,10.0.0.0/8`） |

---

<a id="section-3-5"></a>

### 3.5 TLS、四种证书模式与 ECH / uTLS

<a id="section-3-5-1"></a>

#### 3.5.1 四种基础证书模式

保留四类部署方式，但区分 Elise 实际加载证书与外部工具签发证书：

| 方式           | 当前实现 / 使用条件                                          |
| -------------- | ------------------------------------------------------------ |
| 自定义文件证书 | TLS 配置接收证书/私钥路径或 PEM；文件需对 Elise 进程可读     |
| HTTP ACME      | 未实现内置申请和续期；使用外部 ACME 工具签发后交给文件证书加载路径 |
| DNS ACME       | 同上；填写 `dns_provider` / `DNS_*` 不能自动完成签发         |
| 自动自签       | `auto_tls=true` 且面板 `allow_insecure=true` 时，无证书的 TLS 入口可自动自签；不具备公共 CA 信任 |

例如面板下发的证书配置对象可包含：

~~~json
{
  "cert_config": {
    "cert_file": "/etc/ssl/certs/fullchain.pem",
    "key_file": "/etc/ssl/private/privkey.pem"
  }
}
~~~

这是一段**面板字段示意**，不是把 JSON 粘进 `elise.conf`。各面板版本的配置入口不同，需确认最终 API 响应确实带上对应字段。

其他证书相关字段及当前消费情况：

| 字段                         | 说明                                                         |
| ---------------------------- | ------------------------------------------------------------ |
| `cert_file`、`key_file`      | TLS 证书对象中的文件路径；本地主配置同名文本不等于已注入     |
| `cert_domain`                | 保留的申请域名字段；未接通内置 ACME                          |
| `cert_mode`                  | 兼容字段参考 `http/dns/self/none`；不能以此推断自动签发或 TLS 开关 |
| `cert_key_length`            | 兼容字段参考 `ec-256/ec-384`；内置 ACME 未消费此参数         |
| `acme_server`                | 兼容字段参考 `letsencrypt/zerossl`；交由外部签发工具设置     |
| `dns_provider`               | 原文如 `dns_cf`；交由外部签发工具设置                        |
| `DNS_CF_Email`、`DNS_CF_Key` | 保留 DNS 环境变量，但 Elise 当前不会因此执行 DNS 验证        |
| `auto_tls`                   | 默认 `true`；自动自签能力，与 ACME 无关                      |
| `fake_sni`                   | 默认 `www.microsoft.com`；部分 TLS 路径使用的默认名称，不赋予域名所有权或可信证书 |

~~~ini
auto_tls = true
fake_sni = node.example.com
~~~

脚本的 `elise cert gen` 使用 OpenSSL 生成自签证书文件，`elise cert status` 查看文件；它不提供 ACME 自动续期。

<a id="section-3-5-2"></a>

#### 3.5.2 ECH (Encrypted Client Hello)

TLS 实现中存在 ECH 服务端解密及密钥验证路径，并使用本地修改的 rustls 依赖。面板常见字段：

| 字段                     | 用途                                   |
| ------------------------ | -------------------------------------- |
| `enabled`                | 启用 ECH                               |
| `server_keys` / `key`    | 服务端密钥材料；格式必须符合当前解析器 |
| `config` / `config_list` | 客户端 ECHConfigList                   |
| `query_server_name`      | 面板订阅中的客户端查询配置             |

服务端启用 ECH 但没有有效密钥会报错，不能用客户端公开配置替代服务端私钥。ECH 的协议版本、密钥格式与客户端支持须独立互通验证，不能承诺“所有 TLS 协议自动支持”。

`tuic_ech_server_keys` 的节点本地覆盖尚未接通；通过 `[USER]` 保存该值不等于生效。

<a id="section-3-5-3"></a>

#### 3.5.3 uTLS 客户端指纹与订阅协同

面板 `utls` / fingerprint 字段描述客户端 ClientHello 配置，常见名称包括 `chrome`、`firefox`、`safari`、`ios`、`android`、`edge`、`qq`、`360`、`random`、`randomized`。

Elise 解析客户端 TLS profile 不等于服务端模拟浏览器指纹，也不保证链式出站自动复现相同握手。客户端是否接受具体指纹值由其内核决定；以实际订阅和握手测试为准。

---

<a id="section-3-6"></a>

### 3.6 用户限速、设备限制与 Redis 增强

<a id="section-3-6-1"></a>

#### 3.6.1 速率与并发连接限制

只使用面板套餐下发的用户速度（Mbps；转换为字节每秒执行）。修改套餐后随用户同步更新。

| 参数名             | 默认值 | 说明                                                         |
| ------------------ | ------ | ------------------------------------------------------------ |
| `user_speed_limit` | `0`    | 兼容保留字段，当前忽略本地值并记录告警；实际速度只来自面板用户套餐 |
| `node_speed_limit` | `0`    | 兼容保留字段，当前忽略本地值；不启用额外动态/节点总限速      |
| `user_tcp_limit`   | `0`    | 单用户最大允许并发 TCP 流数（0 表示不限）                    |
| `user_conn_limit`  | `0`    | 用户设备数上限，与面板 device_limit 的非零较小值组合；不是 TCP 连接数 |

<a id="section-3-6-2"></a>

#### 3.6.2 在线设备限制与 Redis 集群去重

设备按 IP 前缀及活跃窗口统计，可启用 Redis 协作。设备不等于物理终端：共享 NAT 会合并，IPv6 前缀变化可能增加记录。跨节点约束仍需真实集群验收：

| 参数名                     | 默认值  | 说明                                                         |
| -------------------------- | ------- | ------------------------------------------------------------ |
| `device_limit_window`      | `300`   | 设备活跃滑动窗口时长（秒，默认 5 分钟）                      |
| `device_limit_prefix_ipv4` | `32`    | IPv4 子网聚合掩码（默认 32 单 IP 单设备；设为 24 则同一 /24 网段视作同设备） |
| `device_limit_prefix_ipv6` | `64`    | IPv6 子网聚合掩码（默认 /64 网段）                           |
| `redis_enable`             | `false` | 是否开启 Redis 分布式设备跨节点去重                          |
| `redis_addr`               | 无      | Redis 连接地址（如 `127.0.0.1:6379` 或 `redis://...`）       |
| `redis_password`           | 无      | Redis 认证密码                                               |
| `redis_db`                 | `0`     | Redis 数据库索引号                                           |
| `conn_limit_expiry`        | `60`    | Redis 在线设备记录键的过期刷新时间（秒）                     |
| `redis_timeout_ms`         | `300`   | Redis 响应超时时间（毫秒）                                   |

> [!TIP]
> **Redis 故障处理**：设备检查超时或连接失败时回到本机内存检查。本机限制仍可能拒绝连接，且此时不能保证跨节点设备总数约束。

<a id="section-3-6-3"></a>

#### 3.6.3 在线 IP 磁盘持久化缓存

```ini
# 缓存保留时长（小时）
ip_user_cache_time = 1
# 开启定时持久化
ip_user_cache_save_enable = true
# 缓存持久化目录
ip_user_cache_save_dir = /etc/elise/
```

缓存保存 IP → 用户映射，用于恢复相关查询；它不是全部活动连接/设备计数的持久化快照，不能承诺重启后精确恢复在线设备数。

---

<a id="section-3-7"></a>

### 3.7 审计黑白名单与 Geo 路由数据库

<a id="section-3-7-1"></a>

#### 3.7.1 审计黑名单 (`blockList`) 与白名单 (`whiteList`)

- **黑名单**：支持域名后缀、IP CIDR 网段、目标端口范围过滤，支持从远程 URL 定期拉取（`block_list_url`）；
- **白名单**：白名单影响对应审计路径，不绕过协议认证、用户限额或路由 block；
- **秒级热重载**：修改本地 `/etc/elise/blockList` 或 `/etc/elise/whiteList`，本地模式约每 10 秒检查修改并重载；配置远程列表时按远程拉取路径处理。

<a id="section-3-7-2"></a>

#### 3.7.2 GeoIP 与 GeoSite 数据库

Geo 数据库按以下候选路径加载：

1. 配置文件显式指定的 `geoip_file` 与 `geosite_file`；
2. `/etc/elise/geoip.dat` 与 `/etc/elise/geosite.dat`；
3. 程序当前目录 `./geoip.dat` 与 `./geosite.dat`；
4. 上级目录 `../geoip.dat` 与 `../geosite.dat`；
5. 系统公共目录 `/usr/local/share/elise/`。

在 `routes.toml` 与 `blockList` 中支持直接使用标签语法：

```toml
[[routes]]
rules = ["geoip:cn", "geoip:private"]
[[routes.Outs]]
type = "direct"

[[routes]]
rules = ["geosite:category-ads-all"]
[[routes.Outs]]
type = "block"
```

---

<a id="section-3-8"></a>

### 3.8 监控审计与高级网络安全

<a id="section-3-8-1"></a>

#### 3.8.1 系统日志与结构化审计日志

`log_level/log_file/audit_log_file` 有实际消费路径。`log_retention_days/log_max_size_mb` 虽可解析，但当前 logger 未按它们执行保留天数或大小轮转；文件日志使用按日 appender。`domain_audit_*` 独立配置尚不能视为已接入。

```ini
# debug, info, warn, error, none
log_level = info
# 留空输出至 stdout / journal
log_file = /var/log/elise/elise.log
# 日志保留天数
log_retention_days = 7
# 单文件切分大小 (MB)
log_max_size_mb = 100

# 结构化审计日志文件
audit_log_file = /var/log/elise/audit.log
```

审计记录通过队列写入 **JSON Lines (JSONL)**。以下为主要字段示意，具体协议是否在对应生命周期点记录需验收；不承诺无锁或每条连接都产生相同事件：

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

<a id="section-3-8-2"></a>

#### 3.8.2 高级网络安全与防扫描控制

| 参数名                       | 默认值  | 说明                                                         |
| ---------------------------- | ------- | ------------------------------------------------------------ |
| `domain_sniff`               | `true`  | 首包域名嗅探：当客户端直接发起目标 IP 连接时，从 TLS ClientHello (SNI) 或 HTTP Host 中嗅探原始域名用于精准路由和审计 |
| `sniff_redirect`             | `false` | 嗅探出真实域名后，强制使用本地/面板 DNS 重新解析目标 IP 出站 |
| `forbidden_ports`            | 无      | 全局禁止代理的敏感端口（如 `25,465,587,6881-6889` 封禁垃圾邮件与 BT） |
| `forbidden_bit_torrent`      | `true`  | 是否启用内置 BitTorrent / P2P 特征流量阻断                   |
| `ban_private_ip`             | `false` | 是否禁止代理出站访问私有内网 IP（防止 SSRF 攻击）            |
| `submit_traffic_min_traffic` | `0`     | 流量上报缓冲阈值（KB），低于此阈值的微小流量在本地缓存累计，减少面板 API 请求压力 |

<a id="section-3-8-3"></a>

#### 3.8.3 协议专有安全防爆破机制

下面示例主动启用封禁；配置默认的 `ss_invalid_access_enable` 和 `vmess_aead_invalid_access_enable` 均为 false。封禁开关不能替代协议 replay/nonce 校验。

- **Shadowsocks 单端口多用户并发解密与防暴力破解**：

  ```ini
  # 多用户单端口解密并发上限，不等于 OS 线程数
  ss_decrypt_concurrency = 8
  # 开启非法探测 IP 自动封锁
  ss_invalid_access_enable = true
  # 连续失败 30 次触发封锁
  ss_invalid_access_count = 30
  # 统计时间窗口（秒）
  ss_invalid_access_duration = 60
  # 封禁时长（秒）
  ss_invalid_access_forbidden_time = 600
  ```

- **VMess AEAD 强制与抗重放防探测**：

  ```ini
  # 强制客户端使用 AEAD 头部（拒绝不安全的旧版 MD5 认证）
  force_vmess_aead = false
  # 强制选择旧版 MD5 模式；不要与 force_vmess_aead 同时开启
  force_vmess_md5 = false
  # 开启探测 IP 自动封禁
  vmess_aead_invalid_access_enable = true
  # 连续失败阈值
  vmess_aead_invalid_access_count = 30
  # 统计窗口（秒）
  vmess_aead_invalid_access_duration = 60
  # 封禁时长（秒）
  vmess_aead_invalid_access_forbidden_time = 600
  ```

---


<a id="section-3-9"></a>

### 3.9 Shadowsocks 加密与原生插件传输

<a id="section-3-9-1"></a>

#### 3.9.1 加密方式

| 方法名                          | 类别   | 配置要求                 |
| ------------------------------- | ------ | ------------------------ |
| `aes-128-gcm`                   | AEAD   | 使用面板下发的密码       |
| `aes-192-gcm`                   | AEAD   | 同上                     |
| `aes-256-gcm`                   | AEAD   | 同上                     |
| `chacha20-ietf-poly1305`        | AEAD   | 同上                     |
| `2022-blake3-aes-128-gcm`       | SS2022 | 使用符合该方法的密钥格式 |
| `2022-blake3-aes-256-gcm`       | SS2022 | 同上                     |
| `2022-blake3-chacha20-poly1305` | SS2022 | 同上                     |

服务端从面板读取加密方法、用户凭据及插件参数。SS2022 的密钥不是任意普通密码；客户端和面板生成方式必须一致。TCP 与 UDP 应分开验证认证、并发、计费及重放处理。

<a id="section-3-9-2"></a>

#### 3.9.2 插件功能入口

插件传输在 Elise 进程内实现，不要求启动 SIP003 外部插件进程。下面列出当前选项入口；不是对上游所有模式和选项的兼容声明。

| 插件         | 配置名称                      | 模式 / 主要选项                                              |
| ------------ | ----------------------------- | ------------------------------------------------------------ |
| None         | 空或 `none`                   | 无插件，选项应为空                                           |
| Simple Obfs  | `simple-obfs` / `obfs-server` | `obfs=http/tls`；`host`                                      |
| V2Ray Plugin | `v2ray-plugin`                | `mode=websocket/quic`；`tls/host/path/cert/key/mux`          |
| Gost Plugin  | `gost-plugin`                 | `tls/mtls/ws/mws/wss/mwss/h2/grpc/gun/quic`；具体模式使用对应选项 |
| Shadow TLS   | `shadow-tls` / `shadowtls`    | `version/v3`、`host`、`password/passwd`、`strict`            |
| ResTLS       | `restls`                      | `host`、`password/passwd`、`script`、`min-record-len` 等     |
| KCPTun       | `kcptun`                      | `key/crypt/mode/mtu/sndwnd/rcvwnd/datashard/parityshard` 及相关流控参数 |

##### kcptun需第三方实现 安装kcptun

```shell
ARCH=$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/') && \
sudo curl -fSL "https://github.com/dumbybumby/kcptun-archive/releases/download/20260411/kcptun-server-linux-${ARCH}" -o /usr/local/bin/kcptun-server && \
sudo chmod +x /usr/local/bin/kcptun-server && \
sudo mkdir -p /etc/elise && \
sudo cp -f /usr/local/bin/kcptun-server /etc/elise/kcptun-server
```

面板 `plugin_opts` 可下发分号分隔字符串或对象。例如 WebSocket 模式的字段示意：

~~~json
{
  "plugin": "v2ray-plugin",
  "plugin_opts": {
    "mode": "websocket",
    "host": "ss.example.com",
    "path": "/ss",
    "server": true
  }
}
~~~

是否启用 TLS、证书路径、mux 和客户端插件版本都应一致。插件包装 TCP 并不自动把 Shadowsocks UDP 改成相同封装；UDP 的监听、防火墙、路由和客户端开关需单独验收。完整允许参数见 [transport.rs](src/protocol/shadowsocks/transport.rs)，具体模式验证还会施加额外约束。

<a id="section-3-10"></a>

### 3.10 Mieru 用户、传输与 TrafficPattern

#### 3.10.1 面板及客户端设置

| 项目               | 当前行为                                                     |
| ------------------ | ------------------------------------------------------------ |
| 面板节点 transport | 选择 **TCP**                                                 |
| 用户名、密码       | XBoard 当前接入使用同一个面板用户凭据：非空 `password` 优先，否则使用 `uuid` |
| 会话复用           | TCP 上支持多个逻辑会话；已有 Mihomo 默认复用互通记录         |
| UDP Associate      | 经 TCP 隧道转发 UDP；客户端仍需开启 UDP                      |
| 原生 UDP 底层      | Unsupported，不要把面板 transport 改成 UDP                   |
| 用户更新           | 由面板用户同步更新；客户端凭据须与当前订阅保持一致           |

Mihomo 配置中 `udp: true` 是允许代理 UDP 数据，不是切换底层 transport。延迟测试通过只能证明短连接的一部分路径，不能替代网页、长连接、复用和 UDP DNS 验收。

<a id="section-3-10-2"></a>

#### 3.10.2 TrafficPattern 参数

| 参数                    | 默认     | 含义                                            |
| ----------------------- | -------- | ----------------------------------------------- |
| `mieru_traffic_pattern` | 空       | 本地覆盖的 Base64 Mieru TrafficPattern protobuf |
| 面板 `traffic_pattern`  | 面板下发 | 没有非空本地覆盖时自动使用                      |

主配置默认留空：

~~~ini
mieru_traffic_pattern=
~~~

节点独立配置默认也留空：

~~~ini
[USER]
mieru_traffic_pattern=
~~~

需要覆盖时，把面板或官方工具生成的完整 Base64 填在等号后面，保留末尾 `=`。这里不提供固定样本，也不在代码里固定某个节点的参数。

顺序为：**非空节点 [USER] > 非空主配置 > 面板**。本地空白值表示不覆盖，不是清除面板参数。无效 Base64 / 损坏 protobuf 会报错；高级 TrafficPattern 组合还需单独验证，不能用基本互通代替。

<a id="section-3-11"></a>

### 3.11 上报、远程规则与补充配置

<a id="section-3-11-1"></a>

#### 3.11.1 流量与在线状态

| 参数                          | 默认           | 说明                                                     |
| ----------------------------- | -------------- | -------------------------------------------------------- |
| `submit_traffic_min_traffic`  | `0`            | 流量批量上报阈值，KB；未达到阈值保留累计                 |
| `submit_alive_ip_min_traffic` | `0`            | 在线 IP 上报的流量阈值，KB                               |
| `ip_user_cache_save_dir`      | 主配置所在目录 | IP 缓存目录，也用于 pending 流量快照的 `traffic/` 子目录 |
| `routes_url`                  | 空             | 远程路由文件来源                                         |
| `block_list_url`              | 空             | 远程黑名单来源                                           |
| `white_list_url`              | 空             | 远程白名单来源                                           |

上报时失败数据仍留在 pending，成功确认后清除已报部分；停机阶段尝试最终上报并保存未确认数据。面板“已接收但响应丢失”的场景依然需要面板端幂等支持，不能保证恰好一次计费。

停止进程不等于面板一定可达；查看停机日志中的未确认 pending 提示，不要直接删除运行配置目录中的流量快照。

<a id="section-3-11-2"></a>

#### 3.11.2 Redis、ClickHouse 与审计补充项

| 参数                          | 默认值                  | 说明                                              |
| ----------------------------- | ----------------------- | ------------------------------------------------- |
| `redis_url`                   | 空                      | 完整 Redis 连接 URL；与拆分字段配合规则见配置实现 |
| `redis_tls`                   | `false`                 | 使用 TLS Redis 连接                               |
| `clickhouse_enabled`          | `false`                 | 启用 ClickHouse 日志出口                          |
| `clickhouse_addr`             | `http://127.0.0.1:8123` | HTTP 接口地址                                     |
| `clickhouse_db`               | `elise`                 | 数据库名                                          |
| `clickhouse_table`            | `access_log`            | 表名                                              |
| `clickhouse_user`             | `default`               | 用户                                              |
| `clickhouse_password`         | 空                      | 密码                                              |
| `domain_audit_enable`         | `false`                 | 可解析，独立审计管线尚未接通                      |
| `domain_audit_domains`        | 空                      | 同上，不要视为实际拦截规则                        |
| `domain_audit_log_dir`        | 空                      | 同上                                              |
| `domain_audit_retention_days` | `7`                     | 同上，尚不保证自动清理                            |
| `outbound_proxy_protocol`     | 空                      | 出站 PROXY Protocol 模式；需与接收方配套配置      |

ClickHouse 出口与本地 audit 日志不是同一条存储管线；网络不可用时的完整投递保证需独立测试。默认构建启用 `distributed`，若关闭该特性，不应配置依赖 Redis 的功能。

---

<a id="section-4"></a>

# 4. 生产环境性能基准参考

以下描述环境为 2 vCPU、Debian 13 / Linux 6.12。**尚未为这组数值绑定可复现的构建版本、完整脚本和原始报告，因此对当前版本均为 NOT TESTED，不作为容量或性能承诺。**

| 压测指标                               | 500 人在册用户 / 10,000 TCP 并发 | 1,000 人在册用户 / 10,000 TCP 并发 | 备注                                                         |
| -------------------------------------- | -------------------------------- | ---------------------------------- | ------------------------------------------------------------ |
| **空载基线物理内存 (RSS)**             | **8.75 MB**                      | **10.95 MB**                       | 极小初始内存开销                                             |
| **10,000 并发长连接常驻内存 (RSS)**    | **119.82 MB**                    | **109.33 MB**                      | **单连接净物理开销仅 ~10~11 KB**                             |
| **峰值最高水位内存 (VmHWM)**           | 246.43 MB                        | 264.68 MB                          | 包含瞬时缓冲区峰值                                           |
| **静默保活 CPU 占用 (Keep-Alive)**     | **0.0% ~ 0.3%**                  | **0.0% ~ 0.3%**                    | 历史记录，当前版本待复测                                     |
| **活跃全量数据中继 CPU 占用 (Active)** | 4.6% (峰值 8.3%~10.7%)           | 4.6% (峰值 8.3%~10.7%)             | 历史记录，不能据此认定零拷贝                                 |
| **打开系统句柄 (FDs)**                 | 20,124                           | 20,124                             | 1w 入站 + 1w 出站 + 124 系统基础句柄，单次观测不能证明无泄漏 |
| **100MB 真实通量大文件传输**           | SHA-256 全量精确匹配             | SHA-256 全量精确匹配               | PCAP 抓包零二进制明文泄露                                    |



# 5. 常见问题与排错指南

<a id="q1"></a>

### Q1: 大并发场景下出现 Too many open files？

先查看实际服务限制：

~~~bash
systemctl show elise -p LimitNOFILE
systemctl status elise --no-pager
~~~

仓库服务文件配置了 `LimitNOFILE=1048576`；自定义服务、容器或手动前台启动可能使用其他限制。systemd 服务通过 unit/drop-in 调整；仅修改 `/etc/security/limits.conf` 不会保证服务限制变化。

手动 shell 可查看 `ulimit -n`。调整限制后仍需观察实际 FD 数和会话释放，不能用更高上限掩盖泄漏。

<a id="q2"></a>

### Q2: 高并发或小内存服务器如何检查网络参数？

先记录现有设置，再结合并发量、RTT、吞吐和内存测试决定是否调整：

~~~bash
sysctl net.core.somaxconn
sysctl net.ipv4.tcp_max_syn_backlog
sysctl net.ipv4.tcp_rmem
sysctl net.ipv4.tcp_wmem
sysctl net.ipv4.ip_local_port_range
sysctl net.ipv4.tcp_tw_reuse
~~~

这些分别涉及监听队列、TCP 缓冲、出站端口范围和 TIME_WAIT 复用策略。原版的固定数值不是 Elise 必需配置；变更前保存旧值，并检查高并发下的内存、吞吐和错误率。

---

<a id="q3"></a>

### Q3: 端口被占用导致启动失败？

查看占用端口的具体进程：

```bash
lsof -i :443   # 或 netstat -tlpn | grep 443
```

前置 Nginx 使用 443 时，应让 Elise 使用另一个后端监听端口，并核对明文/TLS 传输匹配；`force_close_ssl` 的当前限制见 2.6。

---

<a id="q4"></a>

### Q5: 修改参数后为什么没生效？

确认修改的是该实例实际使用的主配置/节点配置，环境变量是否覆盖了主配置，以及这个键是否已接入运行时。面板同步、路由重载、本地配置加载是不同路径。本地配置修改后重启对应服务，`[AUTO]` 区不要手动修改。

<a id="q6"></a>

# 6. 源码构建、原生命令与项目目录

<a id="section-6-1"></a>

### 6.1 构建

使用当前稳定版 Rust 与相应平台 C/C++ 构建工具。最低 Rust 版本尚未建立独立验证；不能继续承诺 Rust 1.80 能编译当前锁文件。

~~~bash
git clone https://github.com/Grandova/Elise-Backend.git
cd Elise-Backend
cargo build --release --locked
~~~

Linux 产物为 `target/release/elise`，Windows 为 `target/release/elise.exe`。默认特性为 `distributed` 和 `quic-protocols`；修改特性集合后要重新验收实际启用协议。发布包脚本见 [scripts/package-release.sh](scripts/package-release.sh)。

<a id="section-6-2"></a>

### 6.2 原生二进制命令

下面直接调用二进制，不经过 Shell 菜单：

~~~bash
/usr/local/elise/elise --help
/usr/local/elise/elise version
/usr/local/elise/elise run -c /etc/elise/elise.conf
/usr/local/elise/elise -c /etc/elise/elise.conf config
/usr/local/elise/elise -c /etc/elise/elise.conf node list
/usr/local/elise/elise -c /etc/elise/elise.conf node add 2
/usr/local/elise/elise -c /etc/elise/elise.conf node del 2
/usr/local/elise/elise reality gen
/usr/local/elise/elise reality show
/usr/local/elise/elise x25519
~~~

原生 `start` 是前台 `run` 的别名，`status/log` 提供状态/日志入口。Shell 脚本则提供后台服务管理、`setup/modify/instance/cert/update/uninstall` 等命令。是否有菜单以实际入口文件为准。

配置查看和密钥生成可能输出敏感信息，分享日志前移除密钥。

<a id="section-6-3"></a>

### 6.3 修改后的检查

~~~bash
cargo fmt --check
cargo clippy --locked
cargo test --locked
~~~

协议变更还需独立客户端互通，覆盖正常/错误认证、长连接、上传下载、双向传输、half-close、UDP、路由、限速、计费、断线清理和 graceful shutdown。自家编码/解码 roundtrip 只算单元测试。

README 文档更新不自动触发新一轮全协议验收，也不把历史测试结果归给新的二进制版本。

<a id="section-6-4"></a>

### 6.4 目录说明

| 路径                                  | 内容                               |
| ------------------------------------- | ---------------------------------- |
| `src/panel/`                          | 面板 API 适配                      |
| `src/protocol/`                       | 协议认证、编解码与会话             |
| `src/proxy/`                          | 节点生命周期、路由与出站           |
| `src/limiter/`、`src/stats/`          | 用户限制及统计                     |
| `src/security/`、`src/observability/` | 安全、审计和诊断                   |
| `example/`                            | 配置模板                           |
| `scripts/`                            | 安装、服务、管理和打包             |
| `vendor/`                             | 构建必需的本地依赖补丁             |
| `target/`                             | 可重新生成的构建文件               |
| `dist/hardening/`                     | 本地历史验收记录和交付包，Git 忽略 |

---

## 许可与使用条款

本项目采用 [PolyForm Noncommercial License 1.0.0](LICENSE)，具体使用、修改与分发条件以许可证全文为准。`vendor/` 中的依赖保留各自许可证。
