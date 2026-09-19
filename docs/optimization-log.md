# Elise 协议与内核加固日志

## [2026-09-19] Shadowsocks 2022 (SIP022 / SIP023) 规范级协议审计与重构修复

### 任务背景与核心目标
- 针对 Elise 中的 SS2022 三大 Cipher (`2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`) 进行规范级彻底重构。
- 严格以 Shadowsocks SIP022 / SIP023 规范及 `shadowsocks-rust` (1.25.0) / `sing-box` 真实互操作行为为唯一基准。
- 坚决杜绝任何非标 key derivation、禁止传统 Shadowsocks fallback、消除暴力试解密多用户扫描，支持严格的双向流分块与 UDP NAT 漫游。

### 关键修复与落地架构
1. **密码学原语 (Primitives & PSK)**：
   - 彻底移除非标 `blake3::derive_key("shadowsocks 2022 user key", password)`、EVP_BytesToKey、MD5 与 SHA256 猜测 fallback；
   - 严格要求 Base64 解码：AES-128 严格 16 字节，AES-256 / ChaCha20 严格 32 字节，格式不符直接报配置错误拒绝启动；
   - 正确实现 `derive_session_subkey`、`derive_identity_subkey`、`aes_block_encrypt` / `aes_block_decrypt` 及 BLAKE3-based identity hash；
   - 时间戳最大偏差严格限制在 30 秒（`SERVER_STREAM_TIMESTAMP_MAX_DIFF`）。
2. **TCP 状态机 (Stream Framing & Anti-Replay)**：
   - 彻底废除 `PrefixedStream` 与 upstream `ProxyServerStream` 二次握手和二次解密的反模式；
   - 实现原生 `Ss2022TcpReader`、`Ss2022TcpWriter` 与 `Ss2022Stream`，完整处理 length-chunk (2B + 16B Tag) 与 data-chunk；
   - 服务端首包严格遵循标准 Response Header 规范：`[Type=1 (1B)][Timestamp (8B)][Request Salt (16B/32B)][First Payload Length (2B)] + 16B Tag`，强绑定客户端 `request_salt` 与首块长度，并紧随 `First Payload + 16B Tag`；
   - 重放防范（`check_nonce_replay`）严格后置在完整 Variable Header 与 Padding 验证成功之后，杜绝残缺数据包造成 Salt 污染。
3. **UDP 状态机 (Cipher Isolation & NAT Roaming)**：
   - 严格隔离 AES (Separate Header ECB + Session subkey AES-GCM + 12B nonce) 与 ChaCha20 (24B random nonce + raw PSK XChaCha20-Poly1305)；
   - 会话路由解耦对端 IP:Port：SS2022 下以 `(user_id, client_session_id, address)` 路由，结合 `ReplayWindow`（1024 槽位无堆分配位图滑动窗口）防重放；
   - 支持 NAT 动态漫游：同一 Session ID 下合法新包平滑原子更新 `client_remote`（`Arc<RwLock<SocketAddr>>`），响应即时回包至最新对端。
4. **SIP023 多用户机制规范化**：
   - 多用户（EIH）模式下，通过 precomputed identity map 实现纯粹的 $O(1)$ 用户查找；
   - 彻底删除多用户未命中时遍历所有用户暴力试解密的回退代码；未命中或解密失败直接丢弃并报错；
   - 单用户模式下直接绑定单个凭证，禁止任何猜测。

### 修改文件列表
- `src/protocol/shadowsocks/ss2022.rs`：底层 Primitive 重构、严格 PSK Base64、TcpReader/Writer/Stream 原生实现、SIP023 EIH 纯 $O(1)$ 查找及完整单元测试。
- `src/protocol/shadowsocks/udp.rs`：1024 槽位位图重放窗口、NAT 漫游会话支持（`SessionKey` 解耦 `remote`，动态读写更新对端地址）。
- `src/protocol/shadowsocks/kcp.rs`：添加 `#![allow(dead_code)]`，消除编译警告。
- `Cargo.toml` / `Cargo.lock`：版本升级至 `1.0.8`。

### 验证命令与结果
- `cargo fmt --check`：通过（退出码 0）。
- `cargo check --tests`：通过（退出码 0，0 warnings）。
- `cargo test --lib protocol::shadowsocks`：29 passed; 0 failed（退出码 0）。
- `cargo test`：202 passed; 0 failed; 0 ignored（退出码 0，全套测试全部绿灯）。

### 剩余问题与下一步
- 无剩余未解决的 Shadowsocks 2022 规范与实现问题。
- CI 维持纯 Linux musl 多架构打包（x86_64 与 aarch64），绝无 Windows 发布产物。
