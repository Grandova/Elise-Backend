# 🚀 支持协议

> 当前以下协议及组合均已完成实际连接测试。
> **测试环境：Xboard + Clash**
> **状态说明：✅ 测试通过**

------

## 📊 支持概览

| 协议        | 测试项 | 状态  |
| ----------- | ------ | ----- |
| SOCKS5      | 1      | ✅     |
| VMess       | 7      | ✅     |
| AnyTLS      | 3      | ✅     |
| Shadowsocks | 19     | ✅     |
| Trojan      | 6      | ✅     |
| Hysteria2   | 1      | ✅     |
| VLESS       | 6      | ✅     |
| HTTP        | 1      | ✅     |
| **总计**    | **44** | **✅** |

------

## SOCKS5

| 协议 / 组合 | 状态   | 测试环境       |
| ----------- | ------ | -------------- |
| SOCKS5      | ✅ 通过 | Xboard + Clash |

------

## VMess

| 协议 / 组合                    | 状态   | 测试环境       |
| ------------------------------ | ------ | -------------- |
| VMess TCP                      | ✅ 通过 | Xboard + Clash |
| VMess WebSocket                | ✅ 通过 | Xboard + Clash |
| VMess WebSocket + TLS          | ✅ 通过 | Xboard + Clash |
| VMess gRPC                     | ✅ 通过 | Xboard + Clash |
| VMess HTTPUpgrade              | ✅ 通过 | Xboard + Clash |
| VMess HTTP/2 + No Security TLS | ✅ 通过 | Xboard + Clash |
| VMess HTTP/2 + TLS             | ✅ 通过 | Xboard + Clash |

------

## AnyTLS

| 协议 / 组合              | 状态   | 测试环境       |
| ------------------------ | ------ | -------------- |
| AnyTLS + No Security TLS | ✅ 通过 | Xboard + Clash |
| AnyTLS + TLS             | ✅ 通过 | Xboard + Clash |
| AnyTLS + TLS + ECH       | ✅ 通过 | Xboard + Clash |

------

## Shadowsocks

### 基础加密

| 加密方式                        | 状态   | 测试环境       |
| ------------------------------- | ------ | -------------- |
| `aes-128-gcm`                   | ✅ 通过 | Xboard + Clash |
| `aes-192-gcm`                   | ✅ 通过 | Xboard + Clash |
| `aes-256-gcm`                   | ✅ 通过 | Xboard + Clash |
| `chacha20-ietf-poly1305`        | ✅ 通过 | Xboard + Clash |
| `2022-blake3-aes-128-gcm`       | ✅ 通过 | Xboard + Clash |
| `2022-blake3-aes-256-gcm`       | ✅ 通过 | Xboard + Clash |
| `2022-blake3-chacha20-poly1305` | ✅ 通过 | Xboard + Clash |

### Simple Obfs

| 协议 / 组合                               | 状态   | 测试环境       |
| ----------------------------------------- | ------ | -------------- |
| SS `aes-128-gcm` + Simple Obfs            | ✅ 通过 | Xboard + Clash |
| SS `chacha20-ietf-poly1305` + Simple Obfs | ✅ 通过 | Xboard + Clash |

### V2Ray Plugin

| 协议 / 组合                                              | 状态   | 测试环境       |
| -------------------------------------------------------- | ------ | -------------- |
| SS `chacha20-ietf-poly1305` + V2Ray Plugin + WS + No TLS | ✅ 通过 | Xboard + Clash |
| SS `chacha20-ietf-poly1305` + V2Ray Plugin + WS + TLS    | ✅ 通过 | Xboard + Clash |

### Gost Plugin

| 协议 / 组合                                     | 状态   | 测试环境       |
| ----------------------------------------------- | ------ | -------------- |
| SS `chacha20-ietf-poly1305` + Gost Plugin + TLS | ✅ 通过 | Xboard + Clash |
| SS `aes-128-gcm` + Gost Plugin + WS + TLS       | ✅ 通过 | Xboard + Clash |

### ShadowTLS

| 协议 / 组合                                | 状态   | 测试环境       |
| ------------------------------------------ | ------ | -------------- |
| SS `aes-128-gcm` + ShadowTLS v3            | ✅ 通过 | Xboard + Clash |
| SS `chacha20-ietf-poly1305` + ShadowTLS v3 | ✅ 通过 | Xboard + Clash |

### ResTLS

| 协议 / 组合                          | 状态   | 测试环境       |
| ------------------------------------ | ------ | -------------- |
| SS `aes-128-gcm` + ResTLS            | ✅ 通过 | Xboard + Clash |
| SS `chacha20-ietf-poly1305` + ResTLS | ✅ 通过 | Xboard + Clash |

### KCPTun

| 协议 / 组合                          | 状态   | 测试环境       |
| ------------------------------------ | ------ | -------------- |
| SS `aes-128-gcm` + KCPTun            | ✅ 通过 | Xboard + Clash |
| SS `chacha20-ietf-poly1305` + KCPTun | ✅ 通过 | Xboard + Clash |

------

## Trojan

| 协议 / 组合                           | 状态   | 测试环境       |
| ------------------------------------- | ------ | -------------- |
| Trojan TCP + TLS + uTLS + ECH         | ✅ 通过 | Xboard + Clash |
| Trojan WebSocket + TLS + uTLS + ECH   | ✅ 通过 | Xboard + Clash |
| Trojan gRPC + TLS + uTLS + ECH        | ✅ 通过 | Xboard + Clash |
| Trojan HTTPUpgrade + TLS + uTLS + ECH | ✅ 通过 | Xboard + Clash |
| Trojan Reality TCP + uTLS + ECH       | ✅ 通过 | Xboard + Clash |
| Trojan Reality gRPC + uTLS + ECH      | ✅ 通过 | Xboard + Clash |

------

## Hysteria2

| 协议 / 组合                        | 状态   | 测试环境       |
| ---------------------------------- | ------ | -------------- |
| Hysteria2 + Salamander + TLS + ECH | ✅ 通过 | Xboard + Clash |

------

## VLESS

| 协议 / 组合                                                  | 状态   | 测试环境       |
| ------------------------------------------------------------ | ------ | -------------- |
| VLESS TCP + TLS + uTLS + ECH                                 | ✅ 通过 | Xboard + Clash |
| VLESS WebSocket + TLS + uTLS + ECH                           | ✅ 通过 | Xboard + Clash |
| VLESS gRPC + TLS + uTLS + ECH                                | ✅ 通过 | Xboard + Clash |
| VLESS HTTPUpgrade + TLS + uTLS + ECH                         | ✅ 通过 | Xboard + Clash |
| VLESS Reality TCP + uTLS + `xtls-rprx-vision`                | ✅ 通过 | Xboard + Clash |
| VLESS Reality TCP + uTLS + `xtls-rprx-vision` + VLESS Encryption | ✅ 通过 | Xboard + Clash |

------

## HTTP

| 协议 / 组合 | 状态   | 测试环境       |
| ----------- | ------ | -------------- |
| HTTP Proxy  | ✅ 通过 | Xboard + Clash |