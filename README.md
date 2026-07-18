# Go Reauth Proxy

一个基于 Go 的本地优先反向代理，支持：
- 路由规则热更新
- 全局认证接入（登录跳转 + Rust AuthBridge 鉴权/预检）
- 同端口 HTTP/HTTPS（动态证书切换）
- 内部 gRPC 控制面（`GO_BACKEND_PORT`，仅绑定 loopback）
- iptables/ip6tables 白黑名单与默认拒绝策略

## 目录

- [项目定位](#项目定位)
- [核心能力](#核心能力)
- [运行架构](#运行架构)
- [快速开始](#快速开始)
- [配置文件说明](#配置文件说明)
- [规则匹配与转发行为](#规则匹配与转发行为)
- [认证与内部通信](#认证与内部通信)
- [内部 gRPC 控制面](#内部-grpc-控制面)
- [iptables 说明](#iptables-说明)
- [日志与可观测性](#日志与可观测性)
- [项目结构](#项目结构)
- [开发命令](#开发命令)
- [注意事项](#注意事项)
- [License](#license)

## 项目定位

`go-reauth-proxy` 适合部署在内网或本机网关位置，把多个本地服务统一收口到一个代理端口，并通过独立认证服务做访问控制。

它的设计重点是：
- 内部 gRPC 控制面只监听 `127.0.0.1` / `::1`
- Go-Rust 内部通信使用 gRPC，不保留 HTTP fallback
- 代理目标限制为内网/回环地址
- 配置改动自动持久化到 `config.json`

## 核心能力

- 动态路由规则（`POST /api/rules` 全量替换）
- 路径前缀匹配 + `StripPath` + HTML 绝对路径重写
- `UseAuth` 场景下自动插入悬浮切换工具栏
- `UseRootMode` 支持：将命中路径写入 cookie 后重定向到根路径
- 认证前置预检（通过 AuthBridge 返回 deny/redirect 决策）
- 认证失败自动跳转到 `/__auth__/login?redirect_uri=...`
- 动态 SSL 证书上传/清除（同一代理端口自动启停 HTTPS）
- 代理流量统计（入/出字节、活跃登录用户、5xx 计数）
- iptables/ip6tables 链初始化、白名单、黑名单、block-all/allow-all

## 运行架构

- 代理服务端口：默认 `7999`
- 内部 gRPC 端口：默认 `7996`（`GO_BACKEND_PORT` / `-admin-port`，固定绑定 loopback）
- 认证服务端口：默认 `7997`（Rust HTTP 认证页面与登录 API，由 `auth_config.auth_port` 指定）

代理端口通过 `cmux` 同时处理：
- 明文 HTTP
- TLS(HTTPS)

当配置了证书后，明文 HTTP 请求会被 `307` 重定向到 HTTPS。

Rust 后端作为客户端连接 `127.0.0.1:${GO_BACKEND_PORT}`，建立长生命周期 AuthBridge stream。Go 通过该 stream 发送联合 `AuthorizeHttp`（旧后端自动回退 `VerifyAuth` + `PreflightAuth`）和 `VerifyStreamAuth` 请求，不再直接通过 HTTP 请求 Rust 鉴权接口。

滚动发布联合鉴权协议时应先发布 Rust 后端、再发布 Go 网关；Go 会通过 `authorize_http_v1` capability 协商，在旧 Rust 后端上自动保持原有双调用流程。

`proxy_protocol_force=true` 时，代理监听地址会从 `0.0.0.0/::` 切换为 `127.0.0.1/::1`，并优先从 `X-Forwarded-For` / `X-Real-IP` 获取客户端 IP。

`gateway_listener.scope` 独立控制代理监听范围，取值为 `loopback` 或 `all`。Windows 新配置默认 `loopback`，其他平台为兼容旧部署默认 `all`；`proxy_protocol_force=true` 始终拥有更高优先级并保持只监听 loopback。

## 快速开始

### 1. 环境要求

- Go `1.26.5+`（见 `go.mod`；模块语言版本仍兼容 Go 1.25）
- 可选：`task`（推荐）
- 若使用防火墙 API：Linux + `iptables/ip6tables` + `sudo` 权限

### 2. 启动

使用 Task：

```bash
export FN_KNOCK_INTERNAL_RPC_TOKEN=dev-local-token
task run -- -proxy-port 7999 -admin-port 7996 -c ./config.json
```

或直接运行：

```bash
FN_KNOCK_INTERNAL_RPC_TOKEN=dev-local-token go run ./cmd/server -proxy-port 7999 -admin-port 7996 -c ./config.json
```

可用启动参数：
- `-proxy-port`：代理端口，默认 `7999`
- `-admin-port`：管理端口，默认 `7996`。传 `0` 时回退到配置文件 `admin_port`
- `-c`：配置文件路径（可传目录，自动补 `config.json`）

### 3. 内部契约

`7996` 默认是内部 gRPC 端口，不提供 HTTP Admin API 或浏览器文档页面。控制面由 Rust 后端通过共享 proto 调用，浏览器管理后台继续访问 Rust 后端暴露的 HTTP 管理接口。

内部 gRPC 必须配置独立 metadata token：`FN_KNOCK_INTERNAL_RPC_TOKEN`。部署脚本会生成并持久化该 token；手动启动时未设置则拒绝启动。

## 配置文件说明

配置文件默认名：`config.json`

默认值（首次运行自动写入）：

```json
{
  "rules": [],
  "default_route": "/__select__",
  "auth_config": {
    "auth_port": 7997,
    "auth_url": "/api/auth/verify",
    "login_url": "/login",
    "logout_url": "/api/auth/logout",
    "preflight_url": "/api/auth/preflight",
    "edge_client_ip_enabled": false,
    "aliyun_esa_enabled": false,
    "tencent_edgeone_enabled": false,
    "public_http_port": 80,
    "public_https_port": 443
  },
  "admin_port": 7996,
  "proxy_protocol_force": false,
  "gateway_listener": {
    "scope": "all"
  },
  "reverse_proxy_throttle": {
    "enabled": true,
    "requests_per_second": 100,
    "burst": 200,
    "block_seconds": 30
  },
  "iptables_chain_name": "",
  "ssl_cert": "",
  "ssl_key": ""
}
```

字段说明：

- `rules`: 路由规则数组
- `default_route`: 根路径 `/` 的默认去向，默认 `"/__select__"`
- `auth_config`: 全局认证配置
- `auth_config.edge_client_ip_enabled`: 边缘网络来源 IP 识别总开关；关闭时 `aliyun_esa_enabled` 与 `tencent_edgeone_enabled` 都不生效
- `auth_config.aliyun_esa_enabled`: 启用阿里云 ESA 模式；与 `tencent_edgeone_enabled` 互斥；来源 IP 优先读取 `Ali-Real-Client-IP`，缺失时回退到 `X-Forwarded-For`
- `auth_config.tencent_edgeone_enabled`: 启用腾讯 EdgeOne 模式；与 `aliyun_esa_enabled` 互斥；来源 IP 优先读取 `EO-Connecting-IP`，缺失时回退到 `X-Forwarded-For`
- `auth_config.public_http_port`: 可选，显式指定对外暴露的 HTTP 端口
- `auth_config.public_https_port`: 可选，显式指定对外暴露的 HTTPS 端口
- `admin_port`: 内部 gRPC 端口（仅在 `-admin-port=0` 时作为回退）
- `proxy_protocol_force`: 是否强制按 PROXY protocol 场景处理来源 IP
- `gateway_listener.scope`: 代理监听范围；Windows 新安装默认 `loopback`，显式允许局域网访问时设置为 `all`
- `reverse_proxy_throttle`: 反代数据面节流配置，作用于命中 host/path 规则的请求以及 `__auth__` 认证代理路径，不影响 `admin-port`、`/__select__`
- `reverse_proxy_throttle.enabled`: 是否启用节流
- `reverse_proxy_throttle.requests_per_second`: 单个客户端 IP 每秒允许的请求数
- `reverse_proxy_throttle.burst`: 单个客户端 IP 可瞬时突发的令牌数
- `reverse_proxy_throttle.block_seconds`: 超限后直接断开连接的封禁时长；被中断的请求不会写 access log
- `iptables_chain_name`: iptables 链名（默认 `REAUTH_FW`）
- `ssl_cert` / `ssl_key`: PEM 证书与私钥（由控制面写入）

一个常见配置示例：

```json
{
  "reverse_proxy_throttle": {
    "enabled": true,
    "requests_per_second": 100,
    "burst": 200,
    "block_seconds": 30
  }
}
```

当网关运行在非标准本地端口上，但前面存在 NAT 或转发时，这两个字段可用于修正网关生成的公开跳转地址。

例如本地监听 `7999`，并希望外部访问 `http://fnos.fnknock.xyz/` 时跳转到 `https://fnos.fnknock.xyz:7999/`，可配置：

```json
{
  "auth_config": {
    "public_http_port": 80,
    "public_https_port": 7999,
    "public_auth_base_url": "https://auth.fnknock.xyz:7999"
  }
}
```

## 规则匹配与转发行为

单条规则结构：

```json
{
  "path": "/app",
  "target": "http://127.0.0.1:8080",
  "use_auth": true,
  "strip_path": true,
  "rewrite_html": true,
  "use_root_mode": false
}
```

行为细节：

- 按最长前缀匹配 `path`
- `GET /app` 会 301 到 `/app/`（规则非 `/` 时）
- `strip_path=true`：转发时去掉匹配前缀
- `rewrite_html=true`：重写 HTML 中 `href/src/action/<base href>` 的绝对路径
- `use_auth=true`：转发前通过 AuthBridge 请求 Rust 后端完成鉴权，并在 HTML 注入悬浮工具栏
- `use_root_mode=true`：命中后写入 `__proxy_path` cookie 并 302 到 `/`

未命中时：
- 请求 `/` 且未配置任何 path/host 规则：返回 Welcome 页面
- 请求 `/` 且有 path 规则：
  - 若 `__proxy_path` cookie 对应到某条规则，则优先按该规则转发
  - 若 `default_route` 对应到某条规则，则按该规则转发
  - 否则跳转到 `/__select__`
- 其他未命中场景（包括 host 未命中，或仅配置 host 规则时访问 `/`）：返回 No Matching Route 页面（404）

## 认证与内部通信

Go 数据面不再直接通过 HTTP 请求 `auth_config.auth_url` 或 `auth_config.preflight_url`。鉴权由 Rust 后端建立的 AuthBridge gRPC stream 承载：

- HTTP 数据面鉴权：Go 发送 `VerifyAuth`
- HTTP 预检：Go 发送 `PreflightAuth`；bridge 短暂失败时进入 cooldown 并跳过预检，不阻断主请求
- TCP/UDP Stream 鉴权：Go 发送 `VerifyStreamAuth`

Go 会把以下请求上下文放入 typed `AuthContext`：

- `Cookie`
- `Authorization`
- `Ali-Real-Client-IP`（启用 `auth_config.edge_client_ip_enabled=true` 且 `auth_config.aliyun_esa_enabled=true` 时）
- `EO-Connecting-IP`（启用 `auth_config.edge_client_ip_enabled=true` 且 `auth_config.tencent_edgeone_enabled=true` 时）
- `X-Real-IP`
- `X-Forwarded-For`
- `X-Forwarded-Path`

### 内置认证代理路径

- `/__auth__/login` -> `auth_config.login_url`
- `/__auth__/api/auth/logout` -> `auth_config.logout_url`
- `/__auth__/*` -> 透传到 Rust HTTP 认证服务对应路径

## 内部 gRPC 控制面

`GO_BACKEND_PORT` 上启动的是纯 gRPC server，只服务本机 Rust 后端，不提供 Go Admin HTTP 兼容层。内部调用使用独立 metadata token `FN_KNOCK_INTERNAL_RPC_TOKEN` 校验；该 token 不应复用会暴露给浏览器认证页的 `HMAC_SECRET`。

当前 Go 侧实现的服务包括：

- `GatewayControlService`
- `GatewayLogsService`
- `SecurityService`
- `TrafficService`
- `WafService`
- `SslService`
- `FirewallService`
- `AuthBridgeService`

标准 `grpc.health.v1` 服务同时注册并受相同 token 保护，服务名为 `fnknock.gateway.process`、`fnknock.gateway.dataplane` 和 `fnknock.gateway.auth_bridge`。`ServerInfo` 暴露版本、OS/架构、控制协议版本、commit 与 capability；`RequestShutdown` 用于服务监督进程触发幂等优雅退出。

非 Linux 平台仍注册 `FirewallService`，但所有方法统一返回 gRPC `Unimplemented`，并且 `ServerInfo.capabilities` 不包含 `firewall.iptables`。

浏览器管理后台应访问 Rust 后端 HTTP 管理接口，由 Rust 负责把前端 JSON envelope 映射到 Go gRPC 控制面。

## iptables 说明

`init` 后会创建/重建自定义链，并应用基础规则：

1. 放行 `lo`
2. 放行 `ESTABLISHED,RELATED`
3. 放行本地网段（v4/v6）
4. 放行 ICMP（IPv4 `icmp` / IPv6 `ipv6-icmp`）
5. 放行 `exempt_ports`
6. 默认 `DROP`

说明：
- 默认链名：`REAUTH_FW`
- 默认父链：`INPUT` 和 `DOCKER-USER`
- 命令通过 `sudo iptables` / `sudo ip6tables` 执行

## 日志与可观测性

- 控制台常规日志默认不输出，避免内部控制面轮询和反代运行日志刷屏；需要排查时可设置 `GO_REPROXY_LOG=1` 开启
- 反代访问明细写入日志文件，由配置项 `logging.enabled` 控制，默认关闭
- 可选设置 `GO_REPROXY_DIAGNOSTICS_ADDR=127.0.0.1:6060` 开启 `/debug/pprof/*` 与 `/debug/metrics`；只接受 loopback 地址，并要求请求携带 `x-fn-knock-internal-rpc-token: $FN_KNOCK_INTERNAL_RPC_TOKEN`（或同值 Bearer token）。未设置时不会启动诊断监听器
- `TrafficService` 返回：
  - `total_in` / `total_out`
  - `active_conns`（最近 2 分钟活跃已登录身份）
  - `error_5xx`
  - `by_host[].active_ip_count`（子域名最近 2 分钟活跃 IP 数）
- 活跃 IP 查询返回单个子域名最近 2 分钟活跃 IP 列表，包含 IP、最近活跃时间和当前未结束请求数

## 项目结构

```text
cmd/server/           # 网关入口与内部 gRPC server
pkg/admin/            # gRPC 控制面服务实现
pkg/grpc/pb/          # 生成的 Go gRPC/protobuf 代码
pkg/rpcbridge/        # AuthBridge 管理器与内部 token 校验
pkg/proxy/            # 反向代理核心逻辑
pkg/config/           # 配置加载与持久化
pkg/iptables/         # iptables 管理
pkg/response/         # 内置页面与响应封装
pkg/middleware/       # 日志/CORS 中间件
```

## 开发命令

```bash
task build            # 构建 macOS、Linux 与 Windows 目标
task build:mac
task build:linux
task build:linux-arm64
task build:linux-arm
task build:windows    # Windows x86_64，CGO=0，不使用 UPX
task run
task test
task docs
```

## 注意事项

- 内部 gRPC 控制面仅监听本地回环地址，不会对外暴露
- 代理目标不再限制为内网地址；仅阻止把目标直接指向本机管理端口
- `POST /api/rules` 是全量覆盖，不是增量追加
- SSL 证书与私钥会写入 `config.json` 明文保存，请注意文件权限
- `GO_BACKEND_PORT` 是 gRPC 协议，不能再用 `curl http://127.0.0.1:7996/api/...` 访问 Go 控制面

## License

[MIT](./LICENSE)
