# Go Reauth Proxy

这是一个使用 Golang 编写的轻量级反向代理服务，支持通过 API 动态管理代理规则和 iptables 防火墙策略。它集成了外部鉴权能力、鉴权结果缓存、WebSocket 支持、HTTP/2 支持、以及动态配置持久化等高级特性。

## 功能特性

*   **动态代理规则**：通过 API 随时添加、获取和全量覆盖反向代理规则。支持路径重写（Strip Path）、HTML 响应内容重写以及特殊的 Root 模式。
*   **IPTables 管理**：集成 iptables 管理功能，支持动态初始化自定义链、封禁/解封 IP、一键拒绝/允许所有流量以及查看当前规则。
*   **先进的全局鉴权集成**：
    *   **全局配置**：可以通过 API 动态管理全局鉴权服务端口及相关路径。
    *   **缓存机制**：鉴权通过后，结果在内存中缓存（默认 60 秒，可配置时间），极大提升性能。
    *   **失败跳转**：当鉴权失败或未提供凭证时，自动附带 `redirect_uri` 重定向至登录页面。
    *   **内置 auth 路由**：内置解析 `/__auth__/` 路径，将其自动代理到配置的鉴权服务，简化前后端部署。
*   **网络和性能优化**：
    *   **WebSocket 支持**：原生支持 WebSocket 的反向代理。
    *   **HTTP/2 支持**：当启用 SSL 时，自动开启并支持 HTTP/2，并且反向代理传输层（Transport）也启用了 ForceAttemptHTTP2 提升与上游服务器的通信效率。
*   **动态 SSL 支持**：可通过 API 动态上传证书和私钥，一键开启可自动重定向的 HTTPS 服务。
*   **持久化配置**：所有的代理规则、默认路由、鉴权配置和 SSL 证书变更将自动持久化至执行目录下的 `config.json` 中，重启服务不会丢失配置。
*   **API 文档与安全设计**：
    *   **Swagger API**：内置 Swagger UI，访问管理端口 `/docs` 即可进行可视化调试。
    *   **安全绑定**：管理 API (Admin Port) 仅绑定在 `127.0.0.1`，防范公网未授权访问。代理目标禁止配置外部非内网地址。预留路径（以 `__` 开头）不可被用户规则覆盖。

## 快速开始

本项目推荐使用 [Taskfile](https://taskfile.dev/) 进行构建和运行管理。如果您的系统尚未安装，可以使用 `brew install go-task` (macOS) 或者参考[官方文档](https://taskfile.dev/installation/)进行安装。

### 1. 编译

使用 Taskfile 一键编译所有版本（macOS ARM64 和 Linux AMD64）。Linux 版本编译时如果存在 `upx` 会自动进行压缩优化：

```bash
task build
```

编译产物将输出至 `build/` 目录下。您也可以单独编译特定平台：

```bash
task build:mac    # 仅编译 macOS (ARM64) 版本
task build:linux  # 仅编译 Linux (AMD64) 版本
```

### 2. 运行

启动代理服务与管理服务（默认代理端口 9090，管理端口 9091）：

```bash
task run -- -proxy-port 9090 -admin-port 9091 -auth-cache-expire 60
```

服务同时提供了示例用的鉴权节点服务器，您可以用如下命令将其启动：

```bash
task run:auth-server -- -port 7997
```

*   **启动参数说明**：
    *   `-proxy-port`: 反向代理监听端口 (默认 9090，绑定 0.0.0.0)。
    *   `-admin-port`: 管理 API 监听端口 (默认 9091，绑定 127.0.0.1)。
    *   `-auth-cache-expire`: 成功鉴权的缓存时间（秒），默认为 60 秒。

持久化文件 `config.json` 会在首次运行并在发生配置改变时被自动写入到二进制文件的同一目录下。

## API 文档与调试

启动服务后，访问以下地址查看完整的 API 文档：

`http://127.0.0.1:9091/docs/index.html`

*(注：请将 `9091` 替换为您实际配置的 `-admin-port` 端口)*

## 管理 API 示例

所有管理 API 均需要通过 Admin Port (默认为 127.0.0.1:9091) 访问。

### 1. 代理规则管理

*   **全量覆盖/添加规则 (POST /api/rules)**
    每次调用此接口将清除现有规则，使用传入的数组作为当前的总规则。
  ```json
  [
    {
      "path": "/api",
      "target": "http://127.0.0.1:8080",
      "use_auth": true,
      "strip_path": true,
      "rewrite_html": true,
      "use_root_mode": false
    }
  ]
  ```
*   **获取现有规则 (GET /api/rules)**
*   **清空所有规则 (DELETE /api/rules)**

### 2. 全局配置与状态

*   **设置默认未匹配路由走向 (POST /api/config/default-route)**
    配置访问根目录 `/` 时的行为，默认为 `/__select__`（代理选择页面）。
  ```json
  { "default_route": "/another-route" }
  ```
*   **设置全局鉴权配置 (POST /api/auth)**
    设置鉴权服务器端口及相对路径等参数：
  ```json
  {
    "auth_port": 7997,
    "auth_url": "/auth",
    "login_url": "/login",
    "auth_cache_expire": 60
  }
  ```
*   **配置动态 SSL 证书 (POST /api/ssl)**
  ```json
  {
    "cert": "-----BEGINCERTIFICATE-----\n...",
    "key": "-----BEGIN RSA PRIVATE KEY-----\n..."
  }
  ```
*   **清除 SSL 证书 (DELETE /api/ssl)**

### 3. IPTables 管理

*   **初始化自定义链 (POST /api/iptables/init)**
    初始化 iptables 链（默认名称为 REAUTH_FW），并挂载到如 INPUT 等父链上。
  ```json
  {
    "chain_name": "REAUTH_FW",
    "parent_chain": ["INPUT", "DOCKER-USER"],
    "exempt_ports": ["9090", "7999"]
  }
  ```
*   **封禁/解封单个 IP (POST /api/iptables/block | allow)**
  ```json
  {"ip": "192.168.1.100"}
  ```
*   **封禁所有流量 (POST /api/iptables/block-all)**
*   **允许所有流量 (POST /api/iptables/allow-all)**
*   **查看规则 (GET /api/iptables/list)**
*   **清空链规则 (POST /api/iptables/flush)**
*   **清理销毁链 (POST /api/iptables/clean)**

## 📄 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.
