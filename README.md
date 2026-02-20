# Go Reauth Proxy

这是一个使用 Golang 编写的轻量级反向代理服务，支持通过 API 动态管理代理规则和 iptables 防火墙策略。它集成了外部鉴权能力，并支持鉴权结果缓存，以及鉴权失败后的自动跳转。

## 功能特性

*   **动态代理规则**：通过 API 随时添加、删除反向代理规则。
*   **IPTables 管理**：集成 iptables 管理功能，支持动态封禁/解封 IP。
*   **外部鉴权集成**：
    *   **鉴权 URL**：支持配置 `auth_url`，代理服务会将请求头转发至该 URL 进行验证。
    *   **缓存机制**：鉴权通过后，结果在内存中缓存 5 分钟。
    *   **失败跳转**：支持配置 `login_url`，当鉴权失败（401/403）时自动重定向。
*   **API 文档**：集成 Swagger UI，方便查看和调试 API。
*   **安全设计**：管理 API (Admin Port) 仅绑定在 `127.0.0.1`，防止公网暴露。

## 快速开始

本项目推荐使用 [Taskfile](https://taskfile.dev/) 进行构建和运行管理。如果您的系统尚未安装，可以使用 `brew install go-task` (macOS) 或者参考[官方文档](https://taskfile.dev/installation/)进行安装。

### 1. 编译

使用 Taskfile 一键编译所有版本（macOS ARM64 和 Linux AMD64）：

```bash
task build
```

编译产物将输出至 `build/` 目录下。您也可以单独编译特定平台：

```bash
task build:mac    # 仅编译 macOS (ARM64) 版本
task build:linux  # 仅编译 Linux (AMD64) 版本
```

或者使用原生 Go 命令：

```bash
# MacOS ARM64
GOOS=darwin GOARCH=arm64 go build -o build/go-reauth-proxy-darwin-arm64 cmd/server/main.go

# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o build/go-reauth-proxy-linux-amd64 cmd/server/main.go
```

### 2. 运行

启动服务（默认代理端口 9090，管理端口 9091）：

使用 Taskfile 运行（支持附加参数）：

```bash
task run -- -proxy-port 8090 -admin-port 8091
```

或者使用二进制文件运行：

```bash
./go-reauth-proxy -proxy-port 8090 -admin-port 8091
```

*   参数说明：
    *   `-proxy-port`: 反向代理监听端口 (默认 9090，绑定 0.0.0.0)。
    *   `-admin-port`: 管理 API 监听端口 (默认 9091，绑定 127.0.0.1)。

## API 文档 (Swagger)

启动服务后，访问以下地址查看完整的 API 文档：

`http://127.0.0.1:8091/docs/index.html`

> 注意：请将 `8091` 替换为您实际配置的 `-admin-port`。

## 管理 API 示例

所有管理 API 均通过 Admin Port (e.g., 9091) 访问。

### 1. 代理规则管理

#### 添加/更新代理规则

*   **URL**: `POST /api/rules`
*   **Body**:

```json
[
  {
    "path": "/api",
    "target": "http://127.0.0.1:9000",
    "auth_url": "http://auth-service/verify",
    "login_url": "http://auth-service/login",
    "strip_path": true,
    "rewrite_html": true
  }
]
```

#### 获取当前规则

*   **URL**: `GET /api/rules`

#### 删除规则

*   **URL**: `POST /api/rules/delete?path=/api`

### 2. IPTables 管理

#### 初始化链

*   **URL**: `POST /api/iptables/init`

#### 封禁 IP

*   **URL**: `POST /api/iptables/block`
*   **Body**: `{"ip": "192.168.1.100"}`

#### 解封 IP

*   **URL**: `POST /api/iptables/allow`
*   **Body**: `{"ip": "192.168.1.100"}`


## 📄 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.
