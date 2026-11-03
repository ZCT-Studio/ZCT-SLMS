# ZCT-SLMS

软件授权验证平台后端，提供应用、卡密、账号、工单和内容审查接口。

## 技术栈

C++ · Drogon · OpenSSL · Argon2id · SQLite / PostgreSQL / MySQL

## 快速开始

安装 Docker 后，在项目根目录执行：

```sh
docker compose up -d --build
docker compose logs -f verifier
```

默认地址：`http://localhost:17112`。检查服务：

```sh
curl http://localhost:17112/api/v1/ping
```

首次启动自动生成管理员账号和一次性密码，请从启动日志获取并完成首次设置。WebUI 默认端口为 `17316`，在前端项目中单独启动。

## 配置

- 本机运行默认读取 `config/config.yaml`，也可通过程序第一个参数指定配置文件。
- Docker 默认绑定 `127.0.0.1:17112`；使用 `ZCT_SLMS_BIND_ADDRESS` 和 `ZCT_SLMS_PORT` 调整宿主机监听地址、端口。
- 平台设置管理运行配置、SMTP 和邮件模板；安全设置管理注册、第三方登录、2FA、人机验证与权限策略。
- Microsoft、GitHub、短信、SMTP 等服务需填写自己的凭据。通行密钥需使用 HTTPS 或 localhost。

Docker 使用 `zct_slms-config`、`zct_slms-data`、`zct_slms-logs` 卷保存配置、数据与日志。更新使用 `docker compose up -d --build`，停止使用 `docker compose down`。

升级前备份数据库、配置与 `data/auth-master.key`；三者需配套恢复。`docker compose down -v` 会删除数据卷，不用于普通停止或升级。

## 发布平台

二进制发布仅保留 Linux x64、Linux ARM64、Windows x64。macOS、x86、ARMv7 和 Windows ARM64 不再构建或发布。

推送任意分支上的 `v*` tag 后，三个二进制平台构建成功，且两种 Linux 镜像完成启动检查后，发布 Docker 镜像索引和 Release。tag 含 `-` 为预发布，不更新 `latest`。

| Docker 平台 | 独立镜像标签示例 |
| --- | --- |
| Linux x64 (`linux/amd64`) | `ghcr.io/zct-studio/zct-slms:v2.0.1-linux-amd64` |
| Linux ARM64 (`linux/arm64`) | `ghcr.io/zct-studio/zct-slms:v2.0.1-linux-arm64` |

公共版本标签（如 `:v2.0.1`，稳定版还有 `:latest`）包含这两种 Linux 架构，Docker 自动选择匹配的镜像。Windows x64 不发布 Windows 容器镜像；在 Windows 上使用 Docker Desktop 的 Linux containers 模式即可运行 Linux 镜像。版本号替换为已发布版本，例如：

```sh
docker pull ghcr.io/zct-studio/zct-slms:v2.0.1
```

本地构建及持久化配置继续使用现有 Compose。

## 本地构建

安装 CMake、受支持的 C++ 工具链及 vcpkg 依赖后执行：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 2
```

程序位于 `build/bin`（多配置生成器位于 `build/bin/Release`）。运行时保留配置与 `migrations/`，工作目录应能访问这些文件。

## 主要功能

- 应用资料、版本、公告、签名、加密和心跳验证。
- 卡密生成、绑定、封禁、计时、余额与兑换码。
- 用户、子用户、管理员和支持账号及安全验证。
- 工单、图片材料、邮件通知、内容审查与屏蔽词过滤。

接口统一使用 `/api/v1/`。独立文档站与 GitHub Pages 部署暂时移除。

## 许可证

见 [LICENSE](LICENSE)。
