# Strix 网页与双接口扫描服务

**当前版本为 v0.2.1，已提供管理员与员工网页。优先阅读 [网页部署与使用](网页部署与使用.md)。以下为 v0.1.0 API 试点说明，令牌/PowerShell 流程仅供程序接入参考，普通网页用户不再需要执行。**

面向公司内部试点的 API 封装，不修改 Strix 源码。同一个镜像有 API、Worker 两个启动角色；接收任务后异步扫描并产生 Markdown/JSON 报告。没有自定义网页，提供 `/docs` 接口调试页面。

本机 Windows Docker Desktop 已部署的试点请优先阅读 [本机接口测试指南](本机接口测试指南.md)，使用 compose.local.yaml。它与下面面向公司 Linux VM 的 compose.yaml 是两套配置；不要混用数据目录和启动命令。

## 接口

所有业务接口使用 `Authorization: Bearer <token>`。管理员为不同用户/项目签发不同令牌，任务和报告按令牌所属主体隔离。`/healthz` 和接口文档不需要令牌。此版不是 SSO、多租户商用平台。

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/v1/scans/whitebox` | multipart 上传 ZIP：project、name、authorized=true |
| POST | `/v1/scans/blackbox` | JSON：target、name、authorized=true |
| GET | `/v1/scans/{id}` | 任务状态、模型响应数、Token、报告地址 |
| GET | `/v1/scans/{id}/report` | 下载 Markdown；`?format=json` 下载 JSON |
| POST | `/v1/scans/{id}/cancel` | 取消排队或运行任务 |

提交接口返回 HTTP 202 和任务 ID，不会等待整场扫描。状态包括 queued、running、cancel_requested、completed、failed、timed_out、cancelled。进度是阶段和计数，不提供虚假的百分比。失败/超时的已执行任务也产生明确标注不完整的报告；排队阶段取消的任务不生成检测报告。

白盒默认 ZIP 最大 50 MiB、解压总量 500 MiB、最多 10000 条目，拒绝路径穿越、特殊文件、符号链接、加密 ZIP、大小写重复路径和明显压缩炸弹。HTTP multipart 需要 Content-Length；反向代理也必须限制请求体大小。

黑盒只接受 HTTP(S) 根地址，例如 `https://test.company/`，不接收用户密码、任意命令、回调地址或自定义提示词。使用精确域名、端口、DNS 解析 IP 范围三重白名单，出队前再次校验。不支持登录态录入、SSO 或验证码流程，本版本是匿名黑盒。

## 必须了解的部署边界

- **目标环境：专用 Linux VM + Docker Engine，amd64 已构建验证。** Compose 的 Worker 使用 host 网络，连接 Strix 绑定宿主机回环地址的 Caido。不能把本配置直接视作通用 Windows Desktop 部署。ARM 构建配置存在，但未验证。
- **不是 Docker-in-Docker。** 只有 Worker 挂载宿主机 Docker socket，由它启动同级沙箱。该 socket 具有接近宿主机 root 的能力，应放在专用扫描 VM；API 不挂载 socket。
- **源码目录必须在宿主机与 Worker 中使用完全相同的绝对路径。** Compose 已按此挂载 STRIX_DATA_DIR，否则沙箱会挂载错误路径。不要改成只有容器内存在的匿名卷路径。
- **网络隔离必须由管理员落实。** URL 检查与提示词无法阻止 DNS 重绑定、跨域重定向、待测代码出网或代理被页面诱导访问其他系统。必须在网络网关/虚拟机 Docker 转发链落实沙箱出站 ACL，只允许本任务授权的测试资产。白盒不得默认访问公司内网。禁止云元数据、主机管理地址和非授权资产。不要只依赖 UFW 对 Docker 转发流量的规则。
- `ENABLE_SCANS=false` 默认关闭提交；Worker 还要求 `EGRESS_POLICY_ACK=true`，表示管理员已经实施 ACL，**该变量本身不会创建防火墙规则**。同一串行 Worker 的项目应处于相同受控测试网络；需要不同网络权限的项目使用独立 Worker VM。
- 本服务不管理生产系统授权、扫描维护窗口或备份。先仅接入测试环境。只有项目负责人批准的资产才能加入白名单。
- 源码、系统响应及证据可能发送到模型供应商，接入公司数据前先确认允许的数据流及供应商政策。
- 每个任务独立源码副本、临时模型配置；默认一个 Worker 串行执行。超时/取消会终止 Strix 进程组并按精确 run-id 标签清理沙箱；清理失败停止继续取任务。Worker 重启将中断任务标为失败，不自动重复付费扫描。
- 默认沙箱 2 CPU、4 GiB RAM、512 进程，Worker 2 CPU/2 GiB；整台 VM 要留足宿主机余量。
- `--max-budget` 是估算，尤其硅基流动自定义路由可能没有成本计量。真正的费用限额应在公司模型网关/供应商侧实现。每任务另有 30 分钟墙钟时间、40 轮上限；无自动付费重试。
- **所有报告标记 review_required=true。** 原始文字报告、结构化漏洞和覆盖记录可能不一致；空列表不能等同安全通过。本轮演示已出现过此问题。
- 当前未实现自动保留期清理、磁盘配额、公司 SSO、用户级速率控制和 PDF。数据留在 STRIX_DATA_DIR，包括源码、日志及凭据以外的敏感测试内容；管理员需安排磁盘监控、备份、保留期和访问审计后再扩大使用。

## Linux VM 部署

下面涉及 Docker 安装、目录权限、防火墙等管理员操作应由公司管理员执行；本次没有在你的电脑修改这些系统配置。

1. 按 Docker 官方 Ubuntu 仓库方式安装 Docker Engine + Compose 插件：https://docs.docker.com/engine/install/ubuntu/ 。
2. 把本源码目录复制到 Linux VM，例如 `/opt/strix-service`，进入该目录。
3. 导入提供的镜像，或从源码构建：

```bash
docker load -i /path/to/strix-service-0.1.0-linux-amd64.tar
# 或：
docker build -t strix-service:0.1.0 .
docker pull ghcr.io/usestrix/strix-sandbox:1.3.0@sha256:f6906c3114e504fd1a218fcf028d7a0e46851118403a438b63956de6ea7c4331
```

4. 准备配置及密钥（不要提交 secrets 到 Git）：

```bash
cp .env.example .env
mkdir -p secrets
chmod 700 secrets
# 管理员创建 /srv/strix-data，建议权限 0700；数据根路径不要使用符号链接。
# 在 secrets/service-tokens.json 中配置：
# {"security-team":"至少32字符的随机服务令牌","project-a":"另一条独立随机令牌"}
# 把模型 API Key 单独写入 secrets/llm-key.txt，一行，不要带引号。
chmod 600 secrets/*
```

可用 `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'` 在本地生成令牌。模型 Key 只在 Worker 中以 Docker secret 文件挂载，不写入镜像、Compose 文件或提交接口。令牌文件只挂 API。Compose secrets 在单机模式本质是文件挂载，宿主机权限仍重要。

5. 编辑 `.env` 中目标域名、IP 范围、模型地址和限制。网络侧落实 ACL、确认数据处理权限后才设置：

```dotenv
ENABLE_SCANS=true
EGRESS_POLICY_ACK=true
```

6. 启动并检查：

```bash
docker compose config --quiet
docker compose up -d
docker compose ps
curl --fail http://127.0.0.1:8080/healthz
docker compose logs --tail=50 worker
```

API 默认只发布宿主机 `127.0.0.1:8080`。公司入口使用 HTTPS 反向代理到这个地址，并限制公司 VPN/来源 IP；不要直接对公网开放 8080、Docker API 或沙箱端口。参考 nginx 配置在 nginx.example.conf，TLS 证书和 SSO 按公司环境配置。

## 调用示例（Linux curl）

```bash
# 服务令牌在本地输入，不写入示例源码。
read -rsp 'Service token: ' SERVICE_TOKEN; echo
export SERVICE_TOKEN

# 白盒：项目 ZIP，不要包含生产密钥或无关数据。
curl --fail-with-body http://127.0.0.1:8080/v1/scans/whitebox \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -F authorized=true -F name=my-project -F project=@project.zip

# 黑盒：目标必须已在管理员白名单。
curl --fail-with-body http://127.0.0.1:8080/v1/scans/blackbox \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"test-system","target":"https://test.example.company","authorized":true}'

# 将 JOB_ID 替换为提交接口返回的 id。
curl --fail-with-body "http://127.0.0.1:8080/v1/scans/$JOB_ID" \
  -H "Authorization: Bearer $SERVICE_TOKEN"
curl --fail-with-body "http://127.0.0.1:8080/v1/scans/$JOB_ID/report" \
  -H "Authorization: Bearer $SERVICE_TOKEN" -o report.md
curl --fail-with-body "http://127.0.0.1:8080/v1/scans/$JOB_ID/report?format=json" \
  -H "Authorization: Bearer $SERVICE_TOKEN" -o report.json
unset SERVICE_TOKEN
```

也可访问受保护入口下的 `/docs`，点击 Authorize 输入服务令牌后调试。`openapi.json` 已导出便于接入前端或公司平台。

## 构建、验证与研究

```bash
docker build -t strix-service:0.1.0 .
docker build -f Dockerfile.test -t strix-service-tests:0.1.0 .
docker run --rm strix-service:0.1.0 strix --version
docker save -o strix-service-0.1.0-linux-amd64.tar strix-service:0.1.0
```

Strix 固定 1.7.0，使用 usestrix/strix 官方 GitHub Release 二进制并校验 SHA256，没有把当前本地 Key/配置打包。依赖直接版本固定，完整解析版本另存 requirements.lock.txt。Strix upstream Apache-2.0 许可见 STRIX-LICENSE；本项目不代表 Strix 官方服务。官方源码：https://github.com/usestrix/strix 。

测试含假扫描子进程、恶意 ZIP、目标校验、身份隔离、取消与报告一致性。`tests/integration_smoke.py` 使用本地假模型驱动真实 Strix 和真实 Docker 沙箱，仅验证启动及报告链路，不代表真实模型的漏洞检出效果。具体测试结果见 VALIDATION.md。
