# Docker 部署

源码 + systemd 与 Docker 是两种可选部署方式，部署时选择其中一种；原源码部署入口继续有效。Docker 不修改、停止或重装现有 systemd、cron、Nginx 服务。审计窗口、多账号 TAG、正文七类资源表、PDF 全量汇总、最新 HTML、可选 Lark 日报链接与异常告警，以及每天最多一封自动邮件规则沿用同一份配置。

## 前提与目录

服务器使用 Linux Docker Engine 和 `docker compose` 插件（V2 或更新版本）。安装器检查现有 Docker，不自动安装或启停宿主服务。可按 [Docker 官方安装文档](https://docs.docker.com/engine/install/) 准备环境。

| 内容 | 默认宿主路径 | 容器路径 |
| --- | --- | --- |
| 统一私有配置 | `/usr/local/aws-user-audit/aws-audit-config.json` | 同名路径，只读 |
| PDF/JSON 归档 | `/usr/local/aws-user-audit/reports` | 按配置解析，可写持久化 |
| 邮件与调度状态 | `/usr/local/aws-user-audit/.state` | 按配置解析，可写持久化 |
| 最新 HTML/CSS/JS | `/usr/local/aws-user-audit/index` | 按 `PUBLISH_DIRECTORY` 解析，可写持久化 |
| 应用与 Python | 源码用于构建 | `/app` 与 `/app/.venv`，只读镜像 |
| 可选 AWS profile | `--profile-dir` 指定目录 | `/root/.aws`，只读 |
| 可选自定义字体 | 原 `PDF_FONT_PATH` 对应文件 | 原配置对应路径，只读 |

镜像包含 Python 3.12、运行依赖、CA 证书、时区数据和中文字体。构建上下文及 COPY 均采用白名单，私有 JSON、Access Key、SMTP/Lark 配置、`.aws`、`.state`、报告和无关项目不进入镜像。容器生成静态页面并写入宿主网页目录，不提供网站端口；Nginx 由使用者配置为读取该目录。

安装器让容器使用配置文件所有者的 UID/GID，保留 `0600` 配置和 `0700` 数据目录的访问边界，不依赖放宽权限或特权模式。已有报告、状态和 profile 须能由该 UID 访问；不递归改写旧文件或凭据所有权。

## 使用现有配置部署

```bash
cd /opt/aws-user-audit-src
sudo git pull --ff-only
sudo bash install-docker.sh
```

如启用账号配置了 `AWS_PROFILE`，使用真实 profile 目录：

```bash
sudo bash install-docker.sh --profile-dir /root/.aws
```

已有 `aws-audit-config.json` 按字节保留，不覆盖、不自动添加字段。使用 Access Key 的账号无需挂载 profile；使用默认凭据链/角色时须确保容器环境确实可获取相应凭据。配置和角色授权不会因为镜像构建而自动产生。

首次没有配置时，脚本只从完整七账号模板创建 `0600` 私有文件，然后退出，尚不构建或启动容器。填写账号与邮件字段后重跑同一条命令。

```bash
sudo nano /usr/local/aws-user-audit/aws-audit-config.json
sudo chmod 600 /usr/local/aws-user-audit/aws-audit-config.json
sudo bash install-docker.sh --profile-dir /root/.aws
```

不使用 profile 时省略最后的 `--profile-dir`。需要独立数据目录或复用其他位置配置时：

```bash
sudo bash install-docker.sh --data-dir /srv/aws-audit --config /srv/aws-audit/aws-audit-config.json
```

相对报告/状态/网页路径分别按宿主配置目录和固定容器配置目录解析；绝对路径保留为对应容器挂载目标，不改写 JSON。报告和状态必须是独立、不嵌套目录，目录权限 `0700`。网页目录还须与私有报告、状态和配置分开，不能互相嵌套或使用符号链接；Nginx 只需读取网页目录。自定义字体自动追加 `compose.font.yaml`；字体文件须真实存在且不是符号链接。

HTML 默认开启，容器与源码方案均每次覆盖同一 `index/index.html`，并更新所需 CSS/JS。开启 Lark 最新报告链接通知时，在现有 JSON 中设置 `LARK_REPORT_ENABLED: true`，按实际 Nginx 地址填写 `REPORT_URL`，沿用原 `LARK_WEBHOOK_URL`、`LARK_SIGNING_SECRET`；异常通知开关仍为独立的 `LARK_ALERTS_ENABLED`。只有网页发布成功后才发送正常链接通知。字段和配置片段见 [最新 HTML 与 Lark 日报链接](README.md#最新-html-与-lark-日报链接)。

只查看计划，或先构建和离线检查、暂不启动：

```bash
bash install-docker.sh --dry-run
sudo bash install-docker.sh --no-start --profile-dir /root/.aws
```

配置检查不查询 AWS、不连接 SMTP、不发送 Lark；它不能证明远端 IAM 权限、邮件授权或网络出口有效。Docker 运行时需要访问 AWS API、SMTP 和已启用的 Lark/飞书地址。

## 定时与恢复

默认容器长期运行，读取 JSON 中的 `DAILY_MAIL_TIME`，北京时间每天 `10:05` 调用原有业务程序，统计昨日 `10:00` 至今日 `10:00`。容器的计算显式使用 `Asia/Shanghai`，与宿主时区无关。

- 首次没有 Docker 调度状态时只初始化游标，等待下个发送时刻，不立即采集或发送。
- 重启或主机停机后恢复时，若错过计划，只补最近一份已经结束的窗口，不连续发送多份历史日报。
- `10:02` 恢复并已补完当天 `10:00` 结束的窗口时，`10:05` 只推进游标，不重复查询同一成功窗口。
- 邮件回执仍在原 `.state/mail-delivery.json`，更新、重建镜像和修改配置不清空每日额度。调度游标、锁和心跳另存于该目录。
- 长任务期间持续更新心跳；SIGTERM/SIGINT 转发给业务子进程并有界等待，避免遗留后台任务。损坏状态保留并报错，不静默重置。

安装器不会直接执行 `once`。更新/重启已有调度实例后，容器会按上述恢复规则补跑；希望只构建检查而不启动时使用 `--no-start`。

Docker 支持不会自动停用原 systemd。使用者在部署时明确选择运行方式；如需从一种切换到另一种，由使用者安排原任务的停止和新任务的启动，并保留原报告、网页和 `.state` 投递记录，安装器不接管另一种部署。

## 状态、日志与手工执行

安装器在数据目录生成 `docker.env`（`0600`），只保存挂载路径、镜像名和 Compose 文件，不包含凭据。后续命令可在任意工作目录执行：

```bash
sudo docker compose --env-file /usr/local/aws-user-audit/docker.env ps
sudo docker compose --env-file /usr/local/aws-user-audit/docker.env logs --tail 100 -f audit
sudo docker compose --env-file /usr/local/aws-user-audit/docker.env exec -T audit /app/.venv/bin/python /app/deploy/docker_runtime.py healthcheck
```

单次生成最近已结束的报告，不发送正常邮件：

```bash
sudo docker compose --env-file /usr/local/aws-user-audit/docker.env run --rm --no-deps -T audit once
```

指定报表结束日期，或明确按自动投递额度发送：

```bash
sudo docker compose --env-file /usr/local/aws-user-audit/docker.env run --rm --no-deps -T audit once --date 2026-11-05
sudo docker compose --env-file /usr/local/aws-user-audit/docker.env run --rm --no-deps -T audit once --send-mail --automatic-mail
```

明确人工发送时省略 `--automatic-mail`；同一报告已投递或结果不确定时，只有核实后再显式增加 `--force-resend` 才重发。`once` 同样默认更新最新 HTML，正常 Lark 链接由 `LARK_REPORT_ENABLED` 决定；不加 `--send-mail` 只是不发邮件。手工执行还可能按配置对实际任务异常发送 Lark；`check-config` 则完全离线。

只停止 Docker 实例，不操作原有服务或删除数据：

```bash
sudo docker compose --env-file /usr/local/aws-user-audit/docker.env stop audit
```

## 更新与配置变更

```bash
cd /opt/aws-user-audit-src
sudo git pull --ff-only
sudo bash install-docker.sh --profile-dir /root/.aws
```

脚本先构建、规划挂载并完成配置检查，通过后才 `up --force-recreate` 更新本项目的 `audit` 服务；构建或预检失败时不停止现有 Docker 实例。既有私有配置、报告和状态保留。直接挂载的配置文件可能被编辑器原子替换，因此修改 JSON 后需重建容器以重新挂载：重跑安装器，或在挂载路径未改变时运行：

```bash
sudo docker compose --env-file /usr/local/aws-user-audit/docker.env up -d --no-deps --force-recreate audit
```

修改输出/状态/网页/字体路径或 profile 挂载时应重跑安装器，以重新校验和更新 `docker.env`。不要在运行中迁移状态目录。容器本身可读取原文件中的时间/账号变更；时间计划更改只重设等待基线，不触发即时补发。

## 手工构建与 Compose

```bash
docker build -t aws-user-audit:local .
docker compose -f compose.yaml config
docker compose -f compose.yaml up -d
```

上述直接 Compose 方式要求默认私有配置和 `0700` 报告/状态目录已存在。profile 或字体须追加对应 overlay；自定义目录须设置 Compose 中的 `AUDIT_*` 路径变量。通常使用安装器可避免手工配置这些挂载。

镜像入口支持 `schedule`、`once`、`check-config`、`healthcheck`、`init-schedule`。无需 systemd、cron、Docker socket、特权模式或网站端口；默认只读根文件系统、移除 Linux capabilities，仅配置的报告/状态/网页卷和 `/tmp` 可写。

## 验证范围

单元测试覆盖北京时间与恢复边界、首次不执行、状态不覆盖、坏状态拒绝、并发锁、热更新、健康检查和信号终止。Linux CI 实际构建生产镜像，以禁用网络的虚构 AWS/SMTP 测试验证中文 PDF、正文表格、附件与持久投递去重，另验证只读 profile/字体挂载、首次调度与重建健康，以及真实 Docker 下的安装器预检。CI 不使用真实 AWS 或邮件配置，不发布镜像到公共仓库。
