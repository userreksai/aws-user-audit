# AWS 多账号操作审计：PDF 邮件日报

按 AWS 账号读取 CloudTrail 管理事件，每个启用账号生成一份按 IAM 用户 / 角色逐行统计的中文 PDF，所有账号的 PDF **合并到同一封邮件**，支持多个收件人和抄送。正常日报只通过邮件发送；开启 Lark 异常告警后，仅在采集、生成或邮件投递失败时通知群。

PDF 保留 **IAM 用户 / 角色维度**：例如 `beiou`、`hhjgx` 各占一行，列出身份类型、新增、修改、删除、Secrets Manager 查看、登录、其他、失败及合计，最后显示 AWS 账号合计。另有 **用户操作与事件汇总**，按“用户 / 角色 + 服务 API”合并调用，显示中文事件、调用次数和失败次数。PDF 不展示逐次执行记录、参数、资源、来源 IP 或每次执行时间。表格较长时自动分页并重复表头，不截掉用户或事件。

多账号日报只生成 **PDF 和私有 `report.json`**。JSON 保留操作时间、身份、API、资源、提交参数和请求结果，供本地复核；PDF 只含统计。普通查看忽略，Secrets Manager 查看保留。这里审计 AWS 管理操作，不采用 RDS 的 SQL/IP 汇总口径。

## 已确认的部署配置

| 项目 | 配置 |
| --- | --- |
| 安装目录 | `/usr/local/aws-user-audit` |
| Python 虚拟环境 | `/usr/local/aws-user-audit/.venv` |
| 统一私有 JSONC | `/usr/local/aws-user-audit/aws-audit-config.json` |
| 归档 | `/usr/local/aws-user-audit/reports/<账号ID>/<报表结束日期>/` |
| 邮件状态 | `/usr/local/aws-user-audit/.state/`，仅任务用户可访问 |
| 每日执行 | **北京时间 10:05**（`DAILY_MAIL_TIME`），不依赖服务器系统时区 |
| 查询窗口 | **昨日 10:00 ≤ 事件时间 < 今日 10:00**，24 小时，相邻日报不重叠 |
| 停机恢复 | 只补最近一份已结束的日报；配置的统计结束时刻之前恢复，选择前一结束日 |

**安装/更新只部署代码、模板、服务与定时器，不立即查询 AWS 或发送通知。** 每日任务不生成 HTML、CSS、JS 或 `index/`，邮件不含网页链接。Nginx 已从安装流程移除，现有 Nginx 文件原样保留；旧服务器的 `/audit`、`/audit/` 由使用者手动清理，保留原前端和 RDS 路由。

## 安装和更新

需要 Docker 部署时，使用独立的 [Docker 部署说明](DOCKER.md) 和 `install-docker.sh`。Docker 支持不会修改、停用或替换现有 systemd、cron、Nginx；配置只读挂载，报告与状态持久化，容器内部按北京时间定时。已有配置不覆盖，首次缺配置仅初始化完整模板并提示填写。

```bash
cd /opt/aws-user-audit-src
sudo git pull --ff-only
sudo bash install-docker.sh
# 若启用账号使用 AWS_PROFILE，改用：
# sudo bash install-docker.sh --profile-dir /root/.aws
```

以下仍为原有宿主机 systemd 部署方式，可继续使用。

已有源码目录先更新，执行安装器：

```bash
cd /opt/aws-user-audit-src
sudo git pull --ff-only
sudo bash install.sh
```

首次没有源码时：

```bash
git clone https://github.com/userreksai/aws-user-audit.git /opt/aws-user-audit-src
cd /opt/aws-user-audit-src
sudo bash install.sh
```

`/opt/aws-user-audit-src` 是源码目录，实际运行目录是 `/usr/local/aws-user-audit`。缺少 `aws-audit-config.json` 时，先以完整模板初始化私有配置，权限 `0600`，然后提示填写后重跑；此阶段不替换运行代码或服务。配置通过后，再部署所有必需运行文件和配置模板。**已有私有配置文件按字节保留，不覆盖、不补字段、不改 TAG 或凭据。** 新增字段由使用者手动填写。不要将真实 Key、授权码或机器人 Webhook 提交到 GitHub。

```bash
sudo nano /usr/local/aws-user-audit/aws-audit-config.json
sudo chmod 600 /usr/local/aws-user-audit/aws-audit-config.json
cd /opt/aws-user-audit-src
sudo bash install.sh
```

配置通过后安装/更新 `aws-user-audit.service` 和 `aws-user-audit.timer`，同名旧定时任务被替换，不另建一套双跑。以后也可用：

```bash
sudo bash /usr/local/aws-user-audit/install.sh --update
systemctl list-timers --all aws-user-audit.timer
systemctl cat aws-user-audit.service
journalctl -u aws-user-audit.service -n 100 --no-pager
```

`systemctl cat` 中 Python、工作目录和配置文件都应指向新目录。旧 `/usr/local/shenji` 的历史文件保留，不自动删除或搬迁；系统定时器改为新路径。自行维护的旧 cron 若仍存在，安装器会停止并提示，避免重复运行。

安装流程仅管理审计服务与定时器，不需要 Nginx、网站路径或域名。旧 `--nginx-config`、`--publish-dir` 等网页选项仅接受并提示忽略，便于沿用安装命令。安装失败恢复原代码、服务单元和定时器状态；pip 依赖安装不具备完整回滚。新路径不应与 RDS 项目共用。

## 私有配置填写

完整带注释模板为 `aws-audit-config.example.json`，预留 7 个账号，后续可继续追加。账号 1 先启用，其他配置好后设置 `ENABLED: true`。账号 ID 占位值必须替换为真实的 12 位账号 ID。

```json
{
  "OUTPUT_DIRECTORY": "reports",
  "STATE_DIRECTORY": ".state",
  "TIMEZONE": "Asia/Shanghai",
  "DAILY_MAIL_TIME": "10:05",
  "REPORT_START_TIME": "10:00",
  "REPORT_END_TIME": "10:00",
  "ACCOUNT_CONCURRENCY": 7,
  "AUTO_MAIL_MAX_PER_DAY": 1,
  "SMTP_HOST": "smtp.example.com",
  "SMTP_PORT": 465,
  "SMTP_SECURITY": "ssl",
  "SMTP_USERNAME": "sender@example.com",
  "SMTP_AUTH_CODE": "填写邮箱授权码",
  "MAIL_RECIPIENTS": ["audit@example.com"],
  "MAIL_CC": ["ops@example.com"],
  "MAIL_SUBJECT": "AWS账号操作审计日报",
  "LARK_ALERTS_ENABLED": false,
  "LARK_WEBHOOK_URL": "",
  "LARK_SIGNING_SECRET": "",
  "ACCOUNTS": [
    {
      "TAG": "prod-支付",
      "NAME": "123456789012",
      "ACCOUNT_ID": "123456789012",
      "ENABLED": true,
      "AWS_PROFILE": "audit",
      "AWS_ACCESS_KEY_ID": "",
      "AWS_SECRET_ACCESS_KEY": "",
      "AWS_SESSION_TOKEN": "",
      "REGIONS": "all"
    }
  ]
}
```

- `SMTP_USERNAME` 同时为发件邮箱与登录账号；465 使用 `ssl`，587 通常使用 `starttls`。只支持验证证书的 TLS。邮箱参数沿用 RDS 字段名称，可从自己的 RDS 私有配置中复制 SMTP/MAIL 字段；无需将真实配置发给我。
- `MAIL_RECIPIENTS` 至少一个地址，`MAIL_CC` 可为空；会对 To/CC 去重。邮件只写一次问候、查询范围和整体查询状态，然后列出实际账号总数及 `TAG-ACCOUNT_ID`，并按账号追加用户资源操作表。启用 3 个账号就生成 3 组表和 3 份 PDF，启用 7 个就生成 7 组表和 7 份 PDF；暂停的账号不计入正文和附件。
- `ACCOUNTS[*].TAG` 是可选账号标签，例如 `prod-支付`、`uat-预生产`、`dev-测试`，支持中文、最多 120 字符。旧配置没有 TAG 时正常运行并只显示账号 ID；手动加入后，下次运行生效。`NAME` 的目录短名规则和 `ACCOUNT_ID` 的 12 位校验保持不变，TAG 不用于路径或凭据选择。
- 使用原 root profile `audit` 时保留 `AWS_PROFILE: "audit"`，Key 留空。使用单独 Key 时 `AWS_PROFILE` 留空，成对填写 ID/Secret；临时凭据还需 Token。均留空时使用默认凭据链/实例角色。每个启用账号先通过 STS 核对归属，错配账号不继续读取 CloudTrail。
- `REGIONS: "all"` 扫描本账号已启用区域，标准 AWS 分区另纳入 `us-east-1` 以覆盖全局事件；也可填写区域数组。单个账号失败不阻止其他账号，失败账号 PDF 明确标记不完整，邮件标题也带不完整标记，不把失败当成零操作。
- 开启异常群时填真实 `LARK_WEBHOOK_URL` 并设置 `LARK_ALERTS_ENABLED: true`，签名校验开启时同时填写 `LARK_SIGNING_SECRET`。原 `lark-config.json` 可供你复制地址和签名；新定时任务只读取统一 JSON，不发送正常 Lark 日报。单次发现失败即告警，同一轮报告的同类异常一小时内抑制重复；只在任务实际执行时检查，不另加分钟级重试定时器。
- 相对目录均以配置文件所在目录计算。新模板取消 `PUBLISH_DIRECTORY`、`REPORT_URL`；已有配置中保留这些旧字段也可运行，程序忽略它们。
- `PDF_FONT_PATH` 可选中文 TTF/TTC；Linux 可安装 `fonts-wqy-zenhei` 提高跨设备显示一致性。留空时自动寻找字体，否则使用中文 CID 字体。
- `DAILY_MAIL_TIME` 控制每天启动采集和生成报告的北京时间，默认 `10:05`；邮件在采集和 PDF 完成后发送，不保证 10:05 整到达邮箱。
- `REPORT_START_TIME` 是统计开始时刻（报表结束日的前一天），`REPORT_END_TIME` 是统计结束时刻（报表结束日），默认均为 `10:00`，即 24 小时。开始和结束都包含日期，采用左闭右开，报表日期是结束日。`DAILY_MAIL_TIME` 不能早于 `REPORT_END_TIME`。
- 三项必须采用 `HH:MM` 格式。更改后重跑 `sudo bash /usr/local/aws-user-audit/install.sh`，安装器会依据 JSON 更新实际 systemd `OnCalendar` 并重新启用定时器；无需修改源码或手工编辑 unit。安装仍不会立即查询或发送。只修改 JSON 不会让 systemd 重新读取定时器。
- 也可配置旧版 `08:01` / `07:00` / `08:00` 以恢复 25 小时及 1 小时重叠。新版本缺少这些字段时使用已确认的新默认 `10:05` / `10:00` / `10:00`，因此旧统一配置升级重装后也会切换新默认；明确填写的值始终优先。
- 统计窗口不足 24 小时会在相邻日报之间留下空档，超过 24 小时会重叠；按自己要求设置。此项目不继承 RDS 的分段 SQL 采集、IP 过滤或自动删除设置，历史报告不会自动删除。

本地检查不访问 AWS、SMTP 或 Lark：

```bash
sudo /usr/local/aws-user-audit/.venv/bin/python /usr/local/aws-user-audit/aws_audit_multi.py   --config /usr/local/aws-user-audit/aws-audit-config.json --check-config
```

安装的预检另检查本地 profile 是否存在，不请求 AWS 凭据，也不能证明远端权限或 SMTP 授权有效。

邮件正文示例（3 个启用账号，对应 3 份独立 PDF）：

```text
各位领导和同事好：
AWS 账号操作审计日报
查询范围（北京时间，结束时刻不含）：
2026-11-03 10:00:00 至 2026-11-04 10:00:00
查询状态：所列查询完成。
PDF 附件按 IAM 用户 / 角色汇总增删改查及中文事件的调用次数和失败次数。
账号总数：3
账号信息：
prod-支付-796973492024
uat-预生产-796973492025
dev-测试-796973492026
```

上述介绍之后追加按用户统计的表，每组标题为 `ACCOUNT_ID-TAG`，例如：

**796973492024-prod-支付**（以下次数为虚构示例）

| 具体用户 | 安全组 | 负载均衡 | 弹性IP申请/绑定 | VPC | 路由表 | EC2 | RDS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| beiou | 2 | 3 | 5 | 4 | 3 | 5 | 9 |
| jit | 4 | 2 | 1 | 4 | 3 | 6 | 12 |

邮件使用真正的 HTML 表格，并保留纯文本表格备选；不会生成或发布网页。账号分组来自本次启用账号的报告，数量不固定为 7。每组仅显示上述七列中至少一列大于 0 的 IAM 用户、角色或其他调用身份；七列全为 0 的行不显示。保留行中未涉及的资源列仍显示 0。整组无匹配操作时保留账号标题和查询状态，显示“本账号在上述七类资源中无操作。”。不另查账号中没有任何本期事件的 IAM 用户，角色会话仍按原有角色身份合并。

IAM 用户执行七类资源操作时会计入正文对应用户行；创建 IAM 用户、修改 IAM 策略等 IAM 服务操作仍保留在 PDF 的全量用户/事件汇总及私有 JSON 中，不增加正文七列次数。建议使用 `REGIONS: "all"`，该模式会补查全局 IAM 管理事件所在的 `us-east-1`。

表中数字是已去重 API 调用次数，包含失败请求，不等于资源数量或成功变更数。资源列按服务/API 互斥识别，不把安全组、VPC、路由表或弹性 IP 再计入 EC2：

- 安全组：安全组创建/删除、规则授权/撤销/修改、规则描述及跨 VPC 关联等明确 API。
- 负载均衡：`elasticloadbalancing.amazonaws.com` 的纳入报告管理操作，包含负载均衡器、目标组、监听器等。
- 弹性 IP：仅 `AllocateAddress` 申请与 `AssociateAddress` 绑定合计；解绑、释放等仍保留在 PDF 的原有汇总中。
- VPC：明确的 VPC 本身、属性、CIDR、对等连接、端点等管理 API。
- 路由表：常规 VPC 路由表、路由、路由表关联及 VGW 路由传播等明确 API。
- EC2：明确面向实例的生命周期、属性、监控、实例 IAM 配置等 API。
- RDS：`rds.amazonaws.com` 的纳入报告管理操作，包含实例和集群等。

完整白名单及官方来源见 `audit_resource_summary.py`。子网、NAT、EBS、AMI 和通用 `CreateTags`/`DeleteTags` 等无法仅凭 API 名称归入上述明确资源列的操作，不推测归属，继续保留在 PDF 的全量用户/事件汇总中。正文只展示七类子集，PDF 内容、统计口径及附件名称保持不变。查询不完整的账号单独标记不完整；旧数据缺少身份/API汇总时标记“统计不可用”，不误写为 0。

## 修改日报时间

在 `/usr/local/aws-user-audit/aws-audit-config.json` 中加入或修改这三项：

```json
"DAILY_MAIL_TIME": "10:05",
"REPORT_START_TIME": "10:00",
"REPORT_END_TIME": "10:00"
```

上述设置表示：北京时间每天 10:05 启动任务，统计昨日 10:00 至今日 10:00。例如 11 月 4 日日报统计 11 月 3 日 10:00（包含）至 11 月 4 日 10:00（不含）。

```bash
sudo bash /usr/local/aws-user-audit/install.sh
systemctl cat aws-user-audit.timer
systemctl list-timers --all aws-user-audit.timer
```

`OnCalendar` 应显示 `*-*-* 10:05:00 Asia/Shanghai`。当天配置时刻已过时，下一次自动执行是次日该时刻；需要当天马上生成时手动启动服务，见下文。

## 执行与投递状态

等待配置的 10:05 自动运行，或明确手动执行一次服务（**会真实采集、发送邮件**，同日自动额度仍生效）：

```bash
sudo systemctl start aws-user-audit.service
sudo journalctl -u aws-user-audit.service -n 100 --no-pager
ls -lh /usr/local/aws-user-audit/reports/
```

手动指定报表结束日；不加 `--send-mail` 仅采集并生成 PDF 和私有 JSON：

```bash
sudo /usr/local/aws-user-audit/.venv/bin/python /usr/local/aws-user-audit/aws_audit_multi.py   --config /usr/local/aws-user-audit/aws-audit-config.json --date 2026-11-04
```

明确手动发送（所有启用账号合并一封；此显式操作可额外超出自动邮件每日额度）：

```bash
sudo /usr/local/aws-user-audit/.venv/bin/python /usr/local/aws-user-audit/aws_audit_multi.py   --config /usr/local/aws-user-audit/aws-audit-config.json --date 2026-11-04 --send-mail
```

同一份已接受或投递不确定的报告不会直接重复发；核实邮箱后确需重发时，手动命令再加 `--force-resend`。不要删除 `.state/mail-delivery.json` 来重置额度。自动邮件按**发送当天北京时间**最多一封，账号、标签、收件人、数据或完整度改变不触发第二封。后续重跑仍更新本地报告。`AUTO_MAIL_MAX_PER_DAY: 0` 关闭自动邮件，仍生成本地报告。

提交 SMTP 前先落盘 `sending`；进程中断、部分拒收、提交中断或损坏状态保守视为投递不确定，停止自动重发。明确认证/连接失败不消耗成功额度，等下次实际运行再试；此项目没有“15 分钟后自动重试”机制。SMTP 接受只代表服务器接受，不保证最终进入收件箱。

产物示例：

```text
/usr/local/aws-user-audit/
  reports/123456789012/2026-11-04/
    123456789012-2026-11-04-aws操作审计.pdf
    report.json
  .state/
    mail-delivery.json
```

多账号入口返回码：0 完成或按规则跳过邮件，1 启动/配置错误，2 查询不完整，3 通知失败或投递不确定，5 报告/PDF 生成失败。旧 `--no-publish` 选项接受但无实际作用。


## PDF 的账号维度

AWS 账号与 IAM 身份是两层：每个 AWS 账号一份 PDF；PDF 内每个 IAM 用户或角色一行。账号名相同但属于不同 AWS 账号时，各自在对应 PDF 中统计，不跨账号合并。

身份汇总依据已去重、已按查看规则过滤的事件生成，输出到 JSON 的 `actors` 字段。IAM 用户使用 ARN 或主体 ID 识别；同一角色的不同会话按签发角色合并，不把会话名称认定为自然人。Root、AWS 服务、Identity Center、联合身份和未知身份分别标注。用户与角色即使同名也不合并。分类计数包含失败请求，失败数作为其中子集单列。

PDF 只读取汇总白名单，校验各身份的分类数量、失败和合计与 AWS 账号总数完全一致；不会读取或输出原始事件内容。中文事件汇总保存在 JSON 的 `actor_events` 字段，使用相同身份识别规则，按服务/API分组，成功和失败调用合并，失败次数是调用次数的子集。旧报告缺少 `actors` 或 `actor_events` 时需要用新版程序重新生成，不能拿仅有账号总数的数据推测各 IAM 用户次数。

例如 `hhjgx` 调用 `PutDashboard` 两次，其中一次失败，事件表显示一行“hhjgx / IAM 用户 / 保存 CloudWatch 监控仪表盘配置（新建或整体覆盖） / 调用 2 / 失败 1”。这个 API 可以新建仪表盘，也可以整体覆盖已有内容，仅凭事件名称不能断定是哪一种。[AWS PutDashboard 说明](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutDashboard.html)

中文名称来自随代码发布的离线词典 `aws-event-translations.json` 和已审核的服务/API规则；每项保留官方来源，不在每日任务中联网翻译，也不增加 AWS 权限。JSON 的 `translation_status` 区分已审核、官方中文和待补中文。AWS 未提供可核实中文或服务/API未知时，PDF 显示原服务和事件并标记“待补中文”，不会按英文单词拼出未经核实的功能。官方服务参考中的权限动作不等于 CloudTrail 事件，词典覆盖不能保证所有 CloudTrail 事件都已翻译。[AWS 服务参考](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html)

维护词典时可在源码目录执行以下命令；第一步联网获取 AWS 官网公开说明，第二步仅用缓存和本地 SDK 操作模型交叉核对。日常部署直接使用仓库内的词典，无需执行这些命令。词典顶部的 `statistics` 记录实际覆盖，`official_sources` 保留来源；修改词典后应重新测试并随代码发布。

```bash
.venv/bin/python tools/fetch_event_docs.py --cache-dir tmp/catalog-cache
.venv/bin/python tools/build_event_catalog.py --cache-dir tmp/catalog-cache --offline
.venv/bin/python -m unittest -q test_audit_event_catalog
```

## 操作识别与“其他操作”

`audit_actions.py` 包含按服务和 API 精确匹配的审核规则，补充旧版仅靠名称前缀遗漏的操作，例如 EC2 监控开关与 Spot 请求、RDS 故障/主备切换、IAM MFA、KMS 授权与计划删除、CloudFormation 回滚、Secrets Manager 复制和 Organizations 账号移动。增删改是依据 API 功能做的报告归类，不是 AWS 官方另行提供的 CRUD 标签；请求未报错也不证明异步任务已完成。

已经确认的实际问题：IAM `ListOrganizationsFeatures` 是**查看组织集中 root 访问功能**，`ServiceAccessNotEnabledException` 表示 Organizations 尚未启用 IAM 受信访问。它是普通查询，旧版在失败事件携带非只读标记时误入“其他操作”。新版按已核对的服务/API 精确识别并忽略该普通查询，包括失败请求；不会把所有名称带 Get/List 的未知非只读调用一概丢弃。[AWS 官方 API 说明](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListOrganizationsFeatures.html)

CloudTrail `readOnly=true` 的普通读取仍忽略，Secrets Manager 查看保留。`GetSessionToken`、`GetFederationToken` 和 `AssumeRoot` 等 STS 临时凭据请求以“身份会话”标记归入登录信息；报告明确区分临时凭据请求与控制台登录，不把它们写成自然人登录成功。[IAM / STS CloudTrail 说明](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)

KMS 加密、解密或签名是使用密钥的操作，不能认定为修改密钥配置；若作为非只读事件进入范围，会保留在“其他操作”并显示明确功能。仍无法确认的 API 保留原服务/API 和已有参数，不能为了减少“其他操作”数量而强行归入增删改。[CloudTrail 事件字段](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)

对于本机已安装 SDK 中可识别的服务 API，新版还会离线读取 botocore 的公开模型说明，在 JSON 附上英文功能摘要和官方 API 链接；不连接 AWS、不读取凭据、不增加 API 权限或查询请求。仅凭 IAM 的 Write 权限标签无法区分新增/删除/修改，也不能将权限动作当作一定存在的 CloudTrail API 事件。[AWS 服务参考说明](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html)

失败次数是分类事件的子集，不再额外加到总数中；各类别统计包含失败请求。PDF 改版不会清空邮件回执或重置当日自动邮件额度，已发送日期不会因改版自动再发一封。

## 报告能说明什么

例如，日志中存在 `hhjgx` 调用 `ModifyInstanceAttribute` 的事件时，PDF 汇总其“修改 EC2 实例属性”的调用及失败次数；具体操作时间、实例 ID、提交的属性参数、API 名称和请求结果保存在私有 JSON 中。范围与警告同样保留在 JSON 和终端输出中。本版本的多账号入口不生成 HTML 或 CSV。

登录信息仅归入能识别的登录事件，例如 `ConsoleLogin`、`CheckMfa`、`GetSigninToken`；`ConsoleLogin` 明确显示中文登录操作及成功或失败结果。不能识别为增删改的非登录写操作保留在“其他操作”；STS 身份会话请求按前文说明另行识别。登录信息和其他操作分类仅在实际存在对应事件时显示。

需要区分以下事实：

- CloudTrail 通常记录提交的参数，未必记录旧配置，所以报告不能保证展示“旧值 → 新值”。参数被 AWS 省略、脱敏或截断时，报告也不能恢复；要比较历史配置，可另行评估 AWS Config。
- API 返回成功表示请求未出现记录中的调用错误，并不保证异步资源创建、删除或修改已经最终完成。失败请求会显示失败，不计作已经成功完成的变更。
- 新增、删除、修改是根据 API 和请求内容的归类；无法可靠识别的非登录写操作保留在“其他操作”供复核，不会静默丢弃。一次 API 调用可能影响多个资源，事件数不能直接等同于资源变更数量。
- 默认保留所有调用身份，包括 IAM 用户、角色、自动化程序和 AWS 服务。角色会话名不一定是真实人员姓名；报告保留角色 ARN、会话和日志已有的来源身份。IAM Identity Center 记录可能只有用户 ID，脚本不会猜测真实姓名。
- Secrets Manager 可以审计“谁在什么时候读取哪个 Secret”，但 CloudTrail 不记录 SecretString/SecretBinary 的明文，脚本也不读取密码本体。

## 一、需要开通哪些权限

AWS 中应配置 **IAM** 用户、用户组或角色。用户组是权限管理方式，本身不能生成 Access Key；Access Key 属于 IAM 用户。AWS RAM 是另一项服务，不是这里要开的身份授权。

| 运行方式 | 建议身份 | 使用策略 |
| --- | --- | --- |
| EC2 上长期每日执行 | EC2 IAM Role，通过实例配置文件提供临时凭据 | `iam-policy.json` |
| 本地人工运行 | IAM Identity Center / SSO 配置文件 | `iam-policy.json` |
| 外部服务器且无法使用角色 | 专用 IAM 用户及 Access Key | `iam-policy.json` |
| 固定区域，跳过自动发现 | 以上任一种身份 | `iam-policy-single-region.json` |

`iam-policy.json` 只有两个权限：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["cloudtrail:LookupEvents", "ec2:DescribeRegions"],
      "Resource": "*"
    }
  ]
}
```

`cloudtrail:LookupEvents` 读取事件历史；`ec2:DescribeRegions` 只用于发现已启用区域。显式指定 `--regions eu-north-1,us-east-1` 时，不需要自动发现，可使用第二份只包含 `cloudtrail:LookupEvents` 的策略。两项操作不支持按资源 ARN 授权，因此使用 `Resource: "*"`，不是给所有 AWS 操作授权。文件名中的 single-region 表示不自动发现区域，显式列出多个区域也适用。

**无需开通 `secretsmanager:GetSecretValue`、`secretsmanager:*`、`kms:Decrypt`、`AdministratorAccess` 或 `iam:ListUsers`。** 获取 Secrets Manager 审计日志只需要 CloudTrail 读取权限。脚本不需要 S3、CloudWatch Logs 或 CloudTrail Lake 查询权限。

这是脚本 API 的最小策略，未必能支持控制台其他页面的全部功能。账号的 SCP、权限边界或显式 Deny 仍可能限制查询；受限区域会在 JSON 查询状态和终端输出中体现，不能视作该区域没有事件。

### IAM 控制台操作：专用用户与 Access Key

如果选择在外部服务器运行：

1. 用有管理 IAM 权限的身份进入 **IAM → Policies（策略）→ Create policy（创建策略）→ JSON**，粘贴 `iam-policy.json` 内容，创建名为 `CloudTrailDailyAuditReadOnly` 的自定义策略。
2. 进入 **User groups（用户组）→ Create group**，创建 `AuditDailyReaders`，挂载该策略。用户组可选，也可以直接把策略挂在用户上。
3. 进入 **Users（用户）→ Create user**，创建专用用户 `cloudtrail-daily-audit`，加入该组。脚本运行不需要为这个用户启用控制台登录。
4. 打开该用户的 **Security credentials（安全凭证）→ Access keys → Create access key**，根据实际运行位置选择用途并创建。保存 Access Key ID 与 Secret Access Key；Secret 只在创建时显示。
5. 在实际运行脚本的机器配置凭据。不要把 Key 写入 Python 文件、Git 或发到聊天中。

如果使用 IAM Identity Center，管理员应将相同的最小权限放入相关权限集。EC2 角色则将策略挂到角色上，无需创建上述用户或 Key。

## 二、安装环境与配置凭据

需要 Python 3.10 或更高版本和 `requirements.txt` 中的依赖。AWS CLI v2 用于配置和验证凭据；脚本本身通过 boto3 调用 AWS。

请先安装 [Python](https://www.python.org/downloads/) 和 [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)。下面的命令都在本项目目录执行。

### Windows PowerShell

```powershell
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
aws configure --profile audit
```

按提示输入本机保存的 Access Key ID、Secret Access Key，默认区域填 `eu-north-1`，输出格式填 `json`。命令会将凭据保存到当前操作系统用户的 AWS 配置目录；运行计划任务的用户必须能使用对应配置。

### Linux

Debian/Ubuntu 先安装虚拟环境支持（已是 root 时去掉 `sudo`）：

```bash
sudo apt update
sudo apt install -y python3-venv
```

然后在包含 `requirements.txt` 的项目目录中，以日后运行审计任务的系统用户执行：

```bash
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
aws configure --profile audit
```

如果系统 pip 提示 `externally-managed-environment`，说明系统 Python 由发行版管理。上面的 `.venv/bin/python -m pip` 会将依赖安装到项目虚拟环境。安装和运行脚本都使用 `.venv/bin/python`，无需激活环境；已配置 `audit` 凭据时可以跳过 `aws configure`。每日任务也使用该虚拟环境 Python 的绝对路径，并由配置凭据的同一系统用户执行。参见 [Python 虚拟环境说明](https://docs.python.org/3/library/venv.html) 和 [外部管理环境规范](https://packaging.python.org/en/latest/specifications/externally-managed-environments/)。

如果运行时提示缺少 `boto3`，请在项目目录执行 `.venv/bin/python -m pip install -r requirements.txt`，然后仍用 `.venv/bin/python` 运行脚本；Windows 对应使用 `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`。安装与运行使用同一个虚拟环境，避免依赖安装在系统 Python 而脚本运行在另一个环境。

### IAM Identity Center / SSO

```bash
aws configure sso --profile audit
aws sso login --profile audit
```

随后给脚本传 `--profile audit`。SSO 登录会话到期需要重新登录，所以无人值守长期任务优先选择合适的工作负载角色。

### EC2 IAM Role

在 IAM 创建可信服务为 EC2 的角色，挂载 `iam-policy.json`，将角色关联到运行脚本的 EC2 实例。实例上的 boto3 会通过默认凭据链获取角色临时凭据，无需 `aws configure` 或 Access Key。运行时省略 `--profile`，并清除不再使用的本地静态凭据配置，避免默认凭据链优先选中旧凭据。

## 三、先验证权限

有 AWS CLI 时执行：

```bash
aws --profile audit sts get-caller-identity --region eu-north-1
aws --profile audit cloudtrail lookup-events --region eu-north-1 --max-results 1 --no-paginate --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false
aws --profile audit cloudtrail lookup-events --region eu-north-1 --max-results 1 --no-paginate --lookup-attributes AttributeKey=EventSource,AttributeValue=secretsmanager.amazonaws.com
aws --profile audit ec2 describe-regions --region eu-north-1 --query "Regions[].RegionName" --output text
```

第一条确认当前账号和身份；中间两条验证实际使用的两类 CloudTrail 查询；最后一条只在 `--regions all` 时需要。固定区域策略不能执行最后一条，这是预期行为。`GetCallerIdentity` 本身不需要另加 Allow 权限。EC2 角色方式验证时去掉 `--profile audit`。

查询结果为空，只能说明查询当时没有匹配的可见记录；还需确认账号、日期、时区和区域是否正确。

## 完整性与验证

CloudTrail LookupEvents 仅覆盖最近 90 天的管理事件，不包含数据事件。任一区域查询或事件解析失败时，JSON、PDF、邮件主题和正文均标记不完整；相关问题按配置触发 Lark 异常告警。查询成功也可能遇到 CloudTrail 日志延迟，应结合任务日志复核。每次调用按 EventID 去重计数，不等于人工操作或资源数量。

旧的单账号网页/机器人辅助代码保留以兼容历史用途；当前部署服务固定使用 `aws_audit_multi.py` 的 PDF 邮件流程。旧网页文件不被新任务更新，服务器现有 Nginx 配置由使用者自行清理。

本地离线回归不连接真实 AWS、SMTP 或 Lark：

```bash
.venv/bin/python -m unittest -q test_aws_daily_audit test_audit_config test_audit_multi test_audit_mail test_audit_mail_delivery test_audit_pdf test_audit_identity_summary test_audit_event_catalog test_deployment test_install_script test_audit_schedule test_audit_alerts
bash -n install.sh
bash install.sh --dry-run
```

Linux CI 另验证完整安装/更新/回滚生命周期、配置文件字节保留、初始化模板、生成的 systemd 单元和北京时间日历；安装器无需 Nginx。

## 官方资料

- [Lark 自定义机器人：消息类型、签名与安全配置](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/bot-v3/use-custom-bots-in-a-group)
- [CloudTrail Event history 范围、费用和限制](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [LookupEvents：90 天、分页、时间边界和限流](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)
- [CloudTrail IAM 授权表](https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudtrail.html)
- [EC2 IAM 授权表](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html)
- [IAM 和 STS 在 CloudTrail 中的区域与日志行为](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)
- [Secrets Manager 的 CloudTrail 审计](https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html)
- [GetSecretValue：敏感值不进入 CloudTrail](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html)
- [BatchGetSecretValue：逐个 Secret 产生读取事件](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_BatchGetSecretValue.html)
- [CloudTrail 参数、只读标记和字段限制](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- [CloudTrail 身份字段](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- [IAM：优先使用角色和临时凭据](https://aws.amazon.com/iam/resources/best-practices/)
- [GetCallerIdentity 权限说明](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
