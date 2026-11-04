# AWS 多账号操作审计：PDF 邮件日报

按 AWS 账号读取 CloudTrail 管理事件，每个 AWS 账号生成一份按 IAM 用户 / 角色逐行统计的中文 PDF，所有启用账号的 PDF **合并到同一封邮件**，支持多个收件人和抄送。正常日报只通过邮件发送；开启 Lark 异常告警后，仅在采集、生成、发布或邮件投递失败时通知群。

PDF 保留 **IAM 用户 / 角色维度**：例如 `beiou`、`hhjgx` 各占一行，列出身份类型、新增、修改、删除、Secrets Manager 查看、登录、其他、失败及合计，最后显示 AWS 账号合计。PDF 不展示逐条 API、参数、资源、来源 IP 或每次执行时间。身份数量较多时自动分页并重复表头，不截掉用户。

网页与 JSON 保留详细操作：谁、北京时间几点、调用什么 API、涉及什么资源、提交什么参数以及请求结果，并补充已识别操作的中文说明和 AWS 官方 API 文档链接。普通查看忽略，Secrets Manager 查看保留。这里审计 AWS 管理操作，不采用 RDS 的 SQL/IP 汇总口径。

## 已确认的部署配置

| 项目 | 配置 |
| --- | --- |
| 安装目录 | `/usr/local/aws-user-audit` |
| Python 虚拟环境 | `/usr/local/aws-user-audit/.venv` |
| 统一私有 JSONC | `/usr/local/aws-user-audit/aws-audit-config.json` |
| 归档 | `/usr/local/aws-user-audit/reports/<账号ID>/<报表结束日期>/` |
| 网页 | `/usr/local/aws-user-audit/index/index.html` 为多账号总览；点击账号进入明细 |
| 单账号网页 | `/usr/local/aws-user-audit/index/<账号ID>/index.html` |
| 邮件状态 | `/usr/local/aws-user-audit/.state/`，不放进网页目录 |
| Nginx 配置 | `/etc/nginx/conf.d/zybocedata-pass.v668live.com.conf` |
| 网站入口 | `8889`、`/audit/`，详情链接 https://zybocedata-pass.v668live.com/audit/ |
| 原前端 / RDS 路由 | `/` → `127.0.0.1:8890` 和 `/audit_rds/` 原文保留 |
| 每日执行 | **北京时间 10:05**（`DAILY_MAIL_TIME`），不依赖服务器系统时区 |
| 查询窗口 | **昨日 10:00 ≤ 事件时间 < 今日 10:00**，24 小时，相邻日报不重叠 |
| 停机恢复 | 只补最近一份已结束的日报；配置的统计结束时刻之前恢复，选择前一结束日 |

网页密码已取消。**安装/更新只配置服务与定时器，不查询 AWS，不发送邮件或 Lark。** 没有成功执行过报告时网页目录为空是正常现象。

## 安装和更新

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

`/opt/aws-user-audit-src` 是源码目录，实际运行目录是 `/usr/local/aws-user-audit`。安装器首次会创建权限 `0600` 的私有配置模板，然后停止；填写配置后重跑安装。不要将真实 Key、授权码或机器人 Webhook 提交到 GitHub。

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

安装器只在指定 Nginx 文件中唯一匹配域名和 `listen 8889` 的 server 内修改 `/audit` 和 `/audit/`，alias 更新为新目录的 `index/`。原前端及 `/audit_rds`、`/audit_rds/` 保持原文；未知路由或匹配不唯一时停止。先备份、`nginx -t`，通过后仅 reload；失败恢复，不 stop/restart。安装失败恢复原任务状态；pip 依赖安装不具备完整回滚。

新路径不应与 RDS 项目共用。原有网页密码服务在静态页面切换成功后停用。报告使用同源外部 CSS/JS，适配原 `style-src 'self'` CSP。

## 私有配置填写

完整带注释模板为 `aws-audit-config.example.json`，预留 7 个账号，后续可继续追加。账号 1 先启用，其他配置好后设置 `ENABLED: true`。账号 ID 占位值必须替换为真实的 12 位账号 ID。

```json
{
  "OUTPUT_DIRECTORY": "reports",
  "PUBLISH_DIRECTORY": "index",
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
      "NAME": "production",
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
- `MAIL_RECIPIENTS` 至少一个地址，`MAIL_CC` 可为空；会对 To/CC 去重。邮件正文先给出各 AWS 账号增删改数量，再附 IAM 用户 / 角色统计 PDF。
- 使用原 root profile `audit` 时保留 `AWS_PROFILE: "audit"`，Key 留空。使用单独 Key 时 `AWS_PROFILE` 留空，成对填写 ID/Secret；临时凭据还需 Token。均留空时使用默认凭据链/实例角色。每个启用账号先通过 STS 核对归属，错配账号不继续读取 CloudTrail。
- `REGIONS: "all"` 扫描本账号已启用区域，标准 AWS 分区另纳入 `us-east-1` 以覆盖全局事件；也可填写区域数组。单个账号失败不阻止其他账号，失败账号 PDF 明确标记不完整，邮件标题也带不完整标记，不把失败当成零操作。
- 开启异常群时填真实 `LARK_WEBHOOK_URL` 并设置 `LARK_ALERTS_ENABLED: true`，签名校验开启时同时填写 `LARK_SIGNING_SECRET`。原 `lark-config.json` 可供你复制地址和签名；新定时任务只读取统一 JSON，不发送正常 Lark 日报。单次发现失败即告警，同一轮报告的同类异常一小时内抑制重复；只在任务实际执行时检查，不另加分钟级重试定时器。
- 相对目录均以配置文件所在目录计算。`PUBLISH_DIRECTORY` 须与安装器 Nginx alias 目录一致，默认 `index`；自定义时同时传 `install.sh --publish-dir`。
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
ls -lh /usr/local/aws-user-audit/index/
```

手动指定报表结束日；不加 `--send-mail` 仅采集并生成 PDF/HTML，默认也更新网页：

```bash
sudo /usr/local/aws-user-audit/.venv/bin/python /usr/local/aws-user-audit/aws_audit_multi.py   --config /usr/local/aws-user-audit/aws-audit-config.json --date 2026-11-04
```

明确手动发送（所有启用账号合并一封；此显式操作可额外超出自动邮件每日额度）：

```bash
sudo /usr/local/aws-user-audit/.venv/bin/python /usr/local/aws-user-audit/aws_audit_multi.py   --config /usr/local/aws-user-audit/aws-audit-config.json --date 2026-11-04 --send-mail
```

同一份已接受或投递不确定的报告不会直接重复发；核实邮箱后确需重发时，手动命令再加 `--force-resend`。不要删除 `.state/mail-delivery.json` 来重置额度。自动邮件按**发送当天北京时间**最多一封，账号、收件人、数据或完整度改变不触发第二封。后续重跑仍更新本地报告与网页。`AUTO_MAIL_MAX_PER_DAY: 0` 关闭自动邮件，仍生成本地报告。

提交 SMTP 前先落盘 `sending`；进程中断、部分拒收、提交中断或损坏状态保守视为投递不确定，停止自动重发。明确认证/连接失败不消耗成功额度，等下次实际运行再试；此项目没有“15 分钟后自动重试”机制。SMTP 接受只代表服务器接受，不保证最终进入收件箱。

产物示例：

```text
/usr/local/aws-user-audit/
  reports/123456789012/2026-11-04/
    2026-11-04-aws操作审计.html
    123456789012-2026-11-04-aws操作审计.pdf
    report.json
    audit-report.css
    audit-report.js
  index/
    index.html
    audit-report.css
    audit-report.js
    123456789012/index.html
  .state/
    mail-delivery.json
```

返回码：0 完成或按规则跳过邮件，1 启动/配置错误，2 查询不完整，3 通知失败或投递不确定，4 网页发布失败，5 报告/PDF 生成失败。网页失败仍可发送完整 PDF，邮件正文不会附指向旧网页的链接。

后文保留单账号 CLI、IAM 和可选手动 Lark 功能，供兼容已有手工命令使用；新定时部署使用上面的多账号邮件入口。


## PDF 的账号维度

AWS 账号与 IAM 身份是两层：每个 AWS 账号一份 PDF；PDF 内每个 IAM 用户或角色一行。账号名相同但属于不同 AWS 账号时，各自在对应 PDF 中统计，不跨账号合并。

身份汇总依据已去重、已按查看规则过滤的事件生成，输出到 JSON 的 `actors` 字段。IAM 用户使用 ARN 或主体 ID 识别；同一角色的不同会话按签发角色合并，不把会话名称认定为自然人。Root、AWS 服务、Identity Center、联合身份和未知身份分别标注。用户与角色即使同名也不合并。分类计数包含失败请求，失败数作为其中子集单列。

PDF 只读取汇总白名单，校验各身份的分类数量、失败和合计与 AWS 账号总数完全一致；不会读取或输出原始事件内容。旧报告缺少身份汇总时需要用新版程序重新生成，不能拿仅有账号总数的数据推测各 IAM 用户次数。

## 操作识别与“其他操作”

`audit_actions.py` 包含按服务和 API 精确匹配的审核规则，补充旧版仅靠名称前缀遗漏的操作，例如 EC2 监控开关与 Spot 请求、RDS 故障/主备切换、IAM MFA、KMS 授权与计划删除、CloudFormation 回滚、Secrets Manager 复制和 Organizations 账号移动。增删改是依据 API 功能做的报告归类，不是 AWS 官方另行提供的 CRUD 标签；请求未报错也不证明异步任务已完成。

已经确认的实际问题：IAM `ListOrganizationsFeatures` 是**查看组织集中 root 访问功能**，`ServiceAccessNotEnabledException` 表示 Organizations 尚未启用 IAM 受信访问。它是普通查询，旧版在失败事件携带非只读标记时误入“其他操作”。新版按已核对的服务/API 精确识别并忽略该普通查询，包括失败请求；不会把所有名称带 Get/List 的未知非只读调用一概丢弃。[AWS 官方 API 说明](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListOrganizationsFeatures.html)

CloudTrail `readOnly=true` 的普通读取仍忽略，Secrets Manager 查看保留。`GetSessionToken`、`GetFederationToken` 和 `AssumeRoot` 等 STS 临时凭据请求以“身份会话”标记归入登录信息；网页明确区分临时凭据请求与控制台登录，不把它们写成自然人登录成功。[IAM / STS CloudTrail 说明](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)

KMS 加密、解密或签名是使用密钥的操作，不能认定为修改密钥配置；若作为非只读事件进入范围，会保留在“其他操作”并显示明确功能。仍无法确认的 API 保留原服务/API 和已有参数，不能为了减少“其他操作”数量而强行归入增删改。[CloudTrail 事件字段](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)

对于本机已安装 SDK 中可识别的服务 API，新版还会离线读取 botocore 的公开模型说明，在网页和 JSON 附上英文功能摘要和官方 API 链接；不连接 AWS、不读取凭据、不增加 API 权限或查询请求。仅凭 IAM 的 Write 权限标签无法区分新增/删除/修改，也不能将权限动作当作一定存在的 CloudTrail API 事件。[AWS 服务参考说明](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html)

失败次数是分类事件的子集，不再额外加到总数中；各类别统计包含失败请求。PDF 改版不会清空邮件回执或重置当日自动邮件额度，已发送日期不会因改版自动再发一封。

## 报告能说明什么

例如，日志中存在 `hhjgx` 调用 `ModifyInstanceAttribute` 的事件时，报告会显示操作时间、实例 ID、提交的属性参数、API 名称及调用是否报错。HTML 只保留标题、账号、生成时间、分类卡片、按操作者汇总、搜索和分类明细；明细使用“北京时间”和“操作信息”列名，时间不附 IANA 时区或偏移值。HTML 不展示来源横幅、查询窗口、区域概要、覆盖状态或技术说明；相关元数据、范围与警告保留在 JSON 和终端输出中。本版本不输出 CSV。

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

## 四、生成、发布并通知

### 日期与窗口

默认报表日期是北京时间今天。`--today`与默认相同；`--date YYYY-MM-DD`指定窗口结束日期，两者互斥。例如`--date 2026-10-28`固定查询2026-10-27 07:00至2026-10-28 08:00，共25小时。任何运行时间都不会将结束时间延伸到当前时刻。未结束窗口会拒绝。

生成并推送总览：

```bash
.venv/bin/python aws_daily_audit.py --profile audit --send-lark --publish-dir /usr/local/aws-user-audit/index
```

只生成文件，不发送Lark时省略`--send-lark`。EC2角色方式省略`--profile audit`。Windows将Python路径替换成`.\.venv\Scripts\python.exe`。

### 日期归档与网页副本

文件保存为：

```text
reports/<AWS账号ID>/2026-10-28/2026-10-28-aws操作审计.html
reports/<AWS账号ID>/2026-10-28/report.json
/usr/local/aws-user-audit/index/index.html
/usr/local/aws-user-audit/index/audit-report.css
/usr/local/aws-user-audit/index/audit-report.js
```

Linux实际AWS查询默认发布到`/usr/local/aws-user-audit/index/index.html`，日期HTML和JSON仍保留。CSS和搜索JavaScript是同目录独立文件，兼容现有 `default-src 'self'; style-src 'self'` 策略。代码会先复制全部静态文件，再原子替换index.html；不将JSON发布到网页目录。缺少任一引用文件时停止发布，保留旧index.html。

样式和脚本链接带内容版本参数，避免浏览器沿用旧缓存。查看下载的日期HTML时，需要同时保留同目录的 `audit-report.css` 和 `audit-report.js`。请勿只手动复制一个HTML文件；脚本的发布函数会自动复制三个文件。

本地服务的静态文件也需能访问，并返回正确的MIME类型，尤其开启 `X-Content-Type-Options: nosniff` 时：

```bash
curl -sSI --max-time 10 http://127.0.0.1:9999/audit/audit-report.css
curl -sSI --max-time 10 http://127.0.0.1:9999/audit/audit-report.js
```

CSS应返回200和`Content-Type: text/css`；JavaScript应返回200和JavaScript MIME类型（例如`text/javascript`或`application/javascript`）。如果返回404或text/html，需要检查现有Web服务对该目录下静态文件的映射。无需放宽CSP或增加unsafe-inline。域名访问问题与本机9999端口服务是不同的连接链路，本次代码不修改DNS或反向代理。

脚本执行用户需要对发布目录有写入权限，Web服务器需已将`/audit/`映射到该目录。代码不修改Web服务器配置。发布失败保留日期归档，返回4（若审计本身不完整，优先返回2），不发送Lark，以免链接指向旧报告。

Windows和离线输入默认不更新网页；可显式使用`--publish-dir`。`--no-publish`禁止网页复制，与`--publish-dir`互斥。同一日期重跑覆盖归档及index.html；重新加`--send-lark`会再次通知。

### Lark数量总览和详情链接

只有显式添加`--send-lark`才会发送。顺序为：生成归档 → 更新index.html → 发送Lark总览。

默认通知先显示新增、删除、修改数量，再显示Secrets Manager查看、登录及失败数量，最后附详细报告链接：

[查看详细报告](https://zybocedata-pass.v668live.com/audit/)

默认`--lark-mode overview`不包含逐条事件、参数或响应。临时需要最近8条可使用`--lark-mode summary`；全部脱敏明细分条发送使用`--lark-mode full`。full每条请求不超过20KB，并以0.7秒间隔节流；不是HTML附件。

### Lark私有配置

代码包只有`lark-config.example.json`模板。实际`lark-config.json`已被Git忽略，不进入代码包；保留自己的私有配置。模板中的Webhook是占位符，必须替换为目标群机器人的真实地址。

```bash
cp lark-config.example.json lark-config.json
chmod 600 lark-config.json
```

已有私有配置不要执行复制覆盖。Windows复制命令为`Copy-Item lark-config.example.json lark-config.json`。

| 配置项 | 说明 |
| --- | --- |
| `webhook_url` | 从目标群机器人设置复制的纯HTTPS地址 |
| `signing_secret` | 开启签名校验时填写签名密钥 |
| `message_mode` | 模板为overview；主脚本以--lark-mode为准 |
| `report_url_template` | 模板已填写固定/audit/链接；主脚本以--report-url为准 |
| `title_prefix` | 标题前缀；开启关键词校验时应包含允许的关键词 |

环境变量`LARK_WEBHOOK_URL`、`LARK_SIGNING_SECRET`会覆盖文件。若机器人启用IP白名单，应放行服务器的公网出口IP。无需增加AWS IAM权限。

### 参数

| 参数 | 默认值 | 用途 |
| --- | --- | --- |
| `--profile` | 不指定 | boto3默认凭据链，外部服务器可填audit |
| `--regions` | all | 所有已启用区域，或逗号分隔区域名 |
| `--timezone` | Asia/Shanghai | 固定北京时间 |
| `--date` | 北京时间今天 | 25小时窗口结束日期 |
| `--today` | 与默认相同 | 今天为窗口结束日期 |
| `--output-dir` | reports | 日期归档根目录 |
| `--publish-dir` | Linux实际查询为/usr/local/aws-user-audit/index | 复制HTML为index.html |
| `--no-publish` | 不启用 | 不更新网页副本 |
| `--send-lark` | 不启用 | 生成及发布后才推送 |
| `--lark-config` | lark-config.json | 可指定配置文件绝对路径 |
| `--lark-mode` | overview | 数量总览和链接，可选summary/full；覆盖配置文件 |
| `--report-url` | https://zybocedata-pass.v668live.com/audit/ | 通知详情链接；覆盖配置文件 |
| `--input-file` | 不指定 | 离线JSON输入，不访问AWS |

### 离线测试

```bash
.venv/bin/python aws_daily_audit.py --input-file examples/sample-events.json --date 2026-10-28 --publish-dir preview-site
```

此命令生成虚构数据报告，并复制到项目下`preview-site/index.html`。不访问AWS，也不发Lark；离线默认不发布到线上目录。JSON保留示例来源，HTML没有来源横幅，请勿将示例当作生产报告。

### 网页访问

当前部署取消网页密码，使用文首 install.sh 流程。它将 /audit/ 恢复为 Nginx 静态页面，不使用 9998 认证服务；原前端 8890 转发保留。

### Lark 错误 19001 与本地配置诊断

`19001` 本身不能唯一确定原因，应结合错误细节定位。模块会将已知错误消息映射为安全的排障提示，不回显 Webhook token。如果提示 `incoming webhook access token invalid`，说明 Webhook/token 无效：请在目标群机器人的设置中重新复制当前 Webhook 地址并更新私有配置，同时检查机器人是否已被删除或重建、地址是否失效，以及配置中是否仍是 `REPLACE` 等示例占位内容。

尤其注意 `LARK_WEBHOOK_URL` 环境变量会覆盖文件里的地址：即使文件已改对，运行用户或调度任务的环境变量仍可能指向旧机器人。`19001` 也可能对应消息请求参数错误，应依据模块提供的具体提示排查，不能仅凭错误码就认定签名或 Webhook 一定有误。机器人原有的签名、关键词及 IP 白名单要求仍需满足。

本地排查步骤：

1. 进入包含 `aws_daily_audit.py`、`lark_notify.py` 和私有配置的脚本目录。
2. 只有希望使用配置文件里的地址时，才在当前终端执行 `unset LARK_WEBHOOK_URL`，避免环境变量继续覆盖文件。Windows PowerShell 对应执行 `Remove-Item Env:LARK_WEBHOOK_URL -ErrorAction SilentlyContinue`；希望继续使用环境变量时跳过这一步。
3. 编辑 `lark-config.json`，将 `webhook_url` 填成从目标群机器人设置中复制的纯 HTTPS 地址。地址中不要带 Markdown 的 `[]()`、尖括号、空白、换行或额外的 `?` 查询参数，也不能保留 `REPLACE` 等占位内容。
4. 执行本地诊断：

```bash
.venv/bin/python -m lark_notify --config lark-config.json --check-config
```

Windows 将 Python 路径替换成 `.\.venv\Scripts\python.exe`。新版诊断会在校验前输出实际配置文件的绝对路径和生效来源，校验失败时同样保留这些信息，并给出具体失败原因；可安全显示目标主机及环境变量是否覆盖文件，不回显 token。该命令没有外网请求，也不发送消息，因此不能验证远端 token 是否仍有效。需要实际推送时，使用上面的主脚本 `--send-lark` 命令。

## 五、旧单账号脚本的固定08:01定时示例（新部署使用前文配置）

请使用文首的 install.sh 和 aws-user-audit.timer，不要另加 cron，以免重复采集和通知。安装不立即推送，后续停机恢复补跑最近一份已结束日报。

## 六、完整性、错误和数据边界

退出码：0=生成、所请求查询和已启用的发布/推送均完成；1=启动/参数/凭据/输入输出错误；2=审计查询或解析不完整（优先于发布/推送失败）；3=报告已生成但Lark失败；4=网页副本发布失败且本次未发Lark。文件会在后续发布或推送失败时保留。参数解析错误也可能由argparse返回2但不生成报告，应结合终端输出判断。0不代表没有风险操作。

- 每个区域分别查询 `ReadOnly=false` 与 `EventSource=secretsmanager.amazonaws.com`，完整翻页，按事件 ID 去重；遵守 LookupEvents 每账号每区域每秒两次请求的限制，并重试暂时性失败。普通只读事件不进入日报，Secrets Manager 读取单独保留。
- 任一区域查询或事件解析失败，JSON 会标记 **不完整** 并记录失败范围，终端输出会提示异常，退出码为 `2`。HTML 不展示查询状态和覆盖范围，因此应结合 JSON、终端和退出码检查完整性，不能仅凭 HTML 判断“全天无异常”。调度器应监控非零退出码和 JSON 完整性。
- Event history 仅包含最近 90 天管理事件，不要求事先建立 Trail；不含 S3 对象写入/删除、Lambda 调用等数据事件，也不能汇总组织其他账号。若需要这些事件或超过 90 天留存，应另外配置 Trail / CloudTrail Lake 及对应采集方案。
- 普通写入覆盖以 AWS 返回的 `ReadOnly=false` 管理事件为准。AWS 缺失/异常分类、未被 CloudTrail 记录的操作以及日志延迟均可能影响覆盖；无法通过脚本补造不存在的事件。
- 自动发现只扫描当前分区内当前已启用的区域。手工限定区域、区域权限限制、已关闭区域或其他分区的历史活动不在完整覆盖承诺中。
- 来源身份为 AWS 服务或角色时，报告仍保留；需要判断是否对应某个人，应结合组织的角色会话规范或身份系统映射，不根据名称猜测。
- 两类查询存在重叠，会按事件 ID 消除同一事件的重复；批量 Secret 读取可能同时产生批量调用事件与每个 Secret 的读取事件，它们是不同审计记录，不应简单按时间和用户名合并。

## 七、离线验证

项目提供离线单元测试，其中包括使用官方 AWS SDK 的 `botocore.stub.Stubber` 按服务模型校验请求和模拟响应。测试及样例演示均在离线数据上验证，未连接实际 AWS 账号，不能代替部署后对账号权限与真实数据的验证。

安装依赖后，在项目目录重新运行：

```bash
.venv/bin/python -m unittest -v
```

Windows 对应命令：

```powershell
.\.venv\Scripts\python.exe -m unittest -v
```

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
