# AWS 账号每日审计报告

## 已确认的服务器部署方式（使用 install.sh）

本次部署取消网页密码认证，报告由现有 Nginx 直接提供。安装/更新过程只配置服务和定时器，不查询 AWS，也不推送 Lark。

| 项目 | 配置 |
| --- | --- |
| GitHub 仓库 | https://github.com/userreksai/aws-user-audit |
| 代码 / Python 虚拟环境 | `/usr/local/shenji/` / `/usr/local/shenji/.venv/` |
| 网页发布位置 | `/usr/local/shenji/index/index.html`，同目录包含 CSS 和 JS |
| 日期归档 | `/usr/local/shenji/reports/<账号>/<报表日期>/` |
| Nginx 配置 | `/etc/nginx/conf.d/zybocedata-pass.v668live.com.conf` |
| Nginx 入口 / 原前端 | `8889` / `127.0.0.1:8890`，原前端转发保持原文 |
| 审计路径 / 详情链接 | `/audit/` / https://zybocedata-pass.v668live.com/audit/ |
| AWS / Lark | root 原有 profile `audit` / `/usr/local/shenji/lark-config.json` |
| 每日任务 | 北京时间 `08:01`，不依赖服务器系统时区 |
| 停机恢复 | 补跑最近一份已结束的日报，不自动回填所有缺失日期 |

首次部署，从仓库克隆到一个新的源码目录，再执行安装脚本。不要把仓库克隆到已经存放配置、虚拟环境和报告的目录中：

```bash
git clone https://github.com/userreksai/aws-user-audit.git /opt/aws-user-audit-src
cd /opt/aws-user-audit-src
sudo bash install.sh
```

安装器适用于 Linux + systemd + 宿主机 Nginx。它使用现有 Python 3.10+；Debian/Ubuntu 缺少 Python 或 venv 时安装必要依赖，不安装或重启 Nginx。AWS 凭据继续使用 root 的原有 profile `audit`，不会生成、索取或打印密钥。Lark 配置必须保存在服务器私有文件中；仓库只提供 `lark-config.example.json`，不会包含真实 Webhook。缺少配置或本地检查失败时，安装停止且不会启用任务。

预览部署计划（不改系统、不联网、不发送通知）：

```bash
bash install.sh --dry-run
```

以后从 GitHub 更新代码：

```bash
sudo bash /usr/local/shenji/install.sh --update
```

更新使用临时目录获取 `main` 并复制明确的代码文件，保留 `lark-config.json`、`.aws`、`.venv`、`reports/`、`index/` 和旧认证状态。不会执行 `git reset`、删除现有配置或将示例数据发布到线上。

安装器只修改已确认配置文件内唯一匹配 `server_name zybocedata-pass.v668live.com` 和 `listen 8889` 的两个审计 location。原有 `location /`、到 `8890` 的转发、请求头及其他业务配置逐字保留；若匹配不唯一、有未展开的 server 级 include、未知审计路由或原前端缺失，会停止并给出提示。修改前保存备份，`nginx -t` 通过后才 reload，检查或 reload 失败会恢复原文件，不执行 stop/restart。切换为静态审计页成功后禁用旧的 `aws-audit-web.service`，不再依赖 `9998`，也不发送访问密码。

安装器会检查旧 cron 中的日报任务；发现可能重复执行时停止，让你先移除对应旧任务，不会自行删除其他 cron。新的服务名称：

```text
aws-user-audit.service    单次采集、生成、发布、Lark 总览
aws-user-audit.timer      每天北京时间 08:01 触发，停机恢复补最近一份
```

计时器为 `Persistent=true`。安装/更新在启用前更新本任务的计时器时间戳，跳过安装当次的历史补触发，不主动执行报告；后续停机错过定时时间后，恢复会正常补跑。服务每次明确传递报表结束日期：北京时间 08:00 前选择昨天，08:00 起选择今天。因此凌晨恢复不会查询尚未结束的窗口。多天停机只补最近一份；手工补其他日期见下文。

验证部署与查看日志：

```bash
systemctl list-timers --all aws-user-audit.timer
systemctl status aws-user-audit.timer --no-pager
journalctl -u aws-user-audit.service -n 100 --no-pager
curl -sSI --max-time 5 -H 'Host: zybocedata-pass.v668live.com' http://127.0.0.1:8889/audit/
```

尚未生成过报告时 `/audit/` 可能返回 403/404；安装不会用示例报告冒充真实报告。已有网页在更新时保留，到下次任务才替换。首次定时运行需要 AWS 实际权限、网络和有效 Lark Webhook；安装检查只验证本地格式，不能证明远端授权或机器人投递成功。

需要手工执行一次时（会真实采集并推送 Lark）：

```bash
sudo systemctl start aws-user-audit.service
```

手工补指定报表日期（同一日期重跑会覆盖该归档和网页，并再次通知）：

```bash
sudo /usr/local/shenji/.venv/bin/python /usr/local/shenji/deploy/run_scheduled.py --date 2026-10-28
```

后面的 AWS 授权和命令行说明仍适用；旧手工密码认证部署已取消，不再作为本次部署步骤。


脚本默认查询北京时间昨天07:00至今天08:00的25小时 CloudTrail 管理事件，生成中文HTML日报和JSON明细。报表日期使用窗口结束日，例如2026-10-28日报覆盖2026-10-27 07:00至2026-10-28 08:00。报告按新增、删除、修改、Secrets Manager查看、登录信息分类，普通查看忽略。

固定北京时间（Asia/Shanghai，UTC+8），扫描当前账号同一AWS分区内所有已启用区域。每天北京时间08:01执行，相邻两份日报有意重叠07:00至08:00这一小时，单份报告内部仍按EventID去重。查询左闭右开；08:00整的事件由之后覆盖该时刻的窗口收录。08:00前执行当日报表会拒绝，不会缩短窗口。

这里提供了脚本、最小权限策略和离线演示。尚未连接你的实际 AWS 账号，真实数据采集需要先由你配置身份与授权。示例数据不代表真实账号活动。

## 报告能说明什么

例如，日志中存在 `hhjgx` 调用 `ModifyInstanceAttribute` 的事件时，报告会显示操作时间、实例 ID、提交的属性参数、API 名称及调用是否报错。HTML 只保留标题、账号、生成时间、分类卡片、按操作者汇总、搜索和分类明细；明细使用“北京时间”和“操作信息”列名，时间不附 IANA 时区或偏移值。HTML 不展示来源横幅、查询窗口、区域概要、覆盖状态或技术说明；相关元数据、范围与警告保留在 JSON 和终端输出中。本版本不输出 CSV。

登录信息仅归入能识别的登录事件，例如 `ConsoleLogin`、`CheckMfa`、`GetSigninToken`；`ConsoleLogin` 明确显示中文登录操作及成功或失败结果。不能识别为增删改的非登录写操作保留在“其他操作”，不会归入登录。登录信息和其他操作分类仅在实际存在对应事件时显示。

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
.venv/bin/python aws_daily_audit.py --profile audit --send-lark --publish-dir /usr/local/shenji/index
```

只生成文件，不发送Lark时省略`--send-lark`。EC2角色方式省略`--profile audit`。Windows将Python路径替换成`.\.venv\Scripts\python.exe`。

### 日期归档与网页副本

文件保存为：

```text
reports/<AWS账号ID>/2026-10-28/2026-10-28-aws操作审计.html
reports/<AWS账号ID>/2026-10-28/report.json
/usr/local/shenji/index/index.html
/usr/local/shenji/index/audit-report.css
/usr/local/shenji/index/audit-report.js
```

Linux实际AWS查询默认发布到`/usr/local/shenji/index/index.html`，日期HTML和JSON仍保留。CSS和搜索JavaScript是同目录独立文件，兼容现有 `default-src 'self'; style-src 'self'` 策略。代码会先复制全部静态文件，再原子替换index.html；不将JSON发布到网页目录。缺少任一引用文件时停止发布，保留旧index.html。

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
| `--publish-dir` | Linux实际查询为/usr/local/shenji/index | 复制HTML为index.html |
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

## 五、每天北京时间08:01执行

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
