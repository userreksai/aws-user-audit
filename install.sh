#!/usr/bin/env bash
# Install/update the audit job without querying AWS or sending notifications.
set -Eeuo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ORIGINAL_DIR=$PWD
INSTALL_DIR=/usr/local/aws-user-audit
CONFIG_PATH=
PYTHON=python3
DRY_RUN=0
UPDATE=0
UNIT_DIR=/etc/systemd/system
TIMER_STAMP=/var/lib/systemd/timers/stamp-aws-user-audit.timer
WORK_DIR=
BACKUP_DIR=
TRANSACTION=0
COMMITTED=0
UNITS_CHANGED=0
STAMP_CHANGED=0
CODE_CHANGED=0
OLD_TIMER_ACTIVE=0
OLD_TIMER_ENABLED=disabled
ROLLBACK_FAILED=0
STAGING_FILES=()

usage() {
    cat <<'HELP'
Usage: sudo bash install.sh [options]
  --install-dir DIR   Code/venv directory (default: /usr/local/aws-user-audit)
  --publish-dir DIR   Deprecated; accepted and ignored (PDF/email only)
  --nginx-config FILE Deprecated; accepted and ignored (Nginx is not touched)
  --config FILE       Private unified JSON/JSONC (default: INSTALL_DIR/aws-audit-config.json)
  --python COMMAND    System Python >=3.10 used to create the venv
  --update            Clone public main into a temporary checkout first
  --dry-run           Render/print a local plan; no root, network or system changes
  --help              Show this help

The installer never starts aws-user-audit.service or calls AWS/SMTP/Lark.
The timer uses DAILY_MAIL_TIME in the private JSON (default: 10:05 Asia/Shanghai).
REPORT_START_TIME/REPORT_END_TIME set the report window (default: yesterday 10:00 to today 10:00).
After editing times, rerun this installer to apply the systemd calendar.
Its timestamp is advanced at install time so installation itself does not run a report.
HELP
}

say() { printf '%s\n' "$*"; }
die() { printf '安装未完成：%s\n' "$*" >&2; exit 1; }
need_value() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "参数 $1 缺少值。"; }

read_schedule() {
    local key value
    DAILY_MAIL_TIME=
    REPORT_START_TIME=
    REPORT_END_TIME=
    while IFS='=' read -r key value; do
        case $key in
            DAILY_MAIL_TIME|REPORT_START_TIME|REPORT_END_TIME) printf -v "$key" '%s' "$value" ;;
            *) die '生成的时间计划格式无效。' ;;
        esac
    done <"$WORK_DIR/units/schedule.env"
    [[ $DAILY_MAIL_TIME =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ \
        && $REPORT_START_TIME =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ \
        && $REPORT_END_TIME =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] \
        || die '生成的时间计划必须为 HH:MM。'
}

while (($#)); do
    case $1 in
        --install-dir) need_value "$@"; INSTALL_DIR=$2; shift 2 ;;
        --publish-dir|--nginx-config)
            need_value "$@"; say "兼容参数 $1 已忽略；本版本仅生成 PDF/JSON 和邮件，不操作网页或 Nginx。"; shift 2 ;;
        --config) need_value "$@"; CONFIG_PATH=$2; shift 2 ;;
        --python) need_value "$@"; PYTHON=$2; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --update) UPDATE=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "未知参数；请使用 --help。" ;;
    esac
done

[[ -n $CONFIG_PATH ]] || CONFIG_PATH=$INSTALL_DIR/aws-audit-config.json
for setting in INSTALL_DIR CONFIG_PATH; do
    value=${!setting}
    [[ $value == /* ]] || value=$ORIGINAL_DIR/$value
    [[ $value =~ ^/[A-Za-z0-9_./-]+$ && $value != //* ]] \
        || die '部署路径必须是明确的 Linux 绝对路径，只能使用字母、数字、下划线、点、短横线和斜杠。'
    case $value/ in */../*|*/./*) die '部署路径不能包含 . 或 .. 路径段。' ;; esac
    printf -v "$setting" '%s' "${value%/}"
done
case $INSTALL_DIR in ''|/|/usr|/usr/local|/etc|/var|/bin|/sbin|/root|/home|/tmp) die '请指定专用安装目录。' ;; esac
for marker in rds_multi.py rds_config.py; do
    [[ ! -e $INSTALL_DIR/$marker && ! -L $INSTALL_DIR/$marker ]] \
        || die '安装目录包含 RDS 项目标识；请使用独立 AWS 账号审计目录，不能覆盖 RDS。'
done

atomic_file() {
    local source=$1 target=$2 reference=${3:-} mode=${4:-0644} stage
    stage=$(mktemp "${target}.install.XXXXXXXX") || return 1
    STAGING_FILES+=("$stage")
    cp -- "$source" "$stage" || return 1
    if [[ -n $reference && -f $reference ]]; then
        chmod --reference="$reference" -- "$stage" || return 1
        chown --reference="$reference" -- "$stage" || return 1
    else
        chmod "$mode" -- "$stage" || return 1
        chown root:root -- "$stage" || return 1
    fi
    mv -fT -- "$stage" "$target"
}

restore_enabled() {
    local unit=$1 previous=$2
    case $previous in
        enabled) systemctl enable "$unit" >/dev/null 2>&1 ;;
        enabled-runtime) systemctl enable --runtime "$unit" >/dev/null 2>&1 ;;
        disabled|static|indirect|generated|transient)
            if [[ $(systemctl show -p LoadState --value "$unit" 2>/dev/null || true) == loaded ]]; then
                systemctl disable "$unit" >/dev/null 2>&1
            fi
            ;;
        *) return 0 ;;
    esac
}

rollback() {
    local unit relative
    say '安装失败，正在恢复原运行文件和定时器状态。' >&2
    if ((UNITS_CHANGED)); then
        systemctl stop aws-user-audit.timer >/dev/null 2>&1 || ROLLBACK_FAILED=1
        # Remove links created by enable even when there was no old unit.
        systemctl disable aws-user-audit.timer >/dev/null 2>&1 || true
        for unit in aws-user-audit.service aws-user-audit.timer; do
            if [[ -f $BACKUP_DIR/$unit ]]; then
                atomic_file "$BACKUP_DIR/$unit" "$UNIT_DIR/$unit" "$BACKUP_DIR/$unit" || ROLLBACK_FAILED=1
            elif [[ -f $BACKUP_DIR/$unit.absent ]]; then
                rm -f -- "$UNIT_DIR/$unit" || ROLLBACK_FAILED=1
            fi
        done
        systemctl daemon-reload >/dev/null 2>&1 || ROLLBACK_FAILED=1
    fi
    if ((CODE_CHANGED)); then
        for relative in "${RUNTIME_FILES[@]}"; do
            if [[ -f $BACKUP_DIR/runtime/$relative ]]; then
                atomic_file "$BACKUP_DIR/runtime/$relative" "$INSTALL_DIR/$relative" \
                    "$BACKUP_DIR/runtime/$relative" || ROLLBACK_FAILED=1
            elif [[ -f $BACKUP_DIR/runtime/$relative.absent ]]; then
                rm -f -- "$INSTALL_DIR/$relative" || ROLLBACK_FAILED=1
            fi
        done
    fi
    if ((STAMP_CHANGED)); then
        if [[ -f $BACKUP_DIR/timer-stamp ]]; then
            cp -p -- "$BACKUP_DIR/timer-stamp" "$TIMER_STAMP" || ROLLBACK_FAILED=1
        else
            rm -f -- "$TIMER_STAMP" || ROLLBACK_FAILED=1
        fi
    fi
    restore_enabled aws-user-audit.timer "$OLD_TIMER_ENABLED" || ROLLBACK_FAILED=1
    if ((OLD_TIMER_ACTIVE)); then
        systemctl start aws-user-audit.timer >/dev/null 2>&1 || ROLLBACK_FAILED=1
    else
        systemctl stop aws-user-audit.timer >/dev/null 2>&1 || true
    fi
    if ((ROLLBACK_FAILED)); then
        say "自动恢复有步骤失败；请检查备份和日志：$BACKUP_DIR" >&2
    else
        say '原配置和定时器状态已恢复。' >&2
    fi
}

finish() {
    local status=$1 stage marker
    trap - EXIT
    set +e
    if ((status != 0 && TRANSACTION && !COMMITTED)); then rollback; fi
    for stage in "${STAGING_FILES[@]}"; do
        [[ -n $stage && -f $stage && $stage == *.install.* ]] && rm -f -- "$stage"
    done
    if [[ -n $WORK_DIR && -d $WORK_DIR && ! -L $WORK_DIR && ${WORK_DIR##*/} == aws-user-audit-install.* ]]; then
        marker=$(cat -- "$WORK_DIR/.installer-owned" 2>/dev/null)
        if [[ $marker == "aws-user-audit-installer:$$" ]]; then rm -rf -- "$WORK_DIR"; fi
    fi
    if ((status != 0)); then
        say '未执行日报，也未由安装器发送邮件或 Lark。修复上述问题后可重跑安装。' >&2
    fi
    exit "$status"
}
trap 'finish "$?"' EXIT

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/aws-user-audit-install.XXXXXXXX") || die '无法创建临时工作目录。'
printf 'aws-user-audit-installer:%s\n' "$$" >"$WORK_DIR/.installer-owned"
SOURCE_DIR=$SCRIPT_DIR

if ((DRY_RUN)); then
    command -v "$PYTHON" >/dev/null 2>&1 || die 'dry-run 需要现有 Python；不会自动安装。'
    [[ -f $SOURCE_DIR/deploy/install_support.py ]] || die '缺少部署 helper，请使用完整代码目录。'
    "$PYTHON" "$SOURCE_DIR/deploy/install_support.py" render \
        --install-dir "$INSTALL_DIR" \
        --config "$CONFIG_PATH" --output-dir "$WORK_DIR/units"
    read_schedule
    say '【dry-run】仅渲染临时计划；未联网、未安装软件、未修改系统服务。'
    ((UPDATE == 0)) || say '实际 --update 时将临时 clone 公共仓库 main；本次使用本地代码渲染。'
    say "代码目录：$INSTALL_DIR"
    say "Python 环境：$INSTALL_DIR/.venv"
    say "统一私有配置：$CONFIG_PATH"
    say '报告：仅归档 PDF/JSON 并通过邮件发送；不创建网页目录，不读取或修改 Nginx。'
    say "定时：每天北京时间 $DAILY_MAIL_TIME，启用停机补跑；安装当次不执行日报。"
    say "报告窗口：北京时间前一天 $REPORT_START_TIME 至报表日 $REPORT_END_TIME。"
    say '生成的 service：'
    cat -- "$WORK_DIR/units/aws-user-audit.service"
    say '生成的 timer：'
    cat -- "$WORK_DIR/units/aws-user-audit.timer"
    exit 0
fi

[[ $(uname -s) == Linux ]] || die '实际安装只支持 Linux。'
((EUID == 0)) || die '实际安装需 root；可用 --dry-run 先查看计划。'
for required in systemctl systemd-analyze flock mktemp cp mv install awk; do
    command -v "$required" >/dev/null 2>&1 || die "缺少必要命令：$required。"
done
[[ -d /run/systemd/system ]] || die '本机未运行 systemd；不能安装定时服务。'
exec 9>/run/lock/aws-user-audit-install.lock
flock -n 9 || die '另一个安装/更新进程正在运行。'

active_state=$(systemctl show -p ActiveState --value aws-user-audit.service 2>/dev/null || true)
case $active_state in active|activating|reloading|deactivating) die '日报服务正在执行，请结束后重试；安装器不会打断它。' ;; esac

# Refuse to introduce a second daily schedule. Never print private cron lines.
cron_match=0
if command -v crontab >/dev/null 2>&1; then
    crontab -l >"$WORK_DIR/root-crontab" 2>/dev/null || true
    if awk '/^[[:space:]]*#/ {next} /aws_daily_audit[.]py|aws_audit_multi[.]py/ {found=1} END {exit !found}' "$WORK_DIR/root-crontab"; then cron_match=1; fi
fi
shopt -s nullglob
for cron_file in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [[ -f $cron_file && -r $cron_file ]] || continue
    if awk '/^[[:space:]]*#/ {next} /aws_daily_audit[.]py|aws_audit_multi[.]py/ {found=1} END {exit !found}' "$cron_file"; then cron_match=1; fi
done
((cron_match == 0)) || die '发现旧 cron 引用 AWS 审计程序，请先手工移除旧定时项以免重复执行，再重跑；安装器没有修改 cron。'

if ((UPDATE)); then
    command -v git >/dev/null 2>&1 || die '--update 需要 git；请先安装 git。'
    say '正在临时获取公共仓库 main。'
    git clone --quiet --depth 1 --branch main -- https://github.com/userreksai/aws-user-audit.git "$WORK_DIR/source"
    SOURCE_DIR=$WORK_DIR/source
fi

RUNTIME_FILES=(aws_daily_audit.py aws_audit_multi.py audit_actions.py audit_event_catalog.py aws-event-translations.json audit_identity_summary.py audit_resource_summary.py audit_mail_summary.py audit_config.py audit_schedule.py audit_mail.py audit_mail_delivery.py
    audit_pdf.py audit_alerts.py lark_notify.py requirements.txt install.sh README.md
    iam-policy.json iam-policy-single-region.json aws-audit-config.example.json
    deploy/install_support.py deploy/run_scheduled.py)
for relative in "${RUNTIME_FILES[@]}"; do
    [[ -f $SOURCE_DIR/$relative && ! -L $SOURCE_DIR/$relative ]] || die "源码包缺少普通文件：$relative。"
done

# First install creates only the private, complete template. Existing private
# settings are never copied from the repository or rewritten by the installer.
[[ ! -L $INSTALL_DIR && ! -L $INSTALL_DIR/deploy ]] || die '安装目录或部署 helper 不能为符号链接。'
if [[ ! -e $CONFIG_PATH ]]; then
    [[ ! -L $CONFIG_PATH ]] || die '统一配置不能为符号链接。'
    install -d -m 0755 -- "$INSTALL_DIR"
    [[ -d $(dirname -- "$CONFIG_PATH") ]] || die '统一配置父目录不存在；请先创建并放入私有配置。'
    install -m 0600 -- "$SOURCE_DIR/aws-audit-config.example.json" "$CONFIG_PATH"
    die "已创建私有配置模板：$CONFIG_PATH。请填写启用账号及邮件配置后重跑；未启用定时器。"
fi
[[ -f $CONFIG_PATH && ! -L $CONFIG_PATH ]] || die '统一配置必须为普通私有文件。'

apt_updated=0
apt_python() {
    command -v apt-get >/dev/null 2>&1 || die 'Python/venv 不可用；请先安装 Python >=3.10 和对应 venv 包。'
    if ((apt_updated == 0)); then apt-get update; apt_updated=1; fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    [[ $PYTHON == python3 || $PYTHON == /usr/bin/python3 ]] || die '指定的 Python 不存在。'
    apt_python python3 python3-venv
fi
"$PYTHON" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' || die '需要 Python >=3.10。'
if ! "$PYTHON" -c 'import venv, ensurepip' >/dev/null 2>&1; then
    apt_python python3-venv
    "$PYTHON" -c 'import venv, ensurepip' >/dev/null 2>&1 || die '指定 Python 缺少可用 venv/ensurepip；请安装与它匹配的 venv 包。'
fi

"$PYTHON" "$SOURCE_DIR/deploy/install_support.py" render \
    --install-dir "$INSTALL_DIR" \
    --config "$CONFIG_PATH" --output-dir "$WORK_DIR/units"
read_schedule

# Pause this timer before touching its code or virtual environment. Stop does
# not interrupt a running oneshot, so check the service again after stopping.
stamp=$(date -u +%Y%m%dT%H%M%SZ)-$$
BACKUP_DIR=$INSTALL_DIR/.installer-backups/$stamp
[[ ! -L $INSTALL_DIR/.installer-backups ]] || die '备份目录不能为符号链接。'
install -d -m 0700 -- "$INSTALL_DIR/.installer-backups" "$BACKUP_DIR"
for unit in aws-user-audit.service aws-user-audit.timer; do
    [[ ! -L $UNIT_DIR/$unit ]] || die '现有 systemd 单元是符号链接，请先人工检查。'
    if [[ -f $UNIT_DIR/$unit ]]; then
        cp -p -- "$UNIT_DIR/$unit" "$BACKUP_DIR/$unit"
    else
        : >"$BACKUP_DIR/$unit.absent"
    fi
done
if [[ -f $TIMER_STAMP ]]; then cp -p -- "$TIMER_STAMP" "$BACKUP_DIR/timer-stamp"; fi
if systemctl is-active --quiet aws-user-audit.timer; then OLD_TIMER_ACTIVE=1; fi
OLD_TIMER_ENABLED=$(systemctl is-enabled aws-user-audit.timer 2>/dev/null || true)
TRANSACTION=1
if ((OLD_TIMER_ACTIVE)); then systemctl stop aws-user-audit.timer; fi
active_state=$(systemctl show -p ActiveState --value aws-user-audit.service 2>/dev/null || true)
case $active_state in active|activating|reloading|deactivating) die '日报服务恰好开始执行，本次停止安装并恢复原定时状态。' ;; esac

install -d -m 0755 -- "$INSTALL_DIR" "$INSTALL_DIR/deploy"
install -d -m 0700 -- "$BACKUP_DIR/runtime" "$BACKUP_DIR/runtime/deploy"
for relative in "${RUNTIME_FILES[@]}"; do
    destination=$INSTALL_DIR/$relative
    [[ ! -L $destination ]] || die '目标源码文件不能为符号链接。'
    [[ ! $CONFIG_PATH -ef $destination ]] || die '统一私有配置不能与运行文件共用路径。'
    if [[ -e $destination ]]; then
        [[ -f $destination ]] || die '目标源码路径不是普通文件。'
        cp -p -- "$destination" "$BACKUP_DIR/runtime/$relative"
    else
        : >"$BACKUP_DIR/runtime/$relative.absent"
    fi
done
CODE_CHANGED=1
for relative in "${RUNTIME_FILES[@]}"; do
    destination=$INSTALL_DIR/$relative
    [[ ! -L $destination ]] || die '目标源码文件不能为符号链接。'
    if [[ -e $destination && $SOURCE_DIR/$relative -ef $destination ]]; then continue; fi
    mode=0644
    [[ $relative != install.sh ]] || mode=0755
    atomic_file "$SOURCE_DIR/$relative" "$destination" '' "$mode"
done

chmod 0600 -- "$CONFIG_PATH"
[[ ! -L $INSTALL_DIR/.venv ]] || die '.venv 不能为符号链接。'
if [[ ! -x $INSTALL_DIR/.venv/bin/python ]]; then
    "$PYTHON" -m venv "$INSTALL_DIR/.venv"
fi
VENV_PYTHON=$INSTALL_DIR/.venv/bin/python
"$VENV_PYTHON" -m pip install -r "$INSTALL_DIR/requirements.txt"
"$VENV_PYTHON" "$INSTALL_DIR/deploy/install_support.py" preflight \
    --install-dir "$INSTALL_DIR" --config "$CONFIG_PATH" \
    --daily-mail-time "$DAILY_MAIL_TIME" --report-start-time "$REPORT_START_TIME" --report-end-time "$REPORT_END_TIME"

systemd-analyze verify "$WORK_DIR/units/aws-user-audit.service" "$WORK_DIR/units/aws-user-audit.timer" \
    >"$WORK_DIR/systemd-verify.log" 2>&1 || die 'systemd 单元校验失败；系统配置尚未变更。'
calendar=$(awk '/^OnCalendar=/ {sub(/^OnCalendar=/, ""); print; exit}' "$WORK_DIR/units/aws-user-audit.timer")
[[ -n $calendar ]] || die '生成的定时器缺少 OnCalendar。'
systemd-analyze calendar "$calendar" >"$WORK_DIR/calendar.log" 2>&1 \
    || die '本机 systemd 不支持目标北京时间表达式；系统配置尚未变更。'

UNITS_CHANGED=1
atomic_file "$WORK_DIR/units/aws-user-audit.service" "$UNIT_DIR/aws-user-audit.service"
atomic_file "$WORK_DIR/units/aws-user-audit.timer" "$UNIT_DIR/aws-user-audit.timer"
systemctl daemon-reload
install -d -m 0755 -- /var/lib/systemd/timers
[[ ! -L $TIMER_STAMP ]] || die 'systemd timer 时间戳不能为符号链接。'
STAMP_CHANGED=1
touch -- "$TIMER_STAMP"
systemctl enable --now aws-user-audit.timer
systemctl is-active --quiet aws-user-audit.timer || die '定时器没有进入 active 状态。'

systemctl list-timers --all --no-pager aws-user-audit.timer >"$WORK_DIR/timer-status"
COMMITTED=1
say '安装完成；本次没有立即执行日报或发送邮件/Lark。'
say "代码：$INSTALL_DIR"
say "Python：$VENV_PYTHON"
say "统一私有配置：$CONFIG_PATH"
say '报告：仅 PDF/JSON 归档和邮件；原 Nginx 配置与旧网页未作任何修改。'
say "单元备份：$BACKUP_DIR"
say "报告窗口：北京时间前一天 $REPORT_START_TIME 至报表日 $REPORT_END_TIME。"
say "下一次执行（北京时间每天 $DAILY_MAIL_TIME 开始采集，完成后发送邮件）："
cat -- "$WORK_DIR/timer-status"
say '诊断：systemctl status aws-user-audit.timer --no-pager'
say '日志：journalctl -u aws-user-audit.service -n 100 --no-pager'
