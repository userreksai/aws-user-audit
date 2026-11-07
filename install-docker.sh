#!/usr/bin/env bash
# Independent Docker deployment; the existing host installation is not managed.
set -Eeuo pipefail
umask 077

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ORIGINAL_DIR=$PWD
DATA_DIR=/usr/local/aws-user-audit
CONFIG_PATH=
PROFILE_DIR=
DRY_RUN=0
NO_START=0
PROJECT=aws-user-audit-docker
IMAGE=${AUDIT_IMAGE:-aws-user-audit:local}
CONTAINER_CONFIG=/usr/local/aws-user-audit/aws-audit-config.json
WORK_LOG=
PLAN_FILE=
ENV_STAGE=

usage() {
    cat <<'HELP'
Usage: bash install-docker.sh [options]
  --data-dir DIR     Private data directory (default: /usr/local/aws-user-audit)
  --config FILE      Existing JSON/JSONC config (default: DATA_DIR/aws-audit-config.json)
  --profile-dir DIR  Explicit read-only AWS profiles directory mounted at /root/.aws
  --no-start         Build and check configuration without starting/replacing a service
  --dry-run          Print the plan without Docker, network requests, or filesystem writes
  --help            Show this help

Requires an already installed Docker Engine and Docker Compose V2 or newer.
If configuration is absent, copies the complete template with mode 0600 and stops.
After filling the private config, rerun this command to build, check, and start.
Updates only Compose project aws-user-audit-docker, service audit. Existing host
services and their scheduling are unchanged; avoid enabling duplicate schedules.
Build and configuration checks never collect AWS events or send notifications.
The installer does not directly invoke a report. With no Docker schedule cursor,
startup waits until the next due time. An existing cursor follows catch-up rules
and may immediately run the most recent completed report window after restart.
Use --no-start to build/check without starting or replacing the service.
HELP
}

say() { printf '%s\n' "$*"; }
die() { printf 'Docker 安装未完成：%s\n' "$*" >&2; exit 1; }
need_value() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "参数 $1 缺少值。"; }

# --mount uses commas as delimiters; control characters and colons are rejected
# before invoking Docker. Spaces and Unicode remain single, quoted arguments.
validate_path() {
    local value=$1
    [[ $value == /* && $value != //* && $value != *:* && $value != *,* && $value != *\\* \
        && $value != *$'\n'* && $value != *$'\r'* && $value != *$'\t'* ]] \
        || die '路径须为无控制字符、冒号或逗号的 Linux 绝对路径。'
    [[ ! $value =~ [[:cntrl:]] ]] || die '路径包含控制字符。'
    case $value/ in */../*|*/./*) die '路径不能包含 . 或 .. 路径段。' ;; esac
}

dedicated_directory() {
    case $1 in
        ''|/|/app|/bin|/sbin|/usr|/usr/local|/etc|/var|/tmp|/home|/root|/opt|/srv|/run|/proc|/dev|/sys|/lib|/lib64)
            die '请使用独立的应用数据子目录。' ;;
    esac
}

safe_writable_directory() {
    local directory=$1 protected
    dedicated_directory "$directory"
    for protected in /app /etc /root/.aws /bin /sbin /lib /lib64 /proc /sys /dev /boot /run \
        /usr/bin /usr/sbin /usr/lib /usr/lib64 /usr/share /usr/local/bin /usr/local/sbin /usr/local/lib /var/run; do
        [[ $directory != "$protected" && $directory != "$protected/"* && $protected != "$directory/"* ]] \
            || die '报告/状态目录不能映射到系统敏感目录或应用代码目录。'
    done
    if [[ -n $PROFILE_DIR ]]; then
        [[ $directory != "$PROFILE_DIR" && $directory != "$PROFILE_DIR/"* && $PROFILE_DIR != "$directory/"* ]] \
            || die '报告/状态目录不能与 AWS profile 凭据目录重叠。'
    fi
}

normalize_path() {
    local name=$1 value=${!1}
    [[ $value == /* ]] || value=$ORIGINAL_DIR/$value
    validate_path "$value"
    value=$(realpath -m -- "$value") || die '无法解析部署路径。'
    validate_path "$value"
    printf -v "$name" '%s' "${value%/}"
}

# Nginx must be able to traverse a newly created public directory's parents.
# Create only missing directories with 0755; never loosen an existing ancestor.
create_public_parents() {
    local parent=$1 index
    local -a missing=()
    while [[ ! -d $parent ]]; do
        [[ ! -e $parent && ! -L $parent ]] || die 'HTML 父路径不是普通目录。'
        missing+=("$parent")
        parent=$(dirname -- "$parent")
    done
    for ((index=${#missing[@]}-1; index>=0; index--)); do
        (umask 022; mkdir -- "${missing[$index]}") || die '无法创建 HTML 可遍历父目录。'
    done
}

cleanup() {
    local status=$?
    trap - EXIT
    [[ -z $WORK_LOG ]] || rm -f -- "$WORK_LOG"
    [[ -z $PLAN_FILE ]] || rm -f -- "$PLAN_FILE"
    [[ -z $ENV_STAGE ]] || rm -f -- "$ENV_STAGE"
    exit "$status"
}

# Docker/helper output can include private configuration. Never echo raw output
# or commands, even on failure; temporary files inherit umask 077 and are removed.
run_logged() {
    local message=$1
    shift
    "$@" >"$WORK_LOG" 2>&1 || die "$message"
}

while (($#)); do
    case $1 in
        --data-dir) need_value "$@"; DATA_DIR=$2; shift 2 ;;
        --config) need_value "$@"; CONFIG_PATH=$2; shift 2 ;;
        --profile-dir) need_value "$@"; PROFILE_DIR=$2; shift 2 ;;
        --no-start) NO_START=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die '未知参数；请使用 --help。' ;;
    esac
done

[[ $IMAGE =~ ^[A-Za-z0-9][A-Za-z0-9._:/@-]*$ ]] || die 'Docker 镜像名称无效。'

[[ -n $CONFIG_PATH ]] || CONFIG_PATH=$DATA_DIR/aws-audit-config.json
# Dry-run also accepts Linux paths on a non-Linux review workstation. It needs
# no temporary files, Docker executable, host Python, or package manager.
if ((DRY_RUN)); then
    for value in "$DATA_DIR" "$CONFIG_PATH"; do
        [[ $value == /* ]] || value=$ORIGINAL_DIR/$value
        validate_path "$value"
    done
    dedicated_directory "$DATA_DIR"
    if [[ -n $PROFILE_DIR ]]; then
        value=$PROFILE_DIR
        [[ $value == /* ]] || value=$ORIGINAL_DIR/$value
        validate_path "$value"
    fi
    say '【dry-run】只显示计划：未调用 Docker、未联网、未写入文件。'
    say "源码构建目录：$SOURCE_DIR"
    say "数据目录：$DATA_DIR"
    say "现有配置只读挂载到：$CONTAINER_CONFIG"
    say '缺少配置时：完整复制模板为 0600，停止并等待填写，再次运行。'
    say "Compose project：$PROJECT；service：audit；image：$IMAGE"
    say '已有配置时：build audit → 隔离网络校验路径 → check → up -d --no-deps --force-recreate audit。'
    say 'AUDIT_CONFIG_PATH 指向现有配置；报告、私有状态和独立 HTML 发布目录按原配置解析宿主路径。'
    say '容器分别挂载报告、状态和 HTML 目录；HTML 目录为 0755，供宿主 Nginx 读取。'
    [[ -z $PROFILE_DIR ]] || say '追加 compose.aws-profile.yaml，AWS profile 只读挂载到 /root/.aws。'
    ((NO_START == 0)) || say '--no-start：完成 build 和 check 后停止，不启动或替换现有容器。'
    say '安装器不直接执行日报；首次无 Docker 调度游标时等待下次；已有游标重启会按补跑规则执行最近结束窗口。'
    exit 0
fi

[[ $(uname -s) == Linux ]] || die '实际安装只支持 Linux；其他系统可用 --dry-run。'
validate_path "$SOURCE_DIR"
for required in realpath mkdir cat dirname chmod chown stat mktemp mv rm; do
    command -v "$required" >/dev/null 2>&1 || die "缺少必要命令：$required。"
done
normalize_path DATA_DIR
[[ ! -L $CONFIG_PATH ]] || die '配置不能是符号链接，请显式指定真实的私有配置文件。'
normalize_path CONFIG_PATH
dedicated_directory "$DATA_DIR"
for marker in rds_multi.py rds_config.py; do
    [[ ! -e $DATA_DIR/$marker && ! -L $DATA_DIR/$marker ]] \
        || die '数据目录包含 RDS 项目标识，请使用独立的 AWS 账号审计目录。'
done

# Initial setup is entirely local shell work. In particular it cannot pull an
# image, build a container, inspect credentials, or start any scheduled task.
if [[ ! -e $CONFIG_PATH ]]; then
    [[ -f $SOURCE_DIR/aws-audit-config.example.json ]] || die '缺少完整配置模板。'
    create_public_parents "$(dirname -- "$CONFIG_PATH")"
    (set -o noclobber; cat -- "$SOURCE_DIR/aws-audit-config.example.json" >"$CONFIG_PATH") \
        2>/dev/null || die '无法安全初始化配置，请检查目录权限并重试。'
    chmod 0600 -- "$CONFIG_PATH" || die '无法设置新配置的私有权限。'
    say "完整配置模板已保存为 0600：$CONFIG_PATH"
    say '请填写真实 AWS 账号和邮件配置，再重新运行本安装命令；本次未调用 Docker 或启动任务。'
    exit 2
fi
[[ -f $CONFIG_PATH && -r $CONFIG_PATH ]] || die '现有配置不是可读的普通文件。'
config_owner=$(stat -c '%u:%g' -- "$CONFIG_PATH") || die '无法读取配置文件所有者。'
[[ $config_owner =~ ^[0-9]+:[0-9]+$ ]] || die '配置文件所有者 UID/GID 无效。'
export AUDIT_UID=${config_owner%:*}
export AUDIT_GID=${config_owner#*:}
if [[ -n $PROFILE_DIR ]]; then
    normalize_path PROFILE_DIR
    [[ -d $PROFILE_DIR && -r $PROFILE_DIR ]] || die '--profile-dir 必须是现有可读目录。'
fi
for asset in Dockerfile compose.yaml deploy/docker_config.py; do
    [[ -f $SOURCE_DIR/$asset ]] || die '源码目录缺少 Docker 部署文件，请使用完整源码。'
done
command -v docker >/dev/null 2>&1 || die '请先安装 Docker Engine 和 Docker Compose V2+；安装器不会自动安装。'
WORK_LOG=$(mktemp "${TMPDIR:-/tmp}/aws-user-audit-docker-log.XXXXXXXX") || die '无法创建私有临时文件。'
trap cleanup EXIT
PLAN_FILE=$(mktemp "${TMPDIR:-/tmp}/aws-user-audit-docker-plan.XXXXXXXX") || die '无法创建私有临时文件。'
run_logged '无法访问 Docker Engine，请确认服务正在运行且当前用户有权限。' docker info --format '{{.ServerVersion}}'
docker compose version --short >"$WORK_LOG" 2>&1 || die '需要 Docker Compose V2+ 插件（docker compose）。'
compose_version=$(cat -- "$WORK_LOG")
if [[ $compose_version =~ ^v?([0-9]{1,3})\. ]]; then
    compose_major=${BASH_REMATCH[1]}
    ((10#$compose_major >= 2)) || die '需要 Docker Compose V2+ 插件（docker compose）。'
else
    die '需要 Docker Compose V2+ 插件（docker compose）。'
fi

export AUDIT_CONFIG_PATH=$CONFIG_PATH
export AUDIT_REPORTS_DIR=$DATA_DIR/reports
export AUDIT_STATE_DIR=$DATA_DIR/.state
export AUDIT_PUBLISH_DIR=$DATA_DIR/index
export AUDIT_CONTAINER_REPORTS_DIR=/usr/local/aws-user-audit/reports
export AUDIT_CONTAINER_STATE_DIR=/usr/local/aws-user-audit/.state
export AUDIT_CONTAINER_PUBLISH_DIR=/usr/local/aws-user-audit/index
COMPOSE=(docker compose --project-name "$PROJECT" --project-directory "$SOURCE_DIR" -f "$SOURCE_DIR/compose.yaml")
if [[ -n $PROFILE_DIR ]]; then
    [[ -f $SOURCE_DIR/compose.aws-profile.yaml ]] || die '缺少 AWS profile 的 Compose overlay。'
    export AUDIT_AWS_DIR=$PROFILE_DIR
    COMPOSE+=(-f "$SOURCE_DIR/compose.aws-profile.yaml")
fi
say '正在构建独立 Docker 镜像；运行中的容器将在检查通过后才更新。'
run_logged '镜像构建失败，未停止或更新运行中的容器。请检查 Docker 构建环境后重试。' "${COMPOSE[@]}" build audit

if ! docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --user "$AUDIT_UID:$AUDIT_GID" \
    --mount "type=bind,src=$CONFIG_PATH,dst=$CONTAINER_CONFIG,readonly" \
    --entrypoint /app/.venv/bin/python "$IMAGE" /app/deploy/docker_config.py \
    --config "$CONTAINER_CONFIG" --host-config-path "$CONFIG_PATH" --format env \
    >"$PLAN_FILE" 2>"$WORK_LOG"; then
    die '私有配置或容器路径预检失败；请检查 JSON/JSONC、路径与目录冲突。未启动或更新容器。'
fi

AUDIT_REPORTS_DIR=
AUDIT_STATE_DIR=
AUDIT_PUBLISH_DIR=
AUDIT_CONTAINER_REPORTS_DIR=
AUDIT_CONTAINER_STATE_DIR=
AUDIT_CONTAINER_PUBLISH_DIR=
AUDIT_REQUIRES_PROFILE=
AUDIT_FONT_SOURCE=
AUDIT_CONTAINER_FONT_PATH=
declare -A PLAN_KEYS=()
while IFS=$'\t' read -r key value extra || [[ -n ${key:-} ]]; do
    case $key in
        AUDIT_REPORTS_DIR|AUDIT_STATE_DIR|AUDIT_PUBLISH_DIR|AUDIT_CONTAINER_REPORTS_DIR|AUDIT_CONTAINER_STATE_DIR|AUDIT_CONTAINER_PUBLISH_DIR|AUDIT_REQUIRES_PROFILE|AUDIT_FONT_SOURCE|AUDIT_CONTAINER_FONT_PATH)
            [[ -n $value && -z ${extra:-} && -z ${PLAN_KEYS[$key]:-} ]] || die '容器路径计划格式无效。'
            printf -v "$key" '%s' "$value"; PLAN_KEYS[$key]=1 ;;
        *) die '容器路径计划包含未知字段。' ;;
    esac
done <"$PLAN_FILE"
[[ ( ${#PLAN_KEYS[@]} == 7 || ${#PLAN_KEYS[@]} == 9 ) && $AUDIT_REQUIRES_PROFILE =~ ^[01]$ ]] \
    || die '容器路径计划不完整。'
for setting in AUDIT_REPORTS_DIR AUDIT_STATE_DIR AUDIT_PUBLISH_DIR AUDIT_CONTAINER_REPORTS_DIR AUDIT_CONTAINER_STATE_DIR AUDIT_CONTAINER_PUBLISH_DIR; do
    validate_path "${!setting}"
    dedicated_directory "${!setting}"
done
normalize_path AUDIT_REPORTS_DIR
normalize_path AUDIT_STATE_DIR
normalize_path AUDIT_PUBLISH_DIR
for setting in AUDIT_REPORTS_DIR AUDIT_STATE_DIR AUDIT_PUBLISH_DIR; do
    directory=${!setting}
    safe_writable_directory "$directory"
    [[ $CONFIG_PATH != "$directory" && $CONFIG_PATH != "$directory/"* ]] \
        || die '报告、状态或 HTML 目录不能包含或覆盖私有配置。'
done
[[ $AUDIT_REPORTS_DIR != "$AUDIT_STATE_DIR" \
    && $AUDIT_REPORTS_DIR != "$AUDIT_STATE_DIR/"* && $AUDIT_STATE_DIR != "$AUDIT_REPORTS_DIR/"* ]] \
    || die '报告目录与状态目录必须是独立、不嵌套的目录。'
for private_directory in "$AUDIT_REPORTS_DIR" "$AUDIT_STATE_DIR"; do
    [[ $AUDIT_PUBLISH_DIR != "$private_directory" \
        && $AUDIT_PUBLISH_DIR != "$private_directory/"* && $private_directory != "$AUDIT_PUBLISH_DIR/"* ]] \
        || die 'HTML 目录必须与私有报告和状态目录分开且不能互相嵌套。'
done
for private_directory in "$AUDIT_CONTAINER_REPORTS_DIR" "$AUDIT_CONTAINER_STATE_DIR"; do
    [[ $AUDIT_CONTAINER_PUBLISH_DIR != "$private_directory" \
        && $AUDIT_CONTAINER_PUBLISH_DIR != "$private_directory/"* && $private_directory != "$AUDIT_CONTAINER_PUBLISH_DIR/"* ]] \
        || die '容器 HTML 目录必须与私有报告和状态目录分开且不能互相嵌套。'
done
if [[ $AUDIT_REQUIRES_PROFILE == 1 && -z $PROFILE_DIR ]]; then
    die '启用的 AWS 账号配置了 AWS_PROFILE。请加 --profile-dir /root/.aws（或真实凭据目录），以只读挂载到容器 /root/.aws 后重跑。'
fi
if [[ -n $AUDIT_FONT_SOURCE || -n $AUDIT_CONTAINER_FONT_PATH ]]; then
    [[ -n $AUDIT_FONT_SOURCE && -n $AUDIT_CONTAINER_FONT_PATH ]] || die '字体路径计划不完整。'
    validate_path "$AUDIT_FONT_SOURCE"
    validate_path "$AUDIT_CONTAINER_FONT_PATH"
    [[ -f $AUDIT_FONT_SOURCE && -r $AUDIT_FONT_SOURCE && ! -L $AUDIT_FONT_SOURCE ]] \
        || die 'PDF_FONT_PATH 的宿主字体必须是可读、非符号链接的普通文件。'
    normalize_path AUDIT_FONT_SOURCE
    for directory in "$AUDIT_REPORTS_DIR" "$AUDIT_STATE_DIR" "$AUDIT_PUBLISH_DIR"; do
        [[ $AUDIT_FONT_SOURCE != "$directory" && $AUDIT_FONT_SOURCE != "$directory/"* ]] \
            || die 'PDF_FONT_PATH 不能位于可写的报告或状态目录内。'
    done
    [[ -f $SOURCE_DIR/compose.font.yaml ]] || die '缺少字体的 Compose overlay。'
    export AUDIT_FONT_SOURCE AUDIT_CONTAINER_FONT_PATH
    COMPOSE+=(-f "$SOURCE_DIR/compose.font.yaml")
fi
export AUDIT_REPORTS_DIR AUDIT_STATE_DIR AUDIT_PUBLISH_DIR AUDIT_CONTAINER_REPORTS_DIR AUDIT_CONTAINER_STATE_DIR AUDIT_CONTAINER_PUBLISH_DIR
# Prepare the public parent chain before private outputs create any shared
# missing ancestors under the installer's private 077 umask.
create_public_parents "$(dirname -- "$AUDIT_PUBLISH_DIR")"
for directory in "$AUDIT_REPORTS_DIR" "$AUDIT_STATE_DIR" "$AUDIT_PUBLISH_DIR"; do
    if [[ -e $directory ]]; then
        [[ -d $directory && $(stat -c '%u' -- "$directory") == "$AUDIT_UID" ]] \
            || die '现有报告、状态及 HTML 目录须属于配置文件所有者，请核对目录所有权后重跑；安装器不会改写旧目录所有权。'
    fi
done
for directory in "$AUDIT_REPORTS_DIR" "$AUDIT_STATE_DIR" "$AUDIT_PUBLISH_DIR"; do
    if [[ ! -d $directory ]]; then
        mkdir -p -- "$directory" || die '无法创建报告或状态目录。'
        if [[ $(stat -c '%u:%g' -- "$directory") != "$AUDIT_UID:$AUDIT_GID" ]]; then
            chown "$AUDIT_UID:$AUDIT_GID" -- "$directory" || die '无法设置新建报告/状态目录所有者。'
        fi
    fi
done
# Only these two directory entries are restricted. Existing files, descendants,
# config bytes/ownership, and the parent data directory are never recursively changed.
chmod 0700 -- "$AUDIT_REPORTS_DIR" "$AUDIT_STATE_DIR" || die '无法设置报告/状态目录权限。'
chmod 0755 -- "$AUDIT_PUBLISH_DIR" || die '无法设置 HTML 目录读取权限。'
run_logged 'Compose 配置检查失败，未启动或更新容器。' "${COMPOSE[@]}" config --quiet
run_logged '容器配置检查失败；请检查私有配置、挂载权限及 AWS profile 文件。未启动或更新容器。' \
    "${COMPOSE[@]}" run --rm --no-deps -T audit check-config --config "$CONTAINER_CONFIG"

# A deployment-only env file makes later logs/stop/manual-once commands use the
# same mount paths and overlays. It never contains the private JSON or credentials.
ENV_FILE=$DATA_DIR/docker.env
[[ $ENV_FILE != "$CONFIG_PATH" && ! -L $ENV_FILE && ( ! -e $ENV_FILE || -f $ENV_FILE ) ]] \
    || die 'docker.env 必须是独立的普通部署环境文件，不能覆盖配置或符号链接。'
mkdir -p -- "$DATA_DIR" || die '无法创建部署环境目录。'
ENV_STAGE=$(mktemp "$DATA_DIR/.docker.env.XXXXXXXX") || die '无法创建部署环境文件。'
COMPOSE_FILE=$SOURCE_DIR/compose.yaml
[[ -z $PROFILE_DIR ]] || COMPOSE_FILE+=:$SOURCE_DIR/compose.aws-profile.yaml
[[ -z $AUDIT_FONT_SOURCE ]] || COMPOSE_FILE+=:$SOURCE_DIR/compose.font.yaml
COMPOSE_PROJECT_NAME=$PROJECT
AUDIT_IMAGE=$IMAGE
write_env() {
    local name=$1 value=${!1}
    # Compose treats single-quoted .env values literally and accepts escaped
    # quotes. Path validation already rejects literal backslashes.
    value=${value//\'/\\\'}
    printf "%s='%s'\n" "$name" "$value" >>"$ENV_STAGE"
}
for setting in COMPOSE_PROJECT_NAME COMPOSE_FILE AUDIT_IMAGE AUDIT_UID AUDIT_GID AUDIT_CONFIG_PATH AUDIT_REPORTS_DIR AUDIT_STATE_DIR AUDIT_PUBLISH_DIR \
    AUDIT_CONTAINER_REPORTS_DIR AUDIT_CONTAINER_STATE_DIR AUDIT_CONTAINER_PUBLISH_DIR; do
    write_env "$setting"
done
[[ -z $PROFILE_DIR ]] || write_env AUDIT_AWS_DIR
if [[ -n $AUDIT_FONT_SOURCE ]]; then
    write_env AUDIT_FONT_SOURCE
    write_env AUDIT_CONTAINER_FONT_PATH
fi
chmod 0600 -- "$ENV_STAGE" || die '无法保护部署环境文件。'
mv -f -- "$ENV_STAGE" "$ENV_FILE" || die '无法保存部署环境文件。'
ENV_STAGE=
say "部署环境已保存为 0600：$ENV_FILE（不含凭据）。"
if ((NO_START)); then
    say '镜像构建和配置检查完成；--no-start 未启动或替换现有容器。'
    exit 0
fi
# Recreate even if the build is cached: editors can atomically replace the JSON
# file, while an existing bind mount still refers to its previous inode.
run_logged 'Docker 服务启动失败；请检查该 Compose 项目状态后重试。' \
    "${COMPOSE[@]}" up -d --no-deps --force-recreate audit
say 'Docker 服务已启动：aws-user-audit-docker / audit。配置字节与原有投递账本保留。'
say '安装器不直接执行日报；首次无 Docker 调度游标时等待下次；已有游标重启会按补跑规则执行最近结束窗口。'
