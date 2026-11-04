"""Reviewed AWS API meanings plus optional local SDK documentation.

The caller keeps ordinary readOnly=true filtering and applies reviewed query
corrections for mislabeled failures. IAM permission actions are not API events,
and resource use is never reclassified as a resource mutation.
No network requests, SDK clients, sessions or credential providers are used.
"""
from __future__ import annotations

from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
import re


# Event source, local SDK service name, Chinese display name, API documentation.
SERVICES = {
    "ec2": ("ec2", "Amazon EC2", "AWSEC2/latest/APIReference"),
    "iam": ("iam", "AWS IAM", "IAM/latest/APIReference"),
    "sts": ("sts", "AWS STS", "STS/latest/APIReference"),
    "rds": ("rds", "Amazon RDS", "AmazonRDS/latest/APIReference"),
    "kms": ("kms", "AWS KMS", "kms/latest/APIReference"),
    "secretsmanager": ("secretsmanager", "AWS Secrets Manager", "secretsmanager/latest/apireference"),
    "cloudformation": ("cloudformation", "AWS CloudFormation", "AWSCloudFormation/latest/APIReference"),
    "ssm": ("ssm", "AWS Systems Manager", "systems-manager/latest/APIReference"),
    "organizations": ("organizations", "AWS Organizations", "organizations/latest/APIReference"),
    "autoscaling": ("autoscaling", "Amazon EC2 Auto Scaling", "autoscaling/ec2/APIReference"),
    "route53": ("route53", "Amazon Route 53", "Route53/latest/APIReference"),
    "ecr": ("ecr", "Amazon ECR", "AmazonECR/latest/APIReference"),
    "s3": ("s3", "Amazon S3", "AmazonS3/latest/API"),
    "lambda": ("lambda", "AWS Lambda", "lambda/latest/api"),
    "ecs": ("ecs", "Amazon ECS", "AmazonECS/latest/APIReference"),
    "eks": ("eks", "Amazon EKS", "eks/latest/APIReference"),
    "cloudtrail": ("cloudtrail", "AWS CloudTrail", "awscloudtrail/latest/APIReference"),
    "logs": ("logs", "Amazon CloudWatch Logs", "AmazonCloudWatchLogs/latest/APIReference"),
    "monitoring": ("cloudwatch", "Amazon CloudWatch", "AmazonCloudWatch/latest/APIReference"),
    "dynamodb": ("dynamodb", "Amazon DynamoDB", "amazondynamodb/latest/APIReference"),
    "elasticache": ("elasticache", "Amazon ElastiCache", "AmazonElastiCache/latest/APIReference"),
}


def _service(event):
    source = event.get("eventSource")
    if not isinstance(source, str):
        return None
    found = re.fullmatch(r"([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?", source.lower())
    return found.group(1) if found and found.group(1) in SERVICES else None


def _reference(service, name):
    return "https://docs.aws.amazon.com/" + SERVICES[service][2] + "/API_" + name + ".html"


ACTIONS = {}


def _register(service, category, rows, *, kind="resource_change"):
    for name, description in rows:
        ACTIONS[(service, name)] = {"category": category, "description": description,
                                    "kind": kind, "reference": _reference(service, name)}


_register("ec2", "新增", [
    ("RequestSpotInstances", "创建 Spot 实例请求（不等于实例已经创建）"),
    ("RequestSpotFleet", "创建 Spot Fleet 请求（不等于实例已经创建）"),
    ("RunScheduledInstances", "启动 Scheduled Instances 实例"),
    ("ProvisionByoipCidr", "预置 BYOIP 地址段并创建地址池"),
    ("ProvisionIpamPoolCidr", "向 IPAM 地址池预置 CIDR"),
    ("ProvisionPublicIpv4PoolCidr", "向公有 IPv4 地址池预置 CIDR"),
])
_register("ec2", "删除", [
    ("DeprovisionByoipCidr", "释放 BYOIP 地址段并删除对应地址池"),
    ("DeprovisionIpamPoolCidr", "从 IPAM 地址池释放 CIDR"),
    ("DeprovisionPublicIpv4PoolCidr", "从公有 IPv4 地址池释放 CIDR"),
])
_register("ec2", "修改", [
    ("MonitorInstances", "启用 EC2 实例详细监控"),
    ("UnmonitorInstances", "关闭 EC2 实例详细监控"),
    ("LockSnapshot", "锁定 EBS 快照或调整快照锁定设置"),
    ("UnlockSnapshot", "解除 EBS 快照锁定"),
    ("AdvertiseByoipCidr", "发布 BYOIP 地址段路由"),
    ("WithdrawByoipCidr", "撤回 BYOIP 地址段路由发布"),
])
_register("rds", "修改", [
    ("FailoverDBCluster", "请求 RDS / Aurora 集群故障切换"),
    ("FailoverGlobalCluster", "请求全局数据库故障切换"),
    ("SwitchoverGlobalCluster", "请求全局数据库主备切换"),
    ("SwitchoverReadReplica", "请求 Oracle 主库与只读副本角色切换"),
    ("SwitchoverBlueGreenDeployment", "请求 RDS 蓝绿部署切换"),
    ("BacktrackDBCluster", "将 Aurora MySQL 集群回溯到指定时间"),
])
_register("iam", "修改", [
    ("DeactivateMFADevice", "停用并解除用户 MFA 设备关联"),
    ("ResyncMFADevice", "重新同步 MFA 设备"),
])
_register("iam", None, [
    ("ListOrganizationsFeatures", "查看组织的集中 root 访问功能"),
], kind="ordinary_read")
_register("sts", "登录信息", [
    ("GetSessionToken", "获取临时会话凭据（不等于控制台登录）"),
    ("GetFederationToken", "获取联合身份临时凭据（不等于控制台登录）"),
    ("AssumeRoot", "申请成员账号的短期特权身份会话（不等于控制台登录）"),
], kind="credential_session")
_register("kms", "新增", [("ReplicateKey", "在目标区域创建多区域 KMS 密钥副本")])
_register("kms", "删除", [
    ("RetireGrant", "退役并删除 KMS 授权"),
    ("ScheduleKeyDeletion", "计划删除 KMS 密钥（尚未立即删除）"),
])
_register("kms", "修改", [
    ("ConnectCustomKeyStore", "请求连接或重新连接 KMS 自定义密钥存储"),
    ("DisconnectCustomKeyStore", "断开 KMS 自定义密钥存储连接"),
])
_register("kms", "其他操作", [
    ("Encrypt", "使用 KMS 密钥加密数据（不修改密钥配置）"),
    ("Decrypt", "使用 KMS 密钥解密数据（不修改密钥配置）"),
    ("ReEncrypt", "使用 KMS 密钥重新加密数据（不修改密钥配置）"),
    ("GenerateDataKey", "生成数据密钥供外部加密使用（不创建 KMS 主密钥）"),
    ("GenerateDataKeyWithoutPlaintext", "生成加密的数据密钥（不返回明文密钥）"),
    ("GenerateDataKeyPair", "生成数据密钥对供外部使用（不创建 KMS 主密钥）"),
    ("GenerateDataKeyPairWithoutPlaintext", "生成加密的数据私钥及公钥"),
    ("GenerateRandom", "请求 KMS 生成安全随机字节"),
    ("GenerateMac", "使用 KMS 密钥生成消息认证码"),
    ("Sign", "使用 KMS 密钥生成数字签名"),
    ("Verify", "使用 KMS 密钥验证数字签名"),
    ("VerifyMac", "使用 KMS 密钥验证消息认证码"),
], kind="resource_use")
_register("cloudformation", "修改", [
    ("ContinueUpdateRollback", "继续回滚失败的 CloudFormation 堆栈更新"),
    ("RollbackStack", "请求将 CloudFormation 堆栈回滚到稳定状态"),
    ("ActivateType", "激活 CloudFormation 扩展或注册 Hook"),
    ("DeactivateType", "停用 CloudFormation 扩展并移除其配置"),
    ("ActivateOrganizationsAccess", "启用 CloudFormation StackSets 与 Organizations 受信访问"),
    ("DeactivateOrganizationsAccess", "停用 CloudFormation StackSets 与 Organizations 受信访问"),
])
_register("ssm", "修改", [
    ("ResumeSession", "重新连接已断开的 Systems Manager 会话"),
    ("LabelParameterVersion", "为 Systems Manager 参数版本设置标签"),
    ("UnlabelParameterVersion", "移除 Systems Manager 参数版本标签"),
])
_register("secretsmanager", "新增", [
    ("ReplicateSecretToRegions", "向目标区域复制 Secret 副本（可能覆盖已有副本）"),
])
_register("secretsmanager", "删除", [("RemoveRegionsFromReplication", "删除指定区域的 Secret 副本")])
_register("secretsmanager", "修改", [("StopReplicationToReplica", "停止 Secret 副本复制并转为独立 Secret")])
_register("organizations", "修改", [
    ("MoveAccount", "将成员账号移动到其他组织单元或根节点"),
    ("DeclineHandshake", "拒绝 Organizations 握手请求"),
])
_register("organizations", "删除", [
    ("CloseAccount", "请求关闭 Organizations 成员账号（异步执行）"),
    ("LeaveOrganization", "成员账号退出组织（不删除 AWS 账号）"),
])
_register("organizations", "新增", [
    ("InviteAccountToOrganization", "创建邀请账号加入组织的握手请求"),
])
_register("autoscaling", "删除", [("BatchDeleteScheduledAction", "批量删除 Auto Scaling 计划操作")])
_register("autoscaling", "新增", [("LaunchInstances", "请求在 Auto Scaling 组内启动实例")])
_register("autoscaling", "修改", [
    ("BatchPutScheduledUpdateGroupAction", "批量创建或更新 Auto Scaling 计划操作"),
    ("EnterStandby", "将 Auto Scaling 实例置于备用状态"),
    ("ExitStandby", "将 Auto Scaling 备用实例恢复服务"),
    ("SuspendProcesses", "暂停 Auto Scaling 流程"),
    ("ResumeProcesses", "恢复 Auto Scaling 流程"),
    ("CompleteLifecycleAction", "完成 Auto Scaling 生命周期挂钩操作"),
])
_register("route53", "修改", [
    ("ActivateKeySigningKey", "激活 Route 53 DNSSEC 密钥签名密钥"),
    ("DeactivateKeySigningKey", "停用 Route 53 DNSSEC 密钥签名密钥"),
])
_register("ecr", "删除", [("BatchDeleteImage", "批量删除 ECR 镜像或镜像标签")])
_register("ecr", "新增", [("InitiateLayerUpload", "创建 ECR 镜像层上传任务")])
_register("ecr", "修改", [("CompleteLayerUpload", "完成 ECR 镜像层上传")])


def lookup_action(event):
    """Return a copy of a reviewed service/API record, never guess by substring."""
    record = ACTIONS.get((_service(event), event.get("eventName")))
    return dict(record) if record else None


class _DocumentationText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.paragraphs = [], []
        self.in_paragraph, self.skip = False, 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.skip += 1
        if tag == "p" and not self.paragraphs:
            self.in_paragraph = True

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.skip = max(0, self.skip - 1)
        if tag == "p" and self.in_paragraph:
            self.paragraphs.append(" ".join(self.parts))
            self.in_paragraph = False

    def handle_data(self, data):
        if not self.skip and not self.paragraphs:
            self.parts.append(data)


def _plain_documentation(value):
    parser = _DocumentationText()
    parser.feed(value or "")
    text = parser.paragraphs[0] if parser.paragraphs else " ".join(parser.parts)
    return re.sub(r"\s+", " ", "".join(char for char in text if ord(char) >= 32 or char in "\n\t")).strip()[:600]


@lru_cache(maxsize=32)
def _local_model(service):
    try:
        import botocore
        from botocore.loaders import Loader
        from botocore.model import ServiceModel
        # Restrict loading to installed public SDK models, excluding ~/.aws paths.
        directory = str(Path(botocore.__file__).resolve().parent / "data")
        loader = Loader(extra_search_paths=[directory], include_default_search_paths=False)
        return ServiceModel(loader.load_service_model(service, "service-2"), service_name=service)
    except (ImportError, OSError, ValueError, KeyError):
        return None
    except Exception:
        # Optional metadata cannot prevent report generation after an SDK update.
        return None


@lru_cache(maxsize=512)
def _operation_metadata(service, name):
    sdk, display, _ = SERVICES[service]
    fallback = {"service_name": display, "api_description": "", "operation_reference": ""}
    model = _local_model(sdk)
    if model is None or name not in model.operation_names:
        return fallback
    try:
        return {"service_name": display,
                "api_description": _plain_documentation(model.operation_model(name).documentation),
                "operation_reference": _reference(service, name)}
    except Exception:
        return fallback


def describe_operation(event):
    """Describe known operations from installed SDK models, entirely offline."""
    service, name = _service(event), event.get("eventName")
    if service is None or not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,159}", name):
        return {"service_name": "未识别 AWS 服务", "api_description": "", "operation_reference": ""}
    return dict(_operation_metadata(service, name))
