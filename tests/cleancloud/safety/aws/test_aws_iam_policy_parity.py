"""
Parity test: assert AWS IAM policy files contain every action required
by the corresponding rule implementations.

Rationale: the existing read-only safety test (`test_aws_iam_policy_readonly.py`)
ensures no mutating actions slip in, but does NOT verify coverage. This test catches
the complementary failure mode — a required action silently omitted from the shipped
policy, leaving users with an "official" policy that produces coverage gaps at runtime.
"""

import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Required actions per policy file — derived from rule implementations
# ---------------------------------------------------------------------------

HYGIENE_REQUIRED_ACTIONS = {
    # aws.ebs.unattached
    "ec2:DescribeVolumes",
    # aws.ebs.snapshot.old — list + public-snapshot attribute check
    "ec2:DescribeSnapshots",
    "ec2:DescribeSnapshotAttribute",
    # aws.ec2.ami.old
    "ec2:DescribeImages",
    # aws.ec2.elastic_ip.unattached
    "ec2:DescribeAddresses",
    # aws.ec2.eni.detached
    "ec2:DescribeNetworkInterfaces",
    # aws.ec2.nat_gateway.idle
    "ec2:DescribeNatGateways",
    # region discovery
    "ec2:DescribeRegions",
    # aws.ec2.instance.stopped, aws.ec2.security_group.unused
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups",
    # aws.elbv2.alb.idle / aws.elbv2.nlb.idle / aws.elb.clb.idle
    "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:DescribeTargetHealth",
    # aws.rds.instance.idle + aws.rds.snapshot.old + public-snapshot attribute check
    "rds:DescribeDBInstances",
    "rds:DescribeDBSnapshots",
    "rds:DescribeDBSnapshotAttributes",
    # aws.ec2.instance.stopped — stopped-duration CloudTrail probe
    "cloudtrail:LookupEvents",
    # metrics (NAT gateway, RDS, ELB idle detection)
    "cloudwatch:GetMetricStatistics",
    # aws.cloudwatch.logs.infinite_retention
    "logs:DescribeLogGroups",
    # aws.resource.untagged
    "s3:ListAllMyBuckets",
    "s3:GetBucketTagging",
}

AI_REQUIRED_ACTIONS = {
    # aws.sagemaker.endpoint.idle
    "sagemaker:ListEndpoints",
    "sagemaker:DescribeEndpoint",
    "sagemaker:DescribeEndpointConfig",
    # aws.sagemaker.notebook.idle
    "sagemaker:ListNotebookInstances",
    "sagemaker:DescribeNotebookInstance",
    # aws.sagemaker.studio_app.idle
    "sagemaker:ListApps",
    "sagemaker:DescribeApp",
    # aws.sagemaker.training_job.long_running
    "sagemaker:ListTrainingJobs",
    "sagemaker:DescribeTrainingJob",
    # aws.bedrock.provisioned_throughput.idle
    "bedrock:ListProvisionedModelThroughputs",
    # aws.ec2.gpu.idle
    "ec2:DescribeInstances",
    "cloudwatch:GetMetricStatistics",
    "cloudwatch:ListMetrics",
}

POLICY_PARITY: list[tuple[Path, set[str]]] = [
    (Path("security/aws/hygiene-readonly.json"), HYGIENE_REQUIRED_ACTIONS),
    (Path("security/aws/ai-readonly.json"), AI_REQUIRED_ACTIONS),
]


def _actions_in_policy(policy_path: Path) -> set[str]:
    policy = json.loads(policy_path.read_text())
    actions: set[str] = set()
    for statement in policy.get("Statement", []):
        raw = statement.get("Action", [])
        if isinstance(raw, str):
            raw = [raw]
        for action in raw:
            actions.add(action)
    return actions


@pytest.mark.safety
@pytest.mark.aws
@pytest.mark.parametrize(
    "policy_path,required",
    POLICY_PARITY,
    ids=lambda x: x.name if isinstance(x, Path) else "required",
)
def test_aws_iam_policy_contains_required_actions(policy_path, required):
    """
    Assert that every runtime-required action is present in the shipped IAM policy.
    Missing actions cause silent coverage gaps at runtime — rules skip resources
    without any error when the required permission is absent.
    """
    actual = _actions_in_policy(policy_path)
    missing = required - actual
    assert not missing, (
        f"{policy_path.name} is missing {len(missing)} required action(s):\n"
        + "\n".join(f"  - {a}" for a in sorted(missing))
        + "\nAdd them to the IAM policy to prevent silent coverage gaps at runtime."
    )
