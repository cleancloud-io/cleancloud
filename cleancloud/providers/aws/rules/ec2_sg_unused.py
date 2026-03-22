from datetime import datetime, timezone
from typing import List, Set

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# Naming prefixes that indicate AWS-managed security groups.
# These are created by managed services (RDS, Lambda, ELB, EKS, ECS, Beanstalk)
# and may temporarily have no ENIs between deployments — not safe to blindly delete.
_SERVICE_MANAGED_PREFIXES = (
    "rds-",
    "lambda-",
    "awslambda-",
    "elasticbeanstalk-",
    "ELB ",
    "eks-",
    "k8s-",
    "amazon-eks-",
    "ecs-",
)


def find_unused_security_groups(
    session: boto3.Session,
    region: str,
) -> List[Finding]:
    """
    Find security groups not associated with any network interface.

    Security groups with no ENI associations serve no protective purpose —
    they are pure governance debt. As environments scale, unused groups
    accumulate from abandoned test stacks, decommissioned services, and
    incomplete teardowns. Each one widens the blast radius if a misconfiguration
    is introduced, increases the manual audit burden during compliance reviews,
    and obscures the real security posture of the account.

    Detection logic:
    - Security group has no associated ENIs (checked via DescribeNetworkInterfaces)
    - Group name is not 'default' — default groups cannot be deleted by AWS design

    Additional signals (no extra API calls):
    - Whether the group is referenced as a source in another SG's inbound rules
    - Whether the group name matches known service-managed naming patterns
    - VPC name (via describe_vpcs, best-effort — no new required permission)

    Caveats:
    - A group referenced only in another group's inbound rules (not attached to
      any ENI) will still be flagged, but this is surfaced as an explicit signal
      so reviewers can make an informed call.
    - Service-managed groups (RDS, ELB, Lambda) are detected via naming heuristics
      and signalled, not skipped — the operator may have left them orphaned.
    - SGs referenced in Launch Templates or Auto Scaling Groups (scaled to 0)
      are not checked; see signals_not_checked.

    IAM permissions:
    - ec2:DescribeSecurityGroups
    - ec2:DescribeNetworkInterfaces
    """
    ec2 = session.client("ec2", region_name=region)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    try:
        # Collect all security groups in the region
        all_sgs = []
        sg_paginator = ec2.get_paginator("describe_security_groups")
        for page in sg_paginator.paginate():
            all_sgs.extend(page.get("SecurityGroups", []))

        if not all_sgs:
            return []

        # Build the set of SG IDs currently in use (attached to at least one ENI)
        in_use_sg_ids: Set[str] = set()
        eni_paginator = ec2.get_paginator("describe_network_interfaces")
        for page in eni_paginator.paginate():
            for eni in page.get("NetworkInterfaces", []):
                for group in eni.get("Groups", []):
                    gid = group.get("GroupId")
                    if gid:
                        in_use_sg_ids.add(gid)

        # Build set of SG IDs referenced by other SGs (inbound or egress rules).
        # We check both IpPermissions and IpPermissionsEgress — stricter environments
        # use SG-to-SG egress rules. We surface this as a signal, not a skip —
        # the referencing group may itself be unused, making this a genuine orphan chain.
        referenced_sg_ids: Set[str] = set()
        for sg in all_sgs:
            for direction in ("IpPermissions", "IpPermissionsEgress"):
                for rule in sg.get(direction, []):
                    for pair in rule.get("UserIdGroupPairs", []):
                        ref_id = pair.get("GroupId")
                        if ref_id:
                            referenced_sg_ids.add(ref_id)

        # Build VPC ID → name map for readability (best-effort; skip on missing permission)
        vpc_names: dict = {}
        vpc_ids = list({sg.get("VpcId") for sg in all_sgs if sg.get("VpcId")})
        if vpc_ids:
            try:
                resp = ec2.describe_vpcs(VpcIds=vpc_ids)
                for vpc in resp.get("Vpcs", []):
                    name = next(
                        (t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"),
                        None,
                    )
                    if name:
                        vpc_names[vpc["VpcId"]] = name
            except ClientError:
                pass  # VPC names are display-only; don't fail the rule

        for sg in all_sgs:
            sg_id = sg.get("GroupId", "")
            sg_name = sg.get("GroupName", "")

            # Skip default SGs — AWS prevents deletion; flagging them is noise
            if sg_name == "default":
                continue

            if sg_id in in_use_sg_ids:
                continue

            tags = sg.get("Tags", [])
            vpc_id = sg.get("VpcId", "")
            vpc_name = vpc_names.get(vpc_id)
            description = sg.get("Description", "")

            # Count inbound and outbound rules as a supporting intent signal
            inbound_rules = sg.get("IpPermissions", [])
            outbound_rules = sg.get("IpPermissionsEgress", [])
            rule_count = len(inbound_rules) + len(outbound_rules)

            is_referenced = sg_id in referenced_sg_ids
            is_service_managed = sg_name.startswith(_SERVICE_MANAGED_PREFIXES)

            vpc_label = f"{vpc_name} ({vpc_id})" if vpc_name else vpc_id
            signals = [
                "No ENI associations found for this security group",
                f"Security group: '{sg_name}' ({sg_id})",
                f"VPC: {vpc_label}",
            ]
            if rule_count > 0:
                signals.append(f"Group has {rule_count} rule(s) defined but no attached interfaces")
            if description:
                signals.append(f"Description: {description}")

            # Surface cross-SG reference as a first-class signal so reviewers
            # can distinguish a genuine orphan from a blue/green deploy in-flight
            if is_referenced:
                signals.append(
                    "Referenced by another security group in inbound or egress rules "
                    "(may not indicate active usage if the referencing group is also unused)"
                )

            # Service-managed naming heuristic — flag, don't skip
            if is_service_managed:
                signals.append(
                    "Name matches a known service-managed prefix "
                    "(e.g. rds-, eks-, lambda-, ELB) — verify before deleting"
                )

            # Graduated confidence: HIGH only when every ambiguity signal is absent —
            # no rules, no tags, not referenced by other SGs, and no service-managed
            # naming. A group with none of these markers is a strong orphan signal.
            if not is_referenced and not is_service_managed and rule_count == 0 and not tags:
                confidence = ConfidenceLevel.HIGH
            else:
                confidence = ConfidenceLevel.MEDIUM

            evidence = Evidence(
                signals_used=signals,
                signals_not_checked=[
                    "Groups referenced in EC2 Launch Templates or Auto Scaling Groups (not yet launched)",
                    "Recently created groups awaiting resource association",
                ],
                time_window=None,
            )

            details: dict = {
                "sg_name": sg_name,
                "vpc_id": vpc_id,
                "description": description,
                "rule_count": rule_count,
            }
            if vpc_name:
                details["vpc_name"] = vpc_name
            if is_referenced:
                details["referenced_by_other_sg"] = True
            if is_service_managed:
                details["likely_service_managed"] = True
            if tags:
                details["tags"] = {t["Key"]: t["Value"] for t in tags}

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.ec2.security_group.unused",
                    resource_type="aws.ec2.security_group",
                    resource_id=sg_id,
                    region=region,
                    title="Unused Security Group",
                    summary=(
                        f"Security group '{sg_name}' ({sg_id}) in VPC {vpc_label} "
                        f"is not associated with any network interface."
                    ),
                    reason="Security group has no ENI associations",
                    risk=RiskLevel.LOW,
                    confidence=confidence,
                    detected_at=now,
                    evidence=evidence,
                    details=details,
                    estimated_monthly_cost_usd=None,
                )
            )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError(
                "Missing required IAM permissions: "
                "ec2:DescribeSecurityGroups, ec2:DescribeNetworkInterfaces"
            ) from e
        raise

    return findings
