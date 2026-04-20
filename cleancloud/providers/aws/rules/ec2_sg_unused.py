"""
Rule: aws.ec2.security_group.unused

    (spec — docs/specs/aws/ec2_sg_unused.md)

Intent:
    Detect security groups not currently associated with any network interface in
    the scanned region that are cleanup review candidates.

Exclusions:
    - sg_id is absent (malformed)
    - is_default_group == True (GroupName == "default")
    - attached_eni_count > 0 (SG ID found in any ENI group membership)

Detection:
    - is_default_group == False
    - normalized attachment_eni_count == 0

Key rules:
    - This is a review-candidate rule, not a delete-safe rule.
    - ENI coverage is region-scoped; absence from ENI scan does not prove no AWS
      control-plane dependency.
    - referenced_by_other_sg is dependency metadata and context only, never an
      exclusion.
    - Service-managed name hints are heuristic context only, never affect
      eligibility or confidence.
    - ENI pagination must be exhausted; partial pagination can create false
      positives.

Blind spots:
    - launch templates, Auto Scaling, ECS, Lambda, and similar configs not
      currently materialized as ENIs
    - security group VPC associations (not queried by this rule)
    - EC2 eventual-consistency windows after recent SG or ENI changes
    - business/application or DR intent not known

APIs:
    - ec2:DescribeSecurityGroups
    - ec2:DescribeNetworkInterfaces
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# Heuristic name-prefix hints for service-managed SGs.
# Contextual evidence only — must never affect eligibility or confidence.
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


def _normalize_sg(sg: dict) -> Optional[dict]:
    """Normalize a raw SDK security group dict to the canonical field shape.

    Returns None when sg_id is absent — the item must be skipped.
    All rule logic must operate only on the returned normalized dict.
    """
    sg_id = sg.get("GroupId") or sg.get("groupId")
    if not sg_id:
        return None

    sg_name: str = sg.get("GroupName") or sg.get("groupName") or ""
    vpc_id: Optional[str] = sg.get("VpcId") or sg.get("vpcId") or None
    description: Optional[str] = (
        sg.get("Description") or sg.get("groupDescription") or sg.get("description") or None
    )

    # Tags — prefer canonical boto3 casing; fall back to lowercase variants.
    if "Tags" in sg:
        normalized_tags = sg["Tags"] or []
    elif "TagSet" in sg:
        normalized_tags = sg["TagSet"] or []
    elif "tagSet" in sg:
        normalized_tags = sg["tagSet"] or []
    else:
        normalized_tags = []

    # Ingress and egress rules.
    if "IpPermissions" in sg:
        normalized_ingress = sg["IpPermissions"] or []
    elif "ipPermissions" in sg:
        normalized_ingress = sg["ipPermissions"] or []
    else:
        normalized_ingress = []

    if "IpPermissionsEgress" in sg:
        normalized_egress = sg["IpPermissionsEgress"] or []
    elif "ipPermissionsEgress" in sg:
        normalized_egress = sg["ipPermissionsEgress"] or []
    else:
        normalized_egress = []

    rule_count = len(normalized_ingress) + len(normalized_egress)
    is_default_group = sg_name == "default"

    return {
        "sg_id": sg_id,
        "sg_name": sg_name,
        "vpc_id": vpc_id,
        "description": description,
        "normalized_tags": normalized_tags,
        "normalized_ingress_rules": normalized_ingress,
        "normalized_egress_rules": normalized_egress,
        "rule_count": rule_count,
        "is_default_group": is_default_group,
    }


def _build_referenced_sg_set(normalized_sgs: List[dict]) -> Set[str]:
    """Build the set of all SG IDs referenced in any other SG's ingress or egress rules.

    Scans only SG-reference entries (UserIdGroupPairs / groups); CIDR ranges,
    IPv6 ranges, and prefix lists are ignored.
    """
    referenced: Set[str] = set()
    for sg in normalized_sgs:
        for rules in (sg["normalized_ingress_rules"], sg["normalized_egress_rules"]):
            if not isinstance(rules, list):
                continue
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                pairs = rule.get("UserIdGroupPairs") or rule.get("groups") or []
                if not isinstance(pairs, list):
                    continue
                for pair in pairs:
                    if not isinstance(pair, dict):
                        continue
                    ref_id = pair.get("GroupId") or pair.get("groupId")
                    if ref_id:
                        referenced.add(ref_id)
    return referenced


def _build_eni_usage(
    eni_pages: list,
) -> Tuple[Dict[str, Set[str]], bool]:
    """Build sg_to_eni_ids from all paginated ENI results.

    Returns (sg_to_eni_ids, failed).

    sg_to_eni_ids maps sg_id → set of distinct ENI IDs that reference it.
    failed=True when any ENI is missing the identity or group-membership field
    required for trustworthy counting — the caller must FAIL RULE in this case.
    """
    sg_to_eni_ids: Dict[str, Set[str]] = {}

    for page in eni_pages:
        for eni in page.get("NetworkInterfaces", []):
            # ENI identity — required for distinct-count deduplication.
            eni_id = eni.get("NetworkInterfaceId") or eni.get("networkInterfaceId")
            if not eni_id:
                return sg_to_eni_ids, True

            # SG membership — canonical precedence: Groups → GroupSet → groupSet.
            # Absent key means the membership field is missing → FAIL RULE.
            if "Groups" in eni:
                groups = eni["Groups"]
            elif "GroupSet" in eni:
                groups = eni["GroupSet"]
            elif "groupSet" in eni:
                groups = eni["groupSet"]
            else:
                return sg_to_eni_ids, True

            if not isinstance(groups, list):
                return sg_to_eni_ids, True

            for group in groups:
                if not isinstance(group, dict):
                    return sg_to_eni_ids, True
                gid = group.get("GroupId") or group.get("groupId")
                if gid:
                    if gid not in sg_to_eni_ids:
                        sg_to_eni_ids[gid] = set()
                    sg_to_eni_ids[gid].add(eni_id)

    return sg_to_eni_ids, False


def find_unused_security_groups(
    session: boto3.Session,
    region: str,
) -> List[Finding]:
    ec2 = session.client("ec2", region_name=region)
    now = datetime.now(timezone.utc)

    # --- Step 1: Retrieve all security groups ---
    try:
        sg_pages = list(ec2.get_paginator("describe_security_groups").paginate())
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError(
                "Missing required IAM permission: ec2:DescribeSecurityGroups"
            ) from exc
        raise
    except BotoCoreError:
        raise

    # --- Step 2: Normalize SG records ---
    normalized_sgs: List[dict] = []
    for page in sg_pages:
        for raw_sg in page.get("SecurityGroups", []):
            n = _normalize_sg(raw_sg)
            if n is not None:
                normalized_sgs.append(n)

    if not normalized_sgs:
        return []

    # --- Step 3: Build referenced-SG set from normalized rules ---
    referenced_sg_ids = _build_referenced_sg_set(normalized_sgs)

    # --- Step 4: Retrieve all ENIs ---
    try:
        eni_pages = list(ec2.get_paginator("describe_network_interfaces").paginate())
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError(
                "Missing required IAM permission: ec2:DescribeNetworkInterfaces"
            ) from exc
        raise
    except BotoCoreError:
        raise

    # --- Step 5: Build sg_to_eni_ids (distinct ENI IDs per SG) ---
    sg_to_eni_ids, eni_parse_failed = _build_eni_usage(eni_pages)
    if eni_parse_failed:
        raise RuntimeError(
            "ENI payload shape prevents trustworthy SG membership derivation — "
            "required ENI identity or group-membership field is missing or malformed"
        )

    # --- Step 6: Optional VPC name enrichment (best-effort; never fails the rule) ---
    vpc_names: dict = {}
    vpc_ids = list({sg["vpc_id"] for sg in normalized_sgs if sg["vpc_id"]})
    if vpc_ids:
        try:
            resp = ec2.describe_vpcs(VpcIds=vpc_ids)
            for vpc in resp.get("Vpcs", []):
                name = next(
                    (t["Value"] for t in vpc.get("Tags", []) if t.get("Key") == "Name"),
                    None,
                )
                if name:
                    vpc_names[vpc["VpcId"]] = name
        except Exception:
            pass  # VPC names are display-only; don't fail the rule

    # --- Step 7: Apply exclusion rules and emit findings ---
    findings: List[Finding] = []

    for sg in normalized_sgs:
        sg_id = sg["sg_id"]

        # EXCLUSION: default security group
        if sg["is_default_group"]:
            continue

        # EXCLUSION: currently associated with at least one ENI
        attached_eni_count = len(sg_to_eni_ids.get(sg_id, set()))
        if attached_eni_count > 0:
            continue

        # --- Detection path: unused-security-group-review-candidate ---

        referenced_by_other_sg: bool = sg_id in referenced_sg_ids
        vpc_name: Optional[str] = vpc_names.get(sg["vpc_id"]) if sg["vpc_id"] else None
        vpc_label = f"{vpc_name} ({sg['vpc_id']})" if vpc_name else (sg["vpc_id"] or "")

        # Heuristic service-managed name hint — context only, never affects eligibility.
        heuristic_service_managed = sg["sg_name"].startswith(_SERVICE_MANAGED_PREFIXES)

        signals_used = [
            f"No ENI associations found (attached_eni_count == 0) for {sg_id}",
            "is_default_group == False — default-group exclusion did not match",
            (
                f"referenced_by_other_sg == {referenced_by_other_sg}; "
                "cross-SG references are dependency metadata only, not ENI attachment"
            ),
            f"{sg['rule_count']} rule(s) defined (ingress + egress)",
        ]
        if vpc_label:
            signals_used.append(f"VPC: {vpc_label}")
        if heuristic_service_managed:
            signals_used.append(
                f"Name {sg['sg_name']!r} matches a service-managed naming hint "
                "(heuristic only — does not affect eligibility or confidence)"
            )

        evidence = Evidence(
            signals_used=signals_used,
            signals_not_checked=[
                "Launch templates, Auto Scaling, ECS, Lambda, and similar "
                "configurations not currently materialized as ENIs",
                "Security group VPC associations (not queried by this rule)",
                "Business/application or DR intent not known",
                "EC2 eventual-consistency windows after recent SG or ENI changes",
                "AWS control-plane dependencies not visible in "
                "DescribeNetworkInterfaces for this region",
            ],
            time_window=None,
        )

        details: dict = {
            "evaluation_path": "unused-security-group-review-candidate",
            "sg_id": sg_id,
            "sg_name": sg["sg_name"],
            "vpc_id": sg["vpc_id"],
            "attached_eni_count": 0,  # only reachable when == 0
            "referenced_by_other_sg": referenced_by_other_sg,
            "rule_count": sg["rule_count"],
            "description": sg["description"],
            "is_default_group": False,  # only reachable when False
            "region_scope_only": True,
        }
        if vpc_name:
            details["vpc_name"] = vpc_name
        if heuristic_service_managed:
            details["heuristic_service_managed_hint"] = True
        if sg["normalized_tags"]:
            details["tags"] = {
                t.get("Key"): t.get("Value") for t in sg["normalized_tags"] if isinstance(t, dict)
            }

        findings.append(
            Finding(
                provider="aws",
                rule_id="aws.ec2.security_group.unused",
                resource_type="aws.ec2.security_group",
                resource_id=sg_id,
                region=region,
                title="Unused security group review candidate",
                summary=(
                    f"Security group '{sg['sg_name']}' ({sg_id})"
                    + (f" in VPC {vpc_label}" if vpc_label else "")
                    + " has no current ENI associations; review as cleanup candidate"
                ),
                reason=(
                    "Security group has normalized attachment_eni_count == 0 "
                    "and the default-group exclusion did not match"
                ),
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.MEDIUM,  # spec §7: MEDIUM mandatory; HIGH not recommended
                detected_at=now,
                evidence=evidence,
                details=details,
                estimated_monthly_cost_usd=None,
            )
        )

    return findings
