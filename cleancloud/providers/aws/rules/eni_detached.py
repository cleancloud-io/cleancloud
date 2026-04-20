"""
Rule: aws.ec2.eni.detached

    (spec — docs/specs/aws/eni_detached.md)

Intent:
    Detect network interfaces that are currently not attached according to the
    EC2 DescribeNetworkInterfaces contract, so they can be reviewed as possible
    cleanup candidates if no longer needed.

Exclusions:
    - network_interface_id absent (malformed identity)
    - normalized_status absent (missing current-state signal)
    - normalized_status != "available" (attached or other non-eligible state)
    - attachment_status is not null/absent or "detached" (any other value including
      unknown/malformed strings is treated as inconsistent — SKIP ITEM)

Detection:
    - network_interface_id present
    - normalized_status == "available"
    - attachment_status absent, null, or "detached"

Key rules:
    - Top-level Status is the sole state authority; attachment_status is validation only.
    - No temporal threshold — current not-attached state is the sole eligibility signal.
    - No exclusion for interface_type, requester_managed, or operator_managed.
    - Do not use CreateTime or any age/duration field for eligibility.
    - estimated_monthly_cost_usd = None.
    - Confidence: HIGH.
    - Risk: LOW.

Blind spots:
    - how long the ENI has been in a not-currently-attached state
    - previous attachment history
    - whether an AWS service expects to recycle or clean up this ENI
    - application, failover, or operational intent
    - exact pricing impact

APIs:
    - ec2:DescribeNetworkInterfaces
"""

from datetime import datetime, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# --- Module-level constants ---

# Sole eligible top-level ENI status per EC2 documented contract.
_ELIGIBLE_STATUS = "available"

# Attachment states that are consistent with an available (not-currently-attached) ENI.
# Any attachment_status outside this set is treated as inconsistent → SKIP ITEM.
_ALLOWED_ATTACHMENT_STATUSES: frozenset = frozenset({None, "detached"})

_FINDING_TITLE = "ENI not currently attached review candidate"

_SIGNAL_NOT_CURRENTLY_ATTACHED = (
    "ENI top-level Status is 'available' (not currently attached per EC2 documented contract)"
)
_SIGNAL_REQUESTER_MANAGED = "ENI is requester-managed (created by an AWS service on your behalf)"

_SIGNALS_NOT_CHECKED = (
    "How long the ENI has been in a not-currently-attached state",
    "Previous attachment history",
    "Whether an AWS service expects to recycle or clean up this ENI",
    "Application, failover, or operational intent",
    "Exact pricing impact",
)


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


def _bool_only(value: object) -> Optional[bool]:
    """Return value only when it is an actual bool; else None."""
    return value if isinstance(value, bool) else None


def _normalize_eni(eni: object) -> Optional[dict]:
    """Normalize a raw DescribeNetworkInterfaces item to the canonical field shape.

    Returns None when the item is not a dict or required identity/state fields
    are absent — the caller must skip the item.  All rule logic must operate
    only on the returned normalized dict.
    """
    if not isinstance(eni, dict):
        return None

    # --- Identity fields (required; absent → skip item) ---
    network_interface_id = _str(eni.get("NetworkInterfaceId"))
    if network_interface_id is None:
        return None

    # --- State fields (required; absent → skip item) ---
    normalized_status = _str(eni.get("Status"))
    if normalized_status is None:
        return None

    # --- Attachment fields (all optional → null) ---
    raw_attachment = eni.get("Attachment")
    if isinstance(raw_attachment, dict):
        attachment_status = _str(raw_attachment.get("Status"))
        attachment_id = _str(raw_attachment.get("AttachmentId"))
        attachment_instance_id = _str(raw_attachment.get("InstanceId"))
        attachment_instance_owner_id = _str(raw_attachment.get("InstanceOwnerId"))
    else:
        attachment_status = None
        attachment_id = None
        attachment_instance_id = None
        attachment_instance_owner_id = None

    # --- Ownership / service-context fields (optional → null) ---
    interface_type = _str(eni.get("InterfaceType"))
    requester_managed = _bool_only(eni.get("RequesterManaged"))

    raw_operator = eni.get("Operator")
    if isinstance(raw_operator, dict):
        operator_managed = _bool_only(raw_operator.get("Managed"))
        operator_principal = _str(raw_operator.get("Principal"))
    else:
        operator_managed = None
        operator_principal = None

    # --- Network / resource-metadata fields (optional → null / []) ---
    description = _str(eni.get("Description"))
    availability_zone = _str(eni.get("AvailabilityZone"))
    subnet_id = _str(eni.get("SubnetId"))
    vpc_id = _str(eni.get("VpcId"))
    private_ip_address = _str(eni.get("PrivateIpAddress"))

    raw_association = eni.get("Association")
    public_ip = _str(raw_association.get("PublicIp")) if isinstance(raw_association, dict) else None

    raw_tag_set = eni.get("TagSet")
    tag_set: list = raw_tag_set if isinstance(raw_tag_set, list) else []

    return {
        "resource_id": network_interface_id,
        "network_interface_id": network_interface_id,
        "normalized_status": normalized_status,
        "attachment_status": attachment_status,
        "attachment_id": attachment_id,
        "attachment_instance_id": attachment_instance_id,
        "attachment_instance_owner_id": attachment_instance_owner_id,
        "interface_type": interface_type,
        "requester_managed": requester_managed,
        "operator_managed": operator_managed,
        "operator_principal": operator_principal,
        "description": description,
        "availability_zone": availability_zone,
        "subnet_id": subnet_id,
        "vpc_id": vpc_id,
        "private_ip_address": private_ip_address,
        "public_ip": public_ip,
        "tag_set": tag_set,
    }


def find_detached_enis(
    session: boto3.Session,
    region: str,
) -> List[Finding]:
    ec2 = session.client("ec2", region_name=region)

    try:
        paginator = ec2.get_paginator("describe_network_interfaces")
        pages = list(paginator.paginate())
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "UnauthorizedOperation":
            raise PermissionError(
                "Missing required IAM permission: ec2:DescribeNetworkInterfaces"
            ) from exc
        raise
    except BotoCoreError:
        raise

    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    for page in pages:
        for raw_eni in page.get("NetworkInterfaces", []):
            # --- Step 1: Normalize ---
            n = _normalize_eni(raw_eni)
            if n is None:
                continue

            # --- Step 2: EXCLUSION RULES ---

            # EXCLUSION: top-level status must be the sole eligible state
            if n["normalized_status"] != _ELIGIBLE_STATUS:
                continue

            # EXCLUSION: attachment_status must be in the allowed set (None or "detached").
            # Any other value — known conflict statuses or unknown/malformed strings —
            # is inconsistent with the available state → SKIP ITEM.
            if n["attachment_status"] not in _ALLOWED_ATTACHMENT_STATUSES:
                continue

            # --- Detection path: detached-eni-review-candidate ---

            signals_used = [_SIGNAL_NOT_CURRENTLY_ATTACHED]
            if n["requester_managed"] is True:
                signals_used.append(_SIGNAL_REQUESTER_MANAGED)
            if n["operator_managed"] is True:
                principal = n["operator_principal"] or "unknown"
                signals_used.append(f"ENI is operator-managed (operator principal: {principal})")

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.ec2.eni.detached",
                    resource_type="aws.ec2.network_interface",
                    resource_id=n["network_interface_id"],
                    region=region,
                    estimated_monthly_cost_usd=None,
                    title=_FINDING_TITLE,
                    summary=(
                        f"ENI {n['network_interface_id']} Status is 'available' — "
                        "not currently attached per DescribeNetworkInterfaces"
                    ),
                    reason=(
                        "ENI Status is 'available' — not currently attached "
                        "per DescribeNetworkInterfaces"
                    ),
                    risk=RiskLevel.LOW,
                    confidence=ConfidenceLevel.HIGH,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=list(_SIGNALS_NOT_CHECKED),
                    ),
                    details={
                        "evaluation_path": "detached-eni-review-candidate",
                        "network_interface_id": n["network_interface_id"],
                        "normalized_status": n["normalized_status"],
                        "attachment_status": n["attachment_status"],
                        "attachment_id": n["attachment_id"],
                        "attachment_instance_id": n["attachment_instance_id"],
                        "attachment_instance_owner_id": n["attachment_instance_owner_id"],
                        "interface_type": n["interface_type"],
                        "requester_managed": n["requester_managed"],
                        "operator_managed": n["operator_managed"],
                        "operator_principal": n["operator_principal"],
                        "availability_zone": n["availability_zone"],
                        "subnet_id": n["subnet_id"],
                        "vpc_id": n["vpc_id"],
                        "private_ip_address": n["private_ip_address"],
                        "public_ip": n["public_ip"],
                        "description": n["description"],
                        "tag_set": n["tag_set"],
                    },
                )
            )

    return findings
