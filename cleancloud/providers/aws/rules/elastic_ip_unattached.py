"""
Rule: aws.ec2.elastic_ip.unattached

    (spec — docs/specs/aws/elastic_ip_unattached.md)

Intent:
    Detect Elastic IP address records that are currently allocated to the account
    in the scanned Region and are not currently associated with an instance or
    network interface.

Exclusions:
    - resource_id absent (malformed identity)
    - any canonical association field present (currently associated)

Detection:
    - resource_id present
    - association_id, instance_id, network_interface_id, private_ip_address all absent

Key rules:
    - This is a review-candidate rule, not a delete-safe rule.
    - No temporal threshold — current unattached state is the sole eligibility signal.
    - Do not use AllocationTime (undocumented field).
    - All four canonical association fields must be checked, not only AssociationId.
    - Missing/non-iterable Addresses response fails the rule.
    - Do not hardcode a fixed monthly cost estimate.

Blind spots:
    - future planned attachment or operational reserve intent not known
    - DNS / allowlist / manual failover dependencies
    - application-level use of the reserved public IP
    - service-managed lifecycle expectations outside current association state

APIs:
    - ec2:DescribeAddresses
"""

from datetime import datetime, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def _str(value) -> Optional[str]:
    """Return value if it is a non-empty string, else None."""
    return value if isinstance(value, str) and value else None


def _normalize_address(address: dict) -> Optional[dict]:
    """Normalize a raw SDK address dict to the canonical field shape.

    Returns None when the item must be skipped (non-dict, absent stable identity).
    All rule logic must operate only on the returned dict.
    """
    if not isinstance(address, dict):
        return None

    # Identity — resource_id: AllocationId → PublicIp → CarrierIp → absent (skip)
    allocation_id = _str(address.get("AllocationId"))
    public_ip = _str(address.get("PublicIp"))
    carrier_ip = _str(address.get("CarrierIp"))

    resource_id = allocation_id or public_ip or carrier_ip
    if not resource_id:
        return None

    # Association fields — any present means currently associated
    association_id = _str(address.get("AssociationId"))
    instance_id = _str(address.get("InstanceId"))
    network_interface_id = _str(address.get("NetworkInterfaceId"))
    private_ip_address = _str(address.get("PrivateIpAddress"))

    # Context fields — absent → null; never block evaluation
    domain = _str(address.get("Domain"))
    network_interface_owner_id = _str(address.get("NetworkInterfaceOwnerId"))
    network_border_group = _str(address.get("NetworkBorderGroup"))
    public_ipv4_pool = _str(address.get("PublicIpv4Pool"))
    customer_owned_ip = _str(address.get("CustomerOwnedIp"))
    customer_owned_ipv4_pool = _str(address.get("CustomerOwnedIpv4Pool"))
    subnet_id = _str(address.get("SubnetId"))

    # ServiceManaged — string enum ("alb", "nlb", "rnat", "rds", …); normalize as string
    service_managed: Optional[str] = _str(address.get("ServiceManaged"))

    # Tags — prefer list; degrade to empty if absent or wrong type
    tags_raw = address.get("Tags")
    tags: list = tags_raw if isinstance(tags_raw, list) else []

    return {
        "resource_id": resource_id,
        "allocation_id": allocation_id,
        "public_ip": public_ip,
        "carrier_ip": carrier_ip,
        "association_id": association_id,
        "instance_id": instance_id,
        "network_interface_id": network_interface_id,
        "private_ip_address": private_ip_address,
        "domain": domain,
        "network_interface_owner_id": network_interface_owner_id,
        "network_border_group": network_border_group,
        "public_ipv4_pool": public_ipv4_pool,
        "customer_owned_ip": customer_owned_ip,
        "customer_owned_ipv4_pool": customer_owned_ipv4_pool,
        "subnet_id": subnet_id,
        "service_managed": service_managed,
        "tags": tags,
    }


def find_unattached_elastic_ips(
    session: boto3.Session,
    region: str,
) -> List[Finding]:
    ec2 = session.client("ec2", region_name=region)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    # --- Step 1: Retrieve all Elastic IP records ---
    try:
        response = ec2.describe_addresses()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError("Missing required IAM permission: ec2:DescribeAddresses") from exc
        raise
    except BotoCoreError:
        raise

    # --- Step 2: Validate top-level response integrity ---
    raw_addresses = response.get("Addresses")
    if raw_addresses is None or not isinstance(raw_addresses, list):
        raise RuntimeError(
            "DescribeAddresses response is missing a usable top-level Addresses field — "
            "cannot reliably determine EIP association state"
        )

    # --- Steps 3–5: Normalize, apply exclusions, emit ---
    for raw_address in raw_addresses:
        a = _normalize_address(raw_address)
        if a is None:
            continue  # SKIP: absent stable identity

        # EXCLUSION: currently associated
        if (
            a["association_id"] is not None
            or a["instance_id"] is not None
            or a["network_interface_id"] is not None
            or a["private_ip_address"] is not None
        ):
            continue

        # --- Detection path: unattached-eip-review-candidate ---

        evidence = Evidence(
            signals_used=[
                f"Address {a['resource_id']} is currently not associated per DescribeAddresses",
                "Address remains allocated to the account until explicitly released",
                "AWS recommends release only when the address is no longer needed "
                "and is not currently associated",
            ],
            signals_not_checked=[
                "Future planned attachment or operational reserve intent not known",
                "DNS / allowlist / manual failover dependencies",
                "Application-level use of the reserved public IP",
                "Exact monthly pricing from the current pricing page",
                "Service-managed lifecycle expectations outside current association state",
            ],
            time_window=None,
        )

        details: dict = {
            "evaluation_path": "unattached-eip-review-candidate",
            "resource_id": a["resource_id"],
            "allocation_id": a["allocation_id"],
            "public_ip": a["public_ip"],
            "carrier_ip": a["carrier_ip"],
            "domain": a["domain"],
            "currently_associated": False,
            "association_id": None,
            "instance_id": None,
            "network_interface_id": None,
            "private_ip_address": None,
        }
        if a["network_interface_owner_id"] is not None:
            details["network_interface_owner_id"] = a["network_interface_owner_id"]
        if a["network_border_group"] is not None:
            details["network_border_group"] = a["network_border_group"]
        if a["public_ipv4_pool"] is not None:
            details["public_ipv4_pool"] = a["public_ipv4_pool"]
        if a["customer_owned_ip"] is not None:
            details["customer_owned_ip"] = a["customer_owned_ip"]
        if a["customer_owned_ipv4_pool"] is not None:
            details["customer_owned_ipv4_pool"] = a["customer_owned_ipv4_pool"]
        if a["subnet_id"] is not None:
            details["subnet_id"] = a["subnet_id"]
        if a["service_managed"] is not None:
            details["service_managed"] = a["service_managed"]
        if a["tags"]:
            details["tags"] = {
                t.get("Key"): t.get("Value") for t in a["tags"] if isinstance(t, dict)
            }

        findings.append(
            Finding(
                provider="aws",
                rule_id="aws.ec2.elastic_ip.unattached",
                resource_type="aws.ec2.elastic_ip",
                resource_id=a["resource_id"],
                region=region,
                title="Unattached Elastic IP review candidate",
                summary=(
                    f"Elastic IP {a['resource_id']}"
                    + (
                        f" ({a['public_ip']})"
                        if a["public_ip"] and a["public_ip"] != a["resource_id"]
                        else ""
                    )
                    + " is currently not associated with any instance or network interface; "
                    "review for possible release"
                ),
                reason="Address has no current association per DescribeAddresses",
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=evidence,
                details=details,
                estimated_monthly_cost_usd=None,
            )
        )

    return findings
