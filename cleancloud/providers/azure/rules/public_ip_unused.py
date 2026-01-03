from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.network import NetworkManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_unused_public_ips(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[NetworkManagementClient] = None,
) -> List[Finding]:
    """
    Find unattached or unused Azure Public IPs.

    Conservative rule (review-only):
    - IP configuration checked
    - Does NOT infer future use or planned attachment

    IAM permissions:
    - Microsoft.Network/publicIPAddresses/read
    """
    findings: List[Finding] = []

    net_client = client or NetworkManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    for pip in net_client.public_ip_addresses.list_all():
        if region_filter and pip.location != region_filter:
            continue

        # Skip attached IPs
        if pip.ip_configuration is not None:
            continue

        evidence = Evidence(
            signals_used=["IP configuration is None (not attached to any resource)"],
            signals_not_checked=[
                "Planned future association",
                "IaC-managed intent",
                "Application-level usage",
                "Disaster recovery or backup planning",
            ],
            time_window=None,
        )

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.public_ip_unused",
                resource_type="azure.public_ip",
                resource_id=pip.id,
                region=pip.location,
                title="Unused Azure Public IP",
                summary="Public IP is not attached to any resource",
                reason="IP configuration is None (not attached)",
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.MEDIUM,  # conservative
                detected_at=datetime.now(timezone.utc),
                evidence=evidence,
                details={
                    "resource_name": pip.name,
                    "subscription_id": subscription_id,
                    "attached": False,
                    "ip_address": pip.ip_address,
                    "tags": pip.tags,
                },
            )
        )

    return findings
