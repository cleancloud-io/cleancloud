from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional, Tuple

import click

from cleancloud.core.finding import Finding
from cleancloud.output.progress import advance
from cleancloud.providers.azure.rules.ebs_snapshots_old import find_old_snapshots
from cleancloud.providers.azure.rules.public_ip_unused import find_unused_public_ips
from cleancloud.providers.azure.rules.unattached_managed_disks import (
    find_unattached_managed_disks,
)
from cleancloud.providers.azure.rules.untagged_resources import (
    find_untagged_resources as find_azure_untagged_resources,
)
from cleancloud.providers.azure.session import create_azure_session


def scan_azure_with_region_selection(
    region: Optional[str],
) -> Tuple[str, List[Finding], List[str]]:
    click.echo("🔍 Authenticating to Azure")
    click.echo()

    session = create_azure_session()
    subscription_ids = session.list_subscription_ids()

    if not subscription_ids:
        raise PermissionError("No accessible Azure subscriptions found")

    click.echo(f"✓ Found {len(subscription_ids)} subscription(s)")
    click.echo()

    findings = scan_azure_subscriptions(
        subscription_ids,
        session.credential,
        region,
    )

    click.echo()

    regions_scanned = ["all"] if not region else [region]
    region_selection_mode = "explicit" if region else "all"

    return region_selection_mode, findings, regions_scanned


AZURE_RULES: List[Callable] = [
    find_unattached_managed_disks,
    find_old_snapshots,
    find_azure_untagged_resources,
    find_unused_public_ips,
]


def scan_azure_subscriptions(
    subscription_ids: List[str],
    credential,
    region_filter: Optional[str],
) -> List[Finding]:
    all_findings: List[Finding] = []

    with click.progressbar(
        length=len(subscription_ids),
        label="Scanning Azure subscriptions",
        show_eta=True,
        show_percent=True,
    ) as bar:
        with ThreadPoolExecutor(max_workers=min(4, len(subscription_ids))) as executor:
            futures = {
                executor.submit(
                    _scan_azure_subscription,
                    subscription_id=sub_id,
                    credential=credential,
                    region_filter=region_filter,
                ): sub_id
                for sub_id in subscription_ids
            }

            for future in as_completed(futures):
                sub_id = futures[future]
                click.echo(f"✅ Completed subscription {sub_id}")
                click.echo()
                try:
                    all_findings.extend(future.result())
                except Exception as e:
                    click.echo(f"⚠️ Subscription {sub_id} failed: {e}")
                finally:
                    advance(bar)

    return all_findings


def _scan_azure_subscription(
    subscription_id: str,
    credential,
    region_filter: Optional[str],
) -> List[Finding]:
    findings: List[Finding] = []

    with click.progressbar(
        length=len(AZURE_RULES),
        label=f"Scanning Azure rules in subscription {subscription_id}",
        show_eta=True,
        show_percent=True,
    ) as bar:
        with ThreadPoolExecutor(max_workers=min(4, len(AZURE_RULES))) as executor:
            futures = [
                executor.submit(
                    rule,
                    subscription_id=subscription_id,
                    credential=credential,
                    region_filter=region_filter,
                )
                for rule in AZURE_RULES
            ]

            for future in as_completed(futures):
                try:
                    rule_findings = future.result()
                    findings.extend(rule_findings)
                except Exception as e:
                    # Trust-first: never fail whole scan
                    click.echo(f"⚠️ Azure rule failed in subscription {subscription_id}: {e}")
                finally:
                    advance(bar)

    return findings
