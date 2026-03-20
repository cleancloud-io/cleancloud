import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import List, Optional

import botocore.exceptions
import click

from cleancloud.config.accounts import AccountConfig, MultiAccountConfig
from cleancloud.core.finding import Finding
from cleancloud.providers.aws.scan import (
    _get_active_aws_regions,
    scan_aws_regions_with_session,
)
from cleancloud.providers.aws.session import BOTO_CONFIG, assume_role, create_aws_session


@dataclass
class AccountScanResult:
    account_id: str
    account_name: str
    findings: List[Finding] = field(default_factory=list)
    skipped_rules: List[dict] = field(default_factory=list)
    regions_scanned: List[str] = field(default_factory=list)
    status: str = "success"  # success | partial | failed | timeout
    regions_failed: List[str] = field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: float = 0.0


def scan_account(
    profile: Optional[str],
    account: AccountConfig,
    role_name: str,
    region: Optional[str],
    external_id: Optional[str],
    regions_override: Optional[List[str]] = None,
) -> AccountScanResult:
    start = time.monotonic()
    click.echo(f"  {account.name} ({account.id}) starting...")

    try:
        # Create a fresh session per thread — boto3 sessions are not thread-safe.
        session = create_aws_session(profile=profile, region=region or "us-east-1")
        assumed_session = assume_role(
            session=session,
            account_id=account.id,
            role_name=role_name,
            region=region or "us-east-1",
            external_id=external_id,
        )

        if regions_override:
            # Regions pre-discovered on hub — skip per-account discovery
            regions_to_scan = regions_override
        elif region:
            regions_to_scan = [region]
        else:
            # Per-account discovery (opt-in via --per-account-regions)
            regions_to_scan = _get_active_aws_regions(assumed_session) or ["us-east-1"]
            click.echo(
                f"  {account.name}: {len(regions_to_scan)} active region(s): {', '.join(regions_to_scan)}"
            )

        findings, skipped_rules, regions_failed = scan_aws_regions_with_session(
            assumed_session, regions_to_scan
        )

        for f in findings:
            f.account_id = account.id
            f.account_name = account.name

        duration = time.monotonic() - start

        if not regions_failed:
            status = "success"
        elif len(regions_failed) < len(regions_to_scan):
            status = "partial"
        else:
            status = "failed"

        return AccountScanResult(
            account_id=account.id,
            account_name=account.name,
            findings=findings,
            skipped_rules=skipped_rules,
            regions_scanned=regions_to_scan,
            regions_failed=regions_failed,
            status=status,
            duration_seconds=duration,
        )

    except botocore.exceptions.ClientError as e:
        duration = time.monotonic() - start
        code = e.response["Error"]["Code"]
        error_msg = f"{code}: {e.response['Error']['Message']}"
        return AccountScanResult(
            account_id=account.id,
            account_name=account.name,
            status="failed",
            error=error_msg,
            duration_seconds=duration,
        )

    except Exception as e:
        duration = time.monotonic() - start
        error_msg = str(e)
        return AccountScanResult(
            account_id=account.id,
            account_name=account.name,
            status="failed",
            error=error_msg,
            duration_seconds=duration,
        )


def scan_multiple_accounts(
    config: MultiAccountConfig,
    region: Optional[str],
    all_regions: bool,
    profile: Optional[str],
    max_concurrent: int = 5,
    per_account_regions: bool = False,
) -> List[AccountScanResult]:
    hub_session = create_aws_session(profile=profile, region=region or "us-east-1")

    # Pre-flight: verify hub credentials before spawning threads
    hub_session.client("sts", config=BOTO_CONFIG).get_caller_identity()

    # Discover active regions once on the hub account and reuse across all spokes.
    # This avoids N × 20 × 8 API calls for region probing in large orgs.
    # Use --per-account-regions if spoke accounts genuinely differ in active regions.
    regions_override: Optional[List[str]] = None
    if all_regions and not per_account_regions:
        click.echo("Detecting active regions (hub account)...")
        regions_override = _get_active_aws_regions(hub_session) or ["us-east-1"]
        click.echo(f"Regions to scan: {', '.join(regions_override)}")
        click.echo()

    click.echo(
        f"Scanning {len(config.accounts)} accounts"
        f" (role: {config.role_name}"
        f"{f', external_id: {config.external_id}' if config.external_id else ''})..."
    )
    click.echo()

    results: List[AccountScanResult] = []
    workers = min(max_concurrent, len(config.accounts))
    total = len(config.accounts)
    completed = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_account = {
            executor.submit(
                scan_account,
                profile,
                account,
                config.role_name,
                region,
                config.external_id,
                regions_override,
            ): account
            for account in config.accounts
        }

        # All accounts start simultaneously — use a global wall-clock deadline.
        # as_completed + future.result(timeout=X) is ineffective because
        # as_completed only yields already-done futures. wait() with a deadline
        # actually enforces the timeout for hung threads.
        deadline = time.monotonic() + config.scan_timeout
        pending = set(future_to_account.keys())

        while pending:
            remaining = max(0.1, deadline - time.monotonic())
            done, pending = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)

            for future in done:
                account = future_to_account[future]
                completed += 1
                try:
                    result = future.result()
                    results.append(result)
                    status = f"[{completed}/{total}] done    {account.name} ({account.id}) — {result.duration_seconds:.1f}s, {len(result.findings)} findings"
                except Exception as e:
                    status = f"[{completed}/{total}] failed  {account.name} ({account.id}) — {e}"
                    results.append(
                        AccountScanResult(
                            account_id=account.id,
                            account_name=account.name,
                            status="failed",
                            error=str(e),
                        )
                    )
                click.echo(status)

            # Deadline expired — mark all remaining as timed out
            if pending and time.monotonic() >= deadline:
                for future in pending:
                    account = future_to_account[future]
                    completed += 1
                    status = f"[{completed}/{total}] timeout {account.name} ({account.id}) — exceeded {config.scan_timeout}s"
                    results.append(
                        AccountScanResult(
                            account_id=account.id,
                            account_name=account.name,
                            status="timeout",
                            error=f"Exceeded {config.scan_timeout}s timeout",
                            duration_seconds=float(config.scan_timeout),
                        )
                    )
                    click.echo(status)
                executor.shutdown(wait=False, cancel_futures=True)
                break

    return results


def discover_org_accounts(hub_session) -> List[AccountConfig]:
    """Auto-discover all ACTIVE accounts in the AWS Organization."""
    orgs = hub_session.client("organizations", config=BOTO_CONFIG)
    accounts = []

    try:
        paginator = orgs.get_paginator("list_accounts")
        for page in paginator.paginate():
            for account in page["Accounts"]:
                if account["Status"] == "ACTIVE":
                    accounts.append(
                        AccountConfig(
                            id=account["Id"],
                            name=account.get("Name", account["Id"]),
                        )
                    )
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AccessDeniedException":
            raise PermissionError(
                "organizations:ListAccounts permission required for --org. "
                "Add it to the hub account role."
            )
        raise

    if not accounts:
        raise ValueError("No active accounts found in the AWS Organization")

    return accounts
