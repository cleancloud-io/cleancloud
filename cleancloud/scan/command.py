import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import botocore.exceptions
import click
import yaml

from cleancloud.config.accounts import (
    MultiAccountConfig,
    load_accounts_config,
    parse_inline_accounts,
)

# ------------------------
# Config + filtering
# ------------------------
from cleancloud.config.schema import (
    CleanCloudConfig,
    IgnoreTagRuleConfig,
    load_config,
)
from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Finding, SuppressedFinding
from cleancloud.filtering.rules import apply_exceptions, apply_policy_filters, apply_rule_config
from cleancloud.filtering.tags import (
    compile_rules,
    filter_findings_by_tags,
)
from cleancloud.output.csv import write_csv
from cleancloud.output.human import print_human
from cleancloud.output.json import write_json
from cleancloud.output.markdown import write_markdown
from cleancloud.output.summary import _print_summary, build_summary
from cleancloud.policy.exit_policy import (
    CONFIDENCE_ORDER,
    EXIT_ERROR,
    EXIT_PERMISSION_ERROR,
    EXIT_POLICY_VIOLATION,
    determine_exit_code,
)
from cleancloud.providers.aws.multi_account import (
    AccountScanResult,
    discover_org_accounts,
    scan_multiple_accounts,
)
from cleancloud.providers.aws.scan import (
    AWS_AI_RULES,
    AWS_RULE_MAP,
    AWS_RULE_MAP_AI,
    AWS_RULES,
    scan_aws_with_region_selection,
)
from cleancloud.providers.azure.scan import (
    AZURE_AI_RULES,
    AZURE_RULE_MAP,
    AZURE_RULE_MAP_AI,
    AZURE_RULES,
    scan_azure_with_region_selection,
)
from cleancloud.providers.gcp.scan import (
    GCP_AI_RULES,
    GCP_RULE_MAP,
    GCP_RULE_MAP_AI,
    GCP_RULES,
    ProjectScanResult,
    scan_gcp_with_project_selection,
)


@click.command("scan")
@click.option(
    "--provider",
    required=False,
    default=None,
    type=click.Choice(["aws", "azure", "gcp"]),
    help="Cloud provider to scan (or set scan.provider in cleancloud.yaml)",
)
@click.option(
    "--region", default=None, help="Specific region to scan (AWS region or Azure location)"
)
@click.option(
    "--all-regions",
    is_flag=True,
    help="Scan all regions with resources (auto-detects active regions)",
)
@click.option(
    "--subscription",
    multiple=True,
    help="Azure subscription ID to scan (can specify multiple times)",
)
@click.option(
    "--all-subscriptions",
    is_flag=True,
    help="Scan all accessible Azure subscriptions (default behavior)",
)
@click.option(
    "--management-group",
    default=None,
    help="Azure Management Group ID — auto-discover all subscriptions underneath (Azure only)",
)
@click.option(
    "--project",
    multiple=True,
    help="GCP project ID to scan (can specify multiple times)",
)
@click.option(
    "--all-projects",
    is_flag=True,
    help="Scan all accessible GCP projects (default behavior for GCP)",
)
@click.option("--profile", default=None, help="AWS CLI profile name")
@click.option(
    "--output",
    default="human",
    type=click.Choice(["human", "json", "csv", "markdown"]),
)
@click.option(
    "--output-file",
    default=None,
    help="Output file path (required for json/csv; optional for markdown — prints to stdout if omitted)",
)
@click.option(
    "--fail-on-findings",
    is_flag=True,
    help="Exit with non-zero code if findings are detected",
)
@click.option(
    "--fail-on-confidence",
    type=click.Choice(["LOW", "MEDIUM", "HIGH"]),
    default=None,
    help="Fail scan if findings at or above this confidence exist",
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Path to cleancloud.yaml (auto-detected in CWD and .cleancloud/config.yaml if not set)",
)
@click.option(
    "--ignore-tag",
    multiple=True,
    help="Ignore findings by tag (key or key:value). Overrides config.",
)
@click.option(
    "--fail-on-cost",
    type=float,
    default=None,
    help="Fail scan if estimated monthly waste exceeds this USD amount",
)
@click.option(
    "--multi-account",
    "multi_account_file",
    type=click.Path(exists=True),
    default=None,
    help="Path to accounts config file for multi-account scanning, e.g. .cleancloud/accounts.yaml (AWS only — GCP uses --all-projects)",
)
@click.option(
    "--accounts",
    "accounts_inline",
    default=None,
    help="Comma-separated AWS account IDs to scan (e.g. 111111111111,222222222222)",
)
@click.option(
    "--org",
    "scan_org",
    is_flag=True,
    default=False,
    help="Auto-discover and scan all accounts in the AWS Organization",
)
@click.option(
    "--role-name",
    default="CleanCloudReadOnlyRole",
    show_default=True,
    help="IAM role name to assume in each target account",
)
@click.option(
    "--external-id",
    default=None,
    help="External ID for cross-account role assumption (if required by trust policy)",
)
@click.option(
    "--timeout",
    default=3600,
    show_default=True,
    help="Total scan timeout in seconds across all accounts (default: 1 hour)",
)
@click.option(
    "--concurrency",
    default=3,
    show_default=True,
    help="Number of accounts to scan in parallel (keep low to avoid AWS API throttling)",
)
@click.option(
    "--per-account-regions",
    is_flag=True,
    default=False,
    help="Detect active regions per account instead of once on the hub (slower but accurate if accounts use different regions)",
)
@click.option(
    "--explain",
    is_flag=True,
    default=False,
    help="Print suppression reasons for each filtered finding (useful for debugging policy config)",
)
@click.option(
    "--no-feedback",
    is_flag=True,
    default=False,
    help="Disable post-scan feedback prompt (recommended for CI/CD runs)",
)
@click.option(
    "--category",
    type=click.Choice(["hygiene", "ai", "all"]),
    default="hygiene",
    show_default=True,
    help="Rule category to run: hygiene (default), ai (AI/ML waste), or all",
)
@click.option(
    "--skip",
    multiple=True,
    metavar="RULE_ID",
    help="Skip a rule by ID (repeatable). e.g. --skip aws.ec2.ami.old --skip aws.resource.untagged",
)
def scan(
    provider: str,
    region: Optional[str],
    all_regions: bool,
    subscription: tuple,
    all_subscriptions: bool,
    management_group: Optional[str],
    project: tuple,
    all_projects: bool,
    profile: Optional[str],
    output: str,
    output_file: Optional[str],
    fail_on_findings: bool,
    fail_on_confidence: Optional[str],
    fail_on_cost: Optional[float],
    config: Optional[str],
    ignore_tag: List[str],
    explain: bool,
    no_feedback: bool,
    category: str,
    skip: tuple,
    multi_account_file: Optional[str],
    accounts_inline: Optional[str],
    scan_org: bool,
    role_name: str,
    external_id: Optional[str],
    timeout: int,
    concurrency: int,
    per_account_regions: bool,
):
    if output in ("json", "csv") and not output_file:
        raise click.UsageError(f"--output-file is required when using --output {output}")

    # Load policy config early — provider/regions may be resolved from it
    cfg = CleanCloudConfig.empty()
    resolved_config = config
    if not resolved_config:
        candidates = [
            "cleancloud.yaml",  # project-level (highest priority)
            str(Path.home() / ".cleancloud.yaml"),  # user-level defaults
            ".cleancloud/config.yaml",  # alternate project location
        ]
        for candidate in candidates:
            if Path(candidate).exists():
                resolved_config = candidate
                break
    if resolved_config:
        try:
            with open(resolved_config) as _f:
                _raw = yaml.safe_load(_f) or {}
            cfg = load_config(_raw)
        except yaml.YAMLError as e:
            click.echo(f"Error parsing {resolved_config}: {e}", err=True)
            sys.exit(EXIT_ERROR)
        except ValueError as e:
            click.echo(f"Error in {resolved_config}: {e}", err=True)
            click.echo("See docs/configuration.md for valid options.", err=True)
            sys.exit(EXIT_ERROR)

    # Resolve provider: CLI flag > scan.provider in config > error
    if provider is None and cfg.scan and cfg.scan.provider:
        provider = cfg.scan.provider
    if provider is None:
        raise click.UsageError("--provider is required (or set scan.provider in cleancloud.yaml)")

    # Resolve regions for AWS: CLI flags > scan.regions in config > error (handled in validate)
    if provider == "aws" and not region and not all_regions and cfg.scan and cfg.scan.regions:
        raw_regions = cfg.scan.regions
        if raw_regions == "auto":
            all_regions = True
        elif isinstance(raw_regions, list):
            if len(raw_regions) == 1:
                region = str(raw_regions[0])
            else:
                click.echo(
                    "Error: scan.regions list with multiple entries is not yet supported. "
                    "Use 'regions: auto' to scan all active regions.",
                    err=True,
                )
                sys.exit(EXIT_ERROR)

    # Cross-provider flag validation — fail fast before any API calls
    _aws_only_flags = {
        "--all-regions": all_regions,
        "--profile": profile is not None,
        "--multi-account": multi_account_file is not None,
        "--accounts": accounts_inline is not None,
        "--org": scan_org,
        "--external-id": external_id is not None,
        "--per-account-regions": per_account_regions,
    }
    _azure_only_flags = {
        "--subscription": bool(subscription),
        "--all-subscriptions": all_subscriptions,
        "--management-group": management_group is not None,
    }
    _gcp_only_flags = {
        "--project": bool(project),
        "--all-projects": all_projects,
    }

    if provider != "aws":
        for flag, used in _aws_only_flags.items():
            if used:
                raise click.UsageError(f"{flag} is only supported with --provider aws")

    if provider != "azure":
        for flag, used in _azure_only_flags.items():
            if used:
                raise click.UsageError(f"{flag} is only supported with --provider azure")

    if provider != "gcp":
        for flag, used in _gcp_only_flags.items():
            if used:
                raise click.UsageError(f"{flag} is only supported with --provider gcp")

    skip_ids = list(skip)

    # Apply YAML categories if --category was not explicitly set (still at default)
    if category == "hygiene" and cfg.categories is not None:
        category = cfg.categories.resolved()

    # Build the AWS rule list based on --category
    if provider == "aws":
        if category == "hygiene":
            aws_rules_to_run = list(AWS_RULES)
        elif category == "ai":
            aws_rules_to_run = list(AWS_AI_RULES)
        else:  # all
            aws_rules_to_run = list(AWS_RULES) + list(AWS_AI_RULES)
        aws_rule_map = {**AWS_RULE_MAP, **AWS_RULE_MAP_AI}
        try:
            aws_rules_to_run, aws_policy_skipped = apply_rule_config(
                aws_rules_to_run, aws_rule_map, cfg, skip_ids
            )
        except ValueError as e:
            click.echo(f"Error in policy config: {e}", err=True)
            click.echo("See docs/configuration.md for valid options.", err=True)
            sys.exit(EXIT_ERROR)
    else:
        aws_rules_to_run = list(AWS_RULES)  # unused for non-AWS but keeps type consistent
        aws_policy_skipped: list = []

    # Build the Azure rule list based on --category
    if provider == "azure":
        if category == "hygiene":
            azure_rules_to_run = list(AZURE_RULES)
        elif category == "ai":
            azure_rules_to_run = list(AZURE_AI_RULES)
        else:  # all
            azure_rules_to_run = list(AZURE_RULES) + list(AZURE_AI_RULES)
        azure_rule_map = {**AZURE_RULE_MAP, **AZURE_RULE_MAP_AI}
        try:
            azure_rules_to_run, azure_policy_skipped = apply_rule_config(
                azure_rules_to_run, azure_rule_map, cfg, skip_ids
            )
        except ValueError as e:
            click.echo(f"Error in policy config: {e}", err=True)
            click.echo("See docs/configuration.md for valid options.", err=True)
            sys.exit(EXIT_ERROR)
    else:
        azure_rules_to_run = list(AZURE_RULES)  # unused for non-Azure but keeps type consistent
        azure_policy_skipped: list = []

    # Build the GCP rule list based on --category
    if provider == "gcp":
        if category == "hygiene":
            gcp_rules_to_run = list(GCP_RULES)
        elif category == "ai":
            gcp_rules_to_run = list(GCP_AI_RULES)
        else:  # all
            gcp_rules_to_run = list(GCP_RULES) + list(GCP_AI_RULES)
        gcp_rule_map = {**GCP_RULE_MAP, **GCP_RULE_MAP_AI}
        try:
            gcp_rules_to_run, gcp_policy_skipped = apply_rule_config(
                gcp_rules_to_run, gcp_rule_map, cfg, skip_ids
            )
        except ValueError as e:
            click.echo(f"Error in policy config: {e}", err=True)
            click.echo("See docs/configuration.md for valid options.", err=True)
            sys.exit(EXIT_ERROR)
    else:
        gcp_rules_to_run = list(GCP_RULES)  # unused for non-GCP but keeps type consistent
        gcp_policy_skipped: list = []

    policy_skipped = aws_policy_skipped + azure_policy_skipped + gcp_policy_skipped

    click.echo()
    click.echo("Starting CleanCloud scan...")
    click.echo()
    click.echo(f"Provider: {provider}")
    if category != "hygiene":
        click.echo(f"Category: {category}")
    if config:
        click.echo(f"Config  : {resolved_config} (--config)")
    elif resolved_config:
        click.echo(f"Config  : {resolved_config} (auto-detected)")
    else:
        click.echo("Config  : none (all rules enabled with defaults)")
    click.echo()

    try:

        findings: List[Finding] = []
        skipped_rules: List[dict] = []
        multi_account_results: List[AccountScanResult] = []

        # Provider-specific metadata
        region_selection_mode = None
        regions_scanned = []
        subscription_selection_mode = None
        subscriptions_scanned = []
        azure_sub_results = []

        # GCP-specific metadata
        project_selection_mode = None
        projects_scanned = []
        gcp_project_results: List[ProjectScanResult] = []

        # Determine if this is a multi-account scan
        is_multi_account = bool(multi_account_file or accounts_inline or scan_org)

        if provider == "aws" and is_multi_account:
            # Build account config from whichever source was provided
            if multi_account_file:
                ma_config = load_accounts_config(multi_account_file)
                # CLI flags override file values
                if role_name != "CleanCloudReadOnlyRole":
                    ma_config.role_name = role_name
                if external_id:
                    ma_config.external_id = external_id
                ma_config.scan_timeout = timeout
            else:
                if scan_org:
                    from cleancloud.providers.aws.session import create_aws_session

                    hub_session = create_aws_session(profile=profile, region=region or "us-east-1")
                    click.echo("Discovering accounts from AWS Organizations...")
                    org_accounts = discover_org_accounts(hub_session)
                    click.echo(f"Found {len(org_accounts)} active accounts")
                    click.echo()
                    ma_config = MultiAccountConfig(
                        accounts=org_accounts,
                        role_name=role_name,
                        external_id=external_id,
                        scan_timeout=timeout,
                    )
                else:
                    ma_config = MultiAccountConfig(
                        accounts=parse_inline_accounts(accounts_inline),
                        role_name=role_name,
                        external_id=external_id,
                        scan_timeout=timeout,
                    )

            multi_account_results = scan_multiple_accounts(
                config=ma_config,
                region=region,
                all_regions=all_regions,
                profile=profile,
                max_concurrent=concurrency,
                per_account_regions=per_account_regions,
                rules=aws_rules_to_run,
            )

            # Aggregate findings and metadata from all accounts
            for result in multi_account_results:
                findings.extend(result.findings)
                for skipped in result.skipped_rules:
                    if not any(s["rule"] == skipped["rule"] for s in skipped_rules):
                        skipped_rules.append(skipped)

            regions_scanned = sorted(
                set(r for res in multi_account_results for r in res.regions_scanned)
            )
            region_selection_mode = "all-regions" if all_regions else "explicit"

        elif provider == "aws":
            region_selection_mode, findings, regions_scanned, skipped_rules = (
                scan_aws_with_region_selection(
                    profile=profile,
                    region=region,
                    all_regions=all_regions,
                    rules=aws_rules_to_run,
                )
            )

        elif provider == "azure":
            subscription_list = list(subscription) if subscription else None
            (
                subscription_selection_mode,
                findings,
                subscriptions_scanned,
                skipped_rules,
                azure_sub_results,
            ) = scan_azure_with_region_selection(
                region=region,
                subscriptions=subscription_list,
                all_subscriptions=all_subscriptions,
                management_group=management_group,
                rules=azure_rules_to_run,
            )
            # Extract unique regions from findings
            regions_scanned = sorted(set(f.region for f in findings if f.region))

        elif provider == "gcp":
            project_list = list(project) if project else None
            (
                project_selection_mode,
                findings,
                projects_scanned,
                skipped_rules,
                gcp_project_results,
            ) = scan_gcp_with_project_selection(
                region=region,
                projects=project_list,
                all_projects=all_projects,
                concurrency=concurrency,
                rules=gcp_rules_to_run,
            )
            # Extract unique regions/zones from findings
            regions_scanned = sorted(set(f.region for f in findings if f.region))

        all_suppressed: List[SuppressedFinding] = []
        all_expired_exception_events: List[dict] = []

        # ── Post-scan filtering pipeline ──────────────────────────────────────────
        # 1. Exceptions       — explicit approvals, bypass all other filters
        # 2. Policy filters   — min_cost / confidence / override_risk_level
        # 3. Tag filtering    — resource-scope exclusion
        # 4. Thresholds       — CI/CD exit-code policy (applied below)

        # 1. Exceptions: suppress by rule_id + resource_id (glob supported).
        findings, exc_suppressed, expired_events = apply_exceptions(findings, cfg)
        all_suppressed.extend(exc_suppressed)
        all_expired_exception_events.extend(expired_events)

        # 2. Policy filters: min_cost, confidence, override_risk_level.
        findings, policy_suppressed = apply_policy_filters(findings, cfg)
        all_suppressed.extend(policy_suppressed)

        # 3. Tag filtering — CLI --ignore-tag overrides config file
        tag_rules = []
        if ignore_tag:
            tag_rules = compile_rules(
                [
                    IgnoreTagRuleConfig(
                        key=item.split(":", 1)[0],
                        values=[item.split(":", 1)[1]] if ":" in item else [],
                    )
                    for item in ignore_tag
                ]
            )
        elif cfg.tag_filtering and cfg.tag_filtering.enabled:
            tag_rules = compile_rules(cfg.tag_filtering.ignore)

        if tag_rules:
            result = filter_findings_by_tags(findings, tag_rules)
            all_suppressed.extend(result.suppressed)
            findings = result.kept

        # Threshold merging — CLI flags take precedence over config
        effective_fail_on_findings = fail_on_findings
        effective_fail_on_confidence = fail_on_confidence
        effective_fail_on_cost = fail_on_cost
        if cfg.thresholds:
            if not effective_fail_on_findings and cfg.thresholds.fail_on_findings:
                effective_fail_on_findings = True
            if effective_fail_on_confidence is None and cfg.thresholds.fail_on_confidence:
                effective_fail_on_confidence = cfg.thresholds.fail_on_confidence
            if effective_fail_on_cost is None and cfg.thresholds.fail_on_cost is not None:
                effective_fail_on_cost = cfg.thresholds.fail_on_cost

        summary = build_summary(
            findings,
            suppressed_findings=all_suppressed,
            skipped_rules=skipped_rules,
            expired_exception_events=all_expired_exception_events or None,
        )
        summary["scanned_at"] = datetime.now(timezone.utc).isoformat()
        summary["regions_scanned"] = regions_scanned
        summary["provider"] = provider
        if policy_skipped:
            summary["rules_skipped_by_policy"] = policy_skipped

        # Multi-account summary fields
        if is_multi_account and multi_account_results:
            succeeded = [r for r in multi_account_results if r.status == "success"]
            partial = [r for r in multi_account_results if r.status == "partial"]
            failed = [r for r in multi_account_results if r.status == "failed"]
            timed_out = [r for r in multi_account_results if r.status == "timeout"]
            summary["accounts_scanned"] = len(succeeded) + len(partial)
            if partial:
                summary["accounts_partial"] = [
                    {"id": r.account_id, "name": r.account_name, "regions_failed": r.regions_failed}
                    for r in partial
                ]
            if failed:
                summary["accounts_failed"] = [
                    {"id": r.account_id, "name": r.account_name, "error": r.error} for r in failed
                ]
            if timed_out:
                summary["accounts_timed_out"] = [
                    {"id": r.account_id, "name": r.account_name} for r in timed_out
                ]
            summary["per_account"] = [
                {
                    "id": r.account_id,
                    "name": r.account_name,
                    "findings": len(r.findings),
                    "status": r.status,
                    "regions_failed": r.regions_failed,
                    "estimated_monthly_cost_usd": (
                        round(
                            sum(
                                f.estimated_monthly_cost_usd
                                for f in r.findings
                                if f.estimated_monthly_cost_usd
                            ),
                            2,
                        )
                        if r.findings
                        else 0
                    ),
                }
                for r in sorted(multi_account_results, key=lambda r: r.account_name)
            ]

        # Add provider-specific fields
        if provider == "aws":
            summary["region_selection_mode"] = region_selection_mode
            summary["total_rules"] = len(aws_rules_to_run)
        elif provider == "azure":
            summary["total_rules"] = len(azure_rules_to_run)
            summary["subscription_selection_mode"] = subscription_selection_mode
            summary["subscriptions_scanned"] = subscriptions_scanned
            failed_subs = [r for r in azure_sub_results if r.status == "failed"]
            if failed_subs:
                summary["subscriptions_failed"] = [
                    {"id": r.subscription_id, "name": r.subscription_name, "error": r.error}
                    for r in failed_subs
                ]
            summary["per_subscription"] = [
                {
                    "id": r.subscription_id,
                    "name": r.subscription_name,
                    "status": r.status,
                    "findings": len(r.findings),
                    "estimated_monthly_cost_usd": round(r.estimated_monthly_cost, 2),
                }
                for r in sorted(azure_sub_results, key=lambda r: r.subscription_name)
            ]
        elif provider == "gcp":
            summary["total_rules"] = len(gcp_rules_to_run)
            summary["project_selection_mode"] = project_selection_mode
            summary["projects_scanned"] = projects_scanned
            failed_projects = [r for r in gcp_project_results if r.status == "failed"]
            if failed_projects:
                summary["projects_failed"] = [
                    {"id": r.project_id, "name": r.project_name, "error": r.error}
                    for r in failed_projects
                ]
            if len(gcp_project_results) > 1:
                summary["per_project"] = [
                    {
                        "id": r.project_id,
                        "name": r.project_name,
                        "status": r.status,
                        "findings": len(r.findings),
                        "rules_succeeded": r.rules_succeeded,
                        "rules_skipped": r.rules_skipped,
                        "rules_failed": r.rules_failed,
                        "estimated_monthly_cost_usd": r.estimated_monthly_cost,
                    }
                    for r in sorted(gcp_project_results, key=lambda r: r.project_name)
                ]
        # Build rules_evaluated: {rule_id: finding_count} for all rules that ran
        if provider == "aws":
            _active_rule_map = {v: k for k, v in aws_rule_map.items() if v in aws_rules_to_run}
        elif provider == "azure":
            _active_rule_map = {v: k for k, v in azure_rule_map.items() if v in azure_rules_to_run}
        else:
            _active_rule_map = {v: k for k, v in gcp_rule_map.items() if v in gcp_rules_to_run}
        _findings_by_rule = Counter(f.rule_id for f in findings)
        summary["rules_evaluated"] = {
            rule_id: _findings_by_rule.get(rule_id, 0)
            for rule_id in sorted(_active_rule_map.values())
        }

        summary["highest_confidence"] = max(
            (f.confidence for f in findings),
            default=None,
            key=lambda c: CONFIDENCE_ORDER.get(c.name, 0),
        )
        summary["high_conf_findings"] = len(
            [f for f in findings if f.confidence == ConfidenceLevel.HIGH]
        )

        output_path = Path(output_file) if output_file else None

        if output == "json":
            json_payload: dict = {
                "schema_version": "1.3.0",
                "summary": summary,
                "findings": findings,
                "suppressed": [s.to_dict() for s in all_suppressed],
            }
            if all_expired_exception_events:
                json_payload["expired_exception_events"] = all_expired_exception_events
            write_json(json_payload, output_path)
            click.echo(f"JSON output written to {output_path}")
            click.echo()

        elif output == "csv":
            write_csv(findings, output_path)
            click.echo(f"CSV output written to {output_path}")
            click.echo()

        elif output == "markdown":
            result = write_markdown(findings, summary, output_path)
            if result is not None:
                click.echo(result)
            else:
                click.echo(f"Markdown output written to {output_path}")
            click.echo()

        else:
            print_human(findings)
            _print_summary(summary, region_selection_mode, multi_account_results or None)
            if explain and all_suppressed:
                click.echo("\n--- Suppressed Findings (--explain) ---")
                for s in all_suppressed:
                    click.echo(
                        f"\n  {s.finding.rule_id} / {s.finding.resource_id}"
                        f"  [{s.suppression_reason}]"
                    )
                    click.echo(f"  Detail: {s.suppression_detail}")
                    click.echo(f"  Path:   {' → '.join(s.decision_path)}")
                click.echo()
            if explain and all_expired_exception_events:
                click.echo("\n--- Expired Exceptions (--explain) ---")
                for ev in all_expired_exception_events:
                    click.echo(
                        f"\n  {ev['exception_rule_id']} / {ev['exception_resource_id']}"
                        f"  [expired {ev['expired_at']}]"
                    )
                    click.echo(f"  Finding:  {ev['finding_rule_id']} / {ev['finding_resource_id']}")
                    if ev.get("reason"):
                        click.echo(f"  Reason:   {ev['reason']}")
                click.echo()
            if not resolved_config:
                click.echo(
                    "Tip: Add a cleancloud.yaml to suppress findings, set cost thresholds,"
                    " or disable specific rules. See docs/configuration.md"
                )
                click.echo()

            if category == "hygiene":
                if provider == "aws":
                    ai_count = len(AWS_AI_RULES)
                    click.echo(
                        f"Tip: {ai_count} AI/ML rule{'s' if ai_count != 1 else ''} available"
                        f" — cleancloud scan --provider aws --category ai"
                        f" (idle SageMaker endpoints)"
                    )
                    click.echo()
                elif provider == "azure":
                    ai_count = len(AZURE_AI_RULES)
                    click.echo(
                        f"Tip: {ai_count} AI/ML rule{'s' if ai_count != 1 else ''} available"
                        f" — cleancloud scan --provider azure --category ai"
                        f" (idle AML compute clusters and Compute Instances)"
                    )
                    click.echo()
                elif provider == "gcp":
                    ai_count = len(GCP_AI_RULES)
                    click.echo(
                        f"Tip: {ai_count} AI/ML rule{'s' if ai_count != 1 else ''} available"
                        f" — cleancloud scan --provider gcp --category ai"
                        f" (idle Vertex AI endpoints)"
                    )
                    click.echo()

        # Community prompt (all output modes)
        click.echo()
        click.echo(
            "Share your findings: "
            "https://github.com/cleancloud-io/cleancloud/issues/new?template=share_findings.md"
        )
        click.echo(
            "Report a bug: "
            "https://github.com/cleancloud-io/cleancloud/issues/new?template=bug_report.md"
        )
        click.echo()

        # ========================
        # Exit policy
        # ========================

        exit_code = determine_exit_code(
            findings,
            fail_on_findings=effective_fail_on_findings,
            fail_on_confidence=effective_fail_on_confidence,
            fail_on_cost=effective_fail_on_cost,
        )

        if exit_code == EXIT_POLICY_VIOLATION:
            click.echo("\nCleanCloud policy violation detected")

        sys.exit(exit_code)

    except PermissionError as e:
        click.echo(f"Permission error: {e}")
        sys.exit(EXIT_PERMISSION_ERROR)

    except EnvironmentError as e:
        # Raised by create_azure_session() or create_gcp_session() when auth fails
        click.echo()
        click.echo(f"Authentication failed — {e}")
        click.echo()
        if provider == "gcp":
            click.echo("Run `cleancloud doctor --provider gcp` to diagnose.")
        else:
            click.echo("Run `cleancloud doctor --provider azure` to diagnose.")
        sys.exit(EXIT_PERMISSION_ERROR)

    except botocore.exceptions.NoCredentialsError:
        click.echo()
        click.echo("Authentication failed — no AWS credentials found.")
        click.echo()
        click.echo("Configure credentials using one of:")
        click.echo("  - AWS CloudShell: credentials are injected from your portal session")
        click.echo("  - Local AWS CLI:  run `aws configure` or set AWS_PROFILE")
        click.echo("  - CI/CD (OIDC):   see docs/aws.md for OIDC role setup")
        click.echo("  - Environment:    set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY")
        click.echo()
        click.echo("Run `cleancloud doctor --provider aws` to diagnose.")
        sys.exit(EXIT_PERMISSION_ERROR)

    except Exception as e:
        click.echo()
        click.echo(f"Unexpected error: {type(e).__name__}: {e}")
        click.echo()
        click.echo("This may be a bug. Please report it:")
        click.echo("  https://github.com/cleancloud-io/cleancloud/issues/new")
        if __import__("os").environ.get("CLEANCLOUD_DEBUG"):
            import traceback

            traceback.print_exc()
        sys.exit(EXIT_ERROR)
