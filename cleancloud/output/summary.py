from collections import Counter
from typing import Dict, List, Optional

import click

from cleancloud.core.finding import Finding


def build_summary(
    findings: List[Finding], skipped_rules: Optional[List[dict]] = None
) -> Dict[str, object]:
    by_provider = Counter(f.provider for f in findings)
    by_risk = Counter(f.risk for f in findings)
    by_confidence = Counter(f.confidence for f in findings)

    costed_findings = [f for f in findings if f.estimated_monthly_cost_usd is not None]
    total_cost = sum(f.estimated_monthly_cost_usd for f in costed_findings)

    summary: Dict[str, object] = {
        "total_findings": len(findings),
        "by_provider": dict(by_provider),
        "by_risk": dict(by_risk),
        "by_confidence": dict(by_confidence),
    }

    if total_cost > 0:
        summary["minimum_estimated_monthly_waste_usd"] = round(total_cost, 2)
        summary["findings_with_cost_estimate"] = len(costed_findings)

    if skipped_rules:
        summary["skipped_rules"] = skipped_rules

    return summary


def _format_enum_counts(data: dict) -> dict[str, int]:
    result = {}
    for key, value in data.items():
        if hasattr(key, "value"):
            result[key.value] = value
        else:
            result[str(key)] = value
    return result


def _print_summary(summary: dict, region_selection_mode: str = None, multi_account_results=None):
    click.echo("\n--- Scan Summary ---")

    skipped_rules = summary.get("skipped_rules", [])
    total_rules = summary.get("total_rules")
    if skipped_rules:
        if total_rules:
            executed = total_rules - len(skipped_rules)
            click.echo(f"Rules executed: {executed}/{total_rules}")
        click.echo(f"Rules skipped:  {len(skipped_rules)} (missing permissions)")
    click.echo(f"Total findings: {summary['total_findings']}")

    # By risk
    by_risk = _format_enum_counts(summary.get("by_risk", {}))
    if by_risk:
        click.echo("\nBy risk:")
        for risk in sorted(by_risk):
            click.echo(f"  {risk}: {by_risk[risk]}")

    # By confidence
    by_conf = _format_enum_counts(summary.get("by_confidence", {}))
    if by_conf:
        click.echo("\nBy confidence:")
        for conf in sorted(by_conf):
            click.echo(f"  {conf}: {by_conf[conf]}")

    # Regions/Subscriptions scanned
    regions_scanned = summary.get("regions_scanned", [])
    if isinstance(regions_scanned, list):
        regions_str = ", ".join(regions_scanned)
    else:
        regions_str = str(regions_scanned)

    # Use provider-aware label
    provider = summary.get("provider", "aws")
    if provider == "azure":
        subscriptions_scanned = summary.get("subscriptions_scanned", [])
        label = "Subscriptions scanned"
        regions_str = ", ".join(subscriptions_scanned) if subscriptions_scanned else regions_str
    elif provider == "gcp":
        projects_scanned = summary.get("projects_scanned", [])
        label = "Projects scanned"
        regions_str = ", ".join(projects_scanned) if projects_scanned else regions_str
    else:
        label = "Regions scanned"

    click.echo(f"\n{label}: {regions_str}", nl=False)

    # Selection mode annotations
    if provider == "azure":
        mode = summary.get("subscription_selection_mode", "")
        if mode == "all":
            click.echo(" (all accessible)")
        elif mode == "management-group":
            click.echo(" (management group)")
        elif mode == "explicit":
            click.echo(" (explicit)")
        else:
            click.echo()
    elif provider == "gcp":
        mode = summary.get("project_selection_mode", "")
        if mode == "all":
            click.echo(" (all accessible)")
        elif mode == "explicit":
            click.echo(" (explicit)")
        else:
            click.echo()
    else:  # AWS
        if region_selection_mode == "all-regions":
            click.echo(" (auto-detected)")
        elif region_selection_mode == "explicit":
            click.echo(" (explicit)")
        else:
            click.echo()

    # Estimated monthly waste
    waste = summary.get("minimum_estimated_monthly_waste_usd")
    if waste and waste > 0:
        costed = summary.get("findings_with_cost_estimate", 0)
        total = summary.get("total_findings", 0)
        click.echo(f"\nMinimum estimated waste: ~${waste:,.0f}/month")
        click.echo(f"({costed} of {total} findings costed)")

    click.echo(f"Scanned at: {summary['scanned_at']}")

    # Tag filtering visibility
    if summary.get("ignored_by_tag_policy", 0) > 0:
        click.echo(f"Ignored by tag policy: {summary['ignored_by_tag_policy']}")

    # Skipped rules detail
    if skipped_rules:
        click.echo()
        click.echo("Skipped (missing permissions):")
        for skipped in skipped_rules:
            rule_name = skipped["rule"]
            if rule_name.startswith("find_"):
                rule_name = rule_name[5:]
            missing = skipped.get("missing_permissions", "")
            # Strip verbose prefix if present
            missing = missing.replace("Missing required IAM permissions: ", "")
            click.echo(f"  - {rule_name}")
            if missing:
                click.echo(f"      needs: {missing}")
        click.echo()
        # Detect which providers have skipped rules by their provider-specific keys
        has_azure = any("subscription_id" in s for s in skipped_rules)
        has_gcp = any("project_id" in s for s in skipped_rules)
        has_aws = any("subscription_id" not in s and "project_id" not in s for s in skipped_rules)

        click.echo("To enable skipped rules, update your IAM policy/role to the latest version:")
        if has_aws:
            click.echo(
                "  AWS:   https://github.com/cleancloud-io/cleancloud/tree/main/security/aws/"
            )
            click.echo(
                "  Run 'cleancloud doctor --provider aws' to validate permissions after updating."
            )
        if has_azure:
            click.echo(
                "  Azure: https://github.com/cleancloud-io/cleancloud/blob/main/security/azure-readonly-role.json"
            )
            click.echo(
                "  Run 'cleancloud doctor --provider azure' to validate permissions after updating."
            )
        if has_gcp:
            click.echo(
                "  GCP:   https://github.com/cleancloud-io/cleancloud/blob/main/security/gcp-readonly-roles.json"
            )
            click.echo(
                "  Run 'cleancloud doctor --provider gcp --project PROJECT_ID' to validate permissions after updating."
            )

    # Multi-account breakdown
    if multi_account_results:
        succeeded = [r for r in multi_account_results if r.status == "success"]
        partial = [r for r in multi_account_results if r.status == "partial"]
        failed = [r for r in multi_account_results if r.status == "failed"]
        timed_out = [r for r in multi_account_results if r.status == "timeout"]

        click.echo()
        click.echo(f"Accounts scanned:   {len(succeeded):>3}")
        if partial:
            click.echo(f"Accounts partial:   {len(partial):>3}  (some regions failed)")
        if failed:
            click.echo(f"Accounts failed:    {len(failed):>3}")
        if timed_out:
            click.echo(f"Accounts timed out: {len(timed_out):>3}")

        complete = succeeded + partial
        if complete:
            click.echo()
            click.echo("Per-account breakdown:")
            for r in sorted(complete, key=lambda x: x.account_name):
                cost = sum(
                    f.estimated_monthly_cost_usd for f in r.findings if f.estimated_monthly_cost_usd
                )
                cost_str = f"  ~${cost:,.0f}/month" if cost else ""
                label = r.account_name if r.account_name != r.account_id else r.account_id
                partial_note = (
                    f"  [{len(r.regions_failed)} region(s) failed]" if r.regions_failed else ""
                )
                click.echo(
                    f"  {label:<20} ({r.account_id}):"
                    f"  {len(r.findings)} findings{cost_str}{partial_note}"
                )

        if failed:
            click.echo()
            click.echo("Failed accounts:")
            for r in failed:
                click.echo(f"  [failed] {r.account_name} ({r.account_id}): {r.error}")

        if timed_out:
            click.echo()
            click.echo("Timed out accounts:")
            for r in timed_out:
                click.echo(f"  [timeout] {r.account_name} ({r.account_id})")

    # Azure multi-subscription breakdown
    per_sub = summary.get("per_subscription")
    if per_sub:
        failed_subs = summary.get("subscriptions_failed", [])
        click.echo()
        click.echo(f"Subscriptions scanned: {len(per_sub) - len(failed_subs)}")
        if failed_subs:
            click.echo(f"Subscriptions failed:  {len(failed_subs)}")
        click.echo()
        click.echo("Per-subscription breakdown:")
        for r in per_sub:
            cost = r.get("estimated_monthly_cost_usd", 0)
            cost_str = f"  ~${cost:,.0f}/month" if cost else ""
            status = "" if r["status"] == "success" else f"  [{r['status']}]"
            click.echo(
                f"  {r['name']:<30} ({r['id']}):" f"  {r['findings']} findings{cost_str}{status}"
            )
        if failed_subs:
            click.echo()
            click.echo("Failed subscriptions:")
            for r in failed_subs:
                click.echo(f"  [failed] {r['name']} ({r['id']}): {r.get('error', '')}")

    # GCP multi-project breakdown
    per_project = summary.get("per_project")
    if per_project:
        failed_projects = summary.get("projects_failed", [])
        click.echo()
        click.echo(f"Projects scanned: {len(per_project) - len(failed_projects)}")
        if failed_projects:
            click.echo(f"Projects failed:  {len(failed_projects)}")
        click.echo()
        click.echo("Per-project breakdown:")
        for r in per_project:
            cost = r.get("estimated_monthly_cost_usd", 0)
            cost_str = f"  ~${cost:,.0f}/month" if cost else ""
            status = "" if r["status"] == "success" else f"  [{r['status']}]"
            skipped = r.get("rules_skipped", 0)
            skipped_str = f"  ({skipped} rule(s) skipped)" if skipped else ""
            click.echo(
                f"  {r['name']:<30} ({r['id']}):"
                f"  {r['findings']} findings{cost_str}{status}{skipped_str}"
            )
        if failed_projects:
            click.echo()
            click.echo("Failed projects:")
            for r in failed_projects:
                click.echo(f"  [failed] {r['name']} ({r['id']}): {r.get('error', '')}")

    # Success message
    if summary["total_findings"] == 0:
        click.echo()
        click.echo("No hygiene issues detected")
        click.echo()
