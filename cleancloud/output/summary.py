from collections import Counter
from typing import Dict, List, Optional

import click

from cleancloud.core.finding import Finding, SuppressedFinding


def build_summary(
    findings: List[Finding],
    suppressed_findings: Optional[List[SuppressedFinding]] = None,
    skipped_rules: Optional[List[dict]] = None,
    expired_exception_events: Optional[List[dict]] = None,
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

    if suppressed_findings:
        by_reason = Counter(s.suppression_reason for s in suppressed_findings)
        summary["suppression_summary"] = {
            "total": len(suppressed_findings),
            **{reason: count for reason, count in sorted(by_reason.items())},
        }

    costed = sorted(
        [f for f in findings if f.estimated_monthly_cost_usd],
        key=lambda f: f.estimated_monthly_cost_usd,
        reverse=True,
    )
    if costed:
        summary["top_savings"] = [
            {
                "rule_id": f.rule_id,
                "resource_id": f.resource_id,
                "estimated_monthly_cost_usd": f.estimated_monthly_cost_usd,
            }
            for f in costed[:3]
        ]

    if expired_exception_events:
        summary["exceptions_expired"] = len(expired_exception_events)
        # Include a sample (up to 10) for quick visibility without bloating the summary.
        summary["expired_exceptions_sample"] = expired_exception_events[:10]

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

    all_skipped = summary.get("skipped_rules", [])
    permission_skipped = [s for s in all_skipped if "missing_permissions" in s]
    failed_rules = [s for s in all_skipped if "error" in s]
    total_rules = summary.get("total_rules")
    if all_skipped:
        if total_rules:
            executed = total_rules - len(all_skipped)
            click.echo(f"Rules executed: {executed}/{total_rules}")
        if permission_skipped:
            click.echo(f"Rules skipped:  {len(permission_skipped)} (missing permissions)")
        if failed_rules:
            click.echo(f"Rules failed:   {len(failed_rules)} (errors during scan)")
    click.echo(f"Total findings: {summary['total_findings']}")

    rules_evaluated = summary.get("rules_evaluated", {})
    if rules_evaluated:
        n = len(rules_evaluated)
        if summary["total_findings"] == 0:
            click.echo(f"\nRules evaluated ({n}):")
            max_len = max(len(r) for r in rules_evaluated)
            for rule_id, count in sorted(rules_evaluated.items()):
                click.echo(f"  {rule_id:<{max_len}}  — {count} findings")
        else:
            names = ", ".join(sorted(rules_evaluated.keys()))
            click.echo(f"Rules evaluated: {n}  ({names})")

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

    # Regions/Subscriptions/Projects scanned
    regions_scanned = summary.get("regions_scanned", [])
    if isinstance(regions_scanned, list):
        regions_str = ", ".join(regions_scanned)
    else:
        regions_str = str(regions_scanned)

    provider = summary.get("provider", "aws")

    if provider == "azure":
        # Subscription display is handled below in the unified per_subscription block
        pass
    elif provider == "gcp":
        projects_scanned = summary.get("projects_scanned", [])
        label = "Projects scanned"
        regions_str = ", ".join(projects_scanned) if projects_scanned else regions_str
        click.echo(f"\n{label}: {regions_str}", nl=False)
    else:
        label = "Regions scanned"
        click.echo(f"\n{label}: {regions_str}", nl=False)

    # Selection mode annotations (non-Azure)
    if provider == "gcp":
        mode = summary.get("project_selection_mode", "")
        if mode == "all":
            click.echo(" (all accessible)")
        elif mode == "explicit":
            click.echo(" (explicit)")
        else:
            click.echo()
    elif provider == "aws":
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

    # Top savings
    top_savings = summary.get("top_savings", [])
    if top_savings:
        click.echo("\nTop savings opportunities:")
        for i, item in enumerate(top_savings, 1):
            cost = item["estimated_monthly_cost_usd"]
            click.echo(f"  {i}. ~${cost:,.0f}/mo  {item['rule_id']}  ({item['resource_id']})")

    # Suppression breakdown
    sup_summary = summary.get("suppression_summary", {})
    if sup_summary.get("total", 0) > 0:
        click.echo(f"\nSuppressed by policy: {sup_summary['total']}")
        for reason, count in sup_summary.items():
            if reason == "total":
                continue
            click.echo(f"  {reason}: {count}")

    # Expired exceptions warning
    expired_count = summary.get("exceptions_expired", 0)
    if expired_count:
        click.echo(f"\nWARNING: {expired_count} exception(s) expired and were not applied.")
        click.echo("  Run with --explain to see which findings are now unprotected.")

    click.echo(f"\nScanned at: {summary['scanned_at']}")

    # Skipped rules detail (permission failures)
    if permission_skipped:
        click.echo()
        click.echo("Skipped (missing permissions):")
        for skipped in permission_skipped:
            rule_name = skipped["rule"]
            if rule_name.startswith("find_"):
                rule_name = rule_name[5:]
            missing = skipped.get("missing_permissions", "")
            missing = missing.replace("Missing required IAM permissions: ", "")
            missing = missing.replace("Missing required permissions: ", "")
            click.echo(f"  - {rule_name}")
            if missing:
                click.echo(f"      needs: {missing}")
        click.echo()

    # Failed rules detail (non-permission errors)
    if failed_rules:
        click.echo()
        click.echo("Failed rules (errors during scan):")
        for failed in failed_rules:
            rule_name = failed["rule"]
            if rule_name.startswith("find_"):
                rule_name = rule_name[5:]
            error = failed.get("error", "unknown error")
            click.echo(f"  - {rule_name}: {error}")
        click.echo()

    # Prompt to fix missing permissions
    if permission_skipped:
        has_azure = any("subscription_id" in s for s in permission_skipped)
        has_gcp = any("project_id" in s for s in permission_skipped)
        has_aws = any(
            "subscription_id" not in s and "project_id" not in s for s in permission_skipped
        )

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
                "  Azure: https://github.com/cleancloud-io/cleancloud/tree/main/security/azure/"
            )
            click.echo(
                "  Run 'cleancloud doctor --provider azure' to validate permissions after updating."
            )
        if has_gcp:
            click.echo(
                "  GCP:   https://github.com/cleancloud-io/cleancloud/blob/main/security/gcp/"
            )
            click.echo(
                "  Run 'cleancloud doctor --provider gcp' to validate permissions after updating."
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

    # Azure subscription breakdown (unified — always shown for Azure)
    per_sub = summary.get("per_subscription")
    if provider == "azure" and per_sub is not None:
        failed_subs = summary.get("subscriptions_failed", [])
        mode = summary.get("subscription_selection_mode", "")
        mode_label = {
            "all": " (all accessible)",
            "management-group": " (management group)",
            "explicit": " (explicit)",
        }.get(mode, "")
        ok_subs = [r for r in per_sub if r["status"] != "failed"]
        total_findings = summary["total_findings"]
        n = len(ok_subs)

        if total_findings == 0:
            click.echo(f"\nSubscriptions scanned ({n}){mode_label}:")
            max_name = max((len(r["name"]) for r in ok_subs), default=0)
            for r in ok_subs:
                click.echo(f"  {r['name']:<{max_name}}  ({r['id']})  — {r['findings']} findings")
        else:
            names = ", ".join(r["name"] for r in ok_subs)
            click.echo(f"\nSubscriptions scanned: {n}{mode_label}  ({names})")

        if failed_subs:
            click.echo(f"\nSubscriptions failed: {len(failed_subs)}")
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
        click.echo("No issues detected")
        click.echo()
