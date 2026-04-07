from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from cleancloud.core.finding import Finding


def _group_findings(findings: List[Finding]) -> List[Dict]:
    """Group findings by title, summing counts and costs."""
    groups: Dict[str, Dict] = defaultdict(lambda: {"count": 0, "cost": 0.0, "has_cost": False})

    for f in findings:
        key = f.title
        groups[key]["count"] += 1
        if f.estimated_monthly_cost_usd is not None:
            groups[key]["cost"] += f.estimated_monthly_cost_usd
            groups[key]["has_cost"] = True

    # Sort by cost descending, then count descending
    return sorted(
        [{"title": k, **v} for k, v in groups.items()],
        key=lambda x: (x["cost"], x["count"]),
        reverse=True,
    )


def write_markdown(
    findings: List[Finding],
    summary: dict,
    output_path: Optional[Path] = None,
) -> Optional[str]:
    lines = []

    provider = summary.get("provider", "").upper()
    scanned_at = summary.get("scanned_at", "")[:10]  # date only

    # Header
    lines.append("## CleanCloud Scan Results")
    lines.append("")

    # Metadata
    regions = summary.get("regions_scanned", [])
    if isinstance(regions, list):
        regions_str = ", ".join(regions) if regions else "—"
    else:
        regions_str = str(regions)

    subscriptions = summary.get("subscriptions_scanned", [])
    accounts_scanned = summary.get("accounts_scanned")

    projects_scanned = summary.get("projects_scanned", [])

    lines.append(f"**Provider:** {provider}  ")
    if subscriptions:
        lines.append(f"**Subscriptions:** {', '.join(subscriptions)}  ")
    elif accounts_scanned is not None:
        lines.append(f"**Accounts:** {accounts_scanned}  ")
        lines.append(f"**Regions:** {regions_str}  ")
    elif projects_scanned:
        lines.append(f"**Projects:** {', '.join(projects_scanned)}  ")
    else:
        lines.append(f"**Regions:** {regions_str}  ")

    lines.append(f"**Scanned:** {scanned_at}  ")

    waste = summary.get("minimum_estimated_monthly_waste_usd")
    if waste and waste > 0:
        lines.append(f"**Estimated monthly waste:** ~${waste:,.0f}  ")

    lines.append("")

    # Findings table
    total = summary.get("total_findings", 0)
    if total == 0:
        lines.append("**No issues detected.**")
    else:
        lines.append(f"**Total findings:** {total}")
        lines.append("")
        lines.append("| Finding | Count | Est. Monthly Cost |")
        lines.append("|---------|------:|------------------:|")

        for group in _group_findings(findings):
            cost_str = f"~${group['cost']:,.0f}" if group["has_cost"] else "—"
            lines.append(f"| {group['title']} | {group['count']} | {cost_str} |")

    lines.append("")

    # Confidence breakdown
    by_conf = summary.get("by_confidence", {})
    if by_conf:
        conf_parts = []
        for level in ["high", "medium", "low"]:
            for k, v in by_conf.items():
                label = k.value if hasattr(k, "value") else str(k)
                if label == level:
                    conf_parts.append(f"{label}: {v}")
        if conf_parts:
            lines.append(f"**Confidence:** {' · '.join(conf_parts)}")
            lines.append("")

    # AWS multi-account breakdown
    per_account = summary.get("per_account")
    if per_account:
        lines.append("**Per-account breakdown:**")
        lines.append("")
        lines.append("| Account | Findings | Est. Monthly Cost |")
        lines.append("|---------|--------:|------------------:|")
        for r in per_account:
            rid = r.get("id", "?")
            rname = r.get("name", rid)
            label = rname if rname != rid else rid
            cost = r.get("estimated_monthly_cost_usd", 0)
            cost_str = f"~${cost:,.0f}" if cost else "—"
            status = r.get("status", "success")
            status_str = f" _{status}_" if status != "success" else ""
            lines.append(f"| {label} ({rid}) | {r.get('findings', 0)}{status_str} | {cost_str} |")
        lines.append("")

    # GCP multi-project breakdown
    per_project = summary.get("per_project")
    if per_project:
        lines.append("**Per-project breakdown:**")
        lines.append("")
        lines.append("| Project | Findings | Est. Monthly Cost |")
        lines.append("|---------|--------:|------------------:|")
        for r in per_project:
            rid = r.get("id", "?")
            rname = r.get("name", rid)
            label = rname if rname != rid else rid
            cost = r.get("estimated_monthly_cost_usd", 0)
            cost_str = f"~${cost:,.0f}" if cost else "—"
            status = r.get("status", "success")
            status_str = f" _{status}_" if status != "success" else ""
            lines.append(f"| {label} ({rid}) | {r.get('findings', 0)}{status_str} | {cost_str} |")
        lines.append("")

    # Azure multi-subscription breakdown
    per_sub = summary.get("per_subscription")
    if per_sub:
        lines.append("**Per-subscription breakdown:**")
        lines.append("")
        lines.append("| Subscription | Findings | Est. Monthly Cost |")
        lines.append("|--------------|--------:|------------------:|")
        for r in per_sub:
            rid = r.get("id", "?")
            rname = r.get("name", rid)
            cost = r.get("estimated_monthly_cost_usd", 0)
            cost_str = f"~${cost:,.0f}" if cost else "—"
            status = r.get("status", "success")
            status_str = f" _{status}_" if status != "success" else ""
            lines.append(f"| {rname} ({rid}) | {r.get('findings', 0)}{status_str} | {cost_str} |")
        lines.append("")

    # Footer
    lines.append(
        "> Generated by [CleanCloud](https://github.com/cleancloud-io/cleancloud) — "
        "read-only cloud cost scanner for AWS, Azure, and GCP."
    )

    output = "\n".join(lines)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output)
        return None
    else:
        return output
