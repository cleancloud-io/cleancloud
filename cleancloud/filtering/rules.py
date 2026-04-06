"""
Post-scan filtering pipeline for CleanCloud findings.

Filtering pipeline (apply in this order):
  1. apply_exceptions     — explicit human approvals; bypass ALL other filters
  2. apply_policy_filters — min_cost / confidence / override_risk_level
  3. tag filtering        — resource-scope exclusion (applied in scan/command.py)
  4. Thresholds           — CI/CD exit-code policy (applied in scan/command.py)

# EXCEPTIONS ARE ABSOLUTE
# ========================
# An exception-matched finding is approved by a human and is NEVER re-evaluated
# by any downstream filter (min_cost, confidence, tag rules, thresholds).
# apply_exceptions MUST always run first. apply_policy_filters MUST only receive
# findings that were NOT matched by apply_exceptions. This invariant is enforced
# by the pipeline in scan/command.py and must not be broken by future changes.

apply_policy_filters decision_path includes PASSED_EXCEPTIONS to make the
pipeline stage explicit in JSON output and audit logs.
"""

import difflib
import fnmatch
import functools
import inspect
import sys
from collections import defaultdict
from dataclasses import replace as _dc_replace
from datetime import date as _today_date
from typing import Any, Callable, Dict, List, Optional, Tuple

from cleancloud.config.schema import CleanCloudConfig, DefaultsConfig, RuleConfig
from cleancloud.core.confidence import CONFIDENCE_ORDER
from cleancloud.core.finding import Finding, SuppressedFinding
from cleancloud.core.risk import RiskLevel
from cleancloud.filtering.decision import DecisionStep, SuppressionReason

# Params provided by the scan infrastructure — not user-configurable via policy config.
_INFRA_PARAMS = frozenset(
    {
        "session",
        "credential",
        "credentials",
        "subscription_id",
        "project_id",
        "region_filter",
        "client",
        "monitor_client",
    }
)


def _get_configurable_params(func: Callable) -> Dict[str, Optional[type]]:
    """
    Introspect a rule function and return {param_name: annotation_type} for
    every optional, non-infrastructure parameter.

    These are the params users can set via `rules.<id>.params` in cleancloud.yaml.
    Returns an empty dict if the function cannot be introspected.
    """
    try:
        sig = inspect.signature(func)
    except (ValueError, TypeError):
        return {}

    result: Dict[str, Optional[type]] = {}
    for name, param in sig.parameters.items():
        if name in _INFRA_PARAMS:
            continue
        if param.default is inspect.Parameter.empty:
            continue  # required (infrastructure) positional param
        annotation = param.annotation
        result[name] = None if annotation is inspect.Parameter.empty else annotation
    return result


def _validate_params(rule_id: str, params: Dict[str, Any], func: Callable) -> None:
    """
    Validate that params keys are recognised and values match their annotated type.

    Raises ValueError with a helpful message — including a "did you mean?" hint
    for likely typos — so misconfigured YAML is caught at scan start, not silently
    passed as a bad kwarg at runtime.
    """
    valid = _get_configurable_params(func)
    if not valid:
        # Introspection failed (e.g. C extension, partial without __wrapped__).
        # Silently skipping would mean the user's config is accepted but never applied —
        # which is worse than a warning. Surface it so misconfigured params aren't invisible.
        print(
            f"WARNING: Could not validate params for rule '{rule_id}' — "
            f"rule function is not introspectable. Config params may be ignored.",
            file=sys.stderr,
        )
        return

    for key, value in params.items():
        if key not in valid:
            close = difflib.get_close_matches(key, valid.keys(), n=1, cutoff=0.6)
            hint = f" (did you mean '{close[0]}'?)" if close else f". Valid params: {sorted(valid)}"
            raise ValueError(f"Invalid config: rules.{rule_id}.params.{key} → unknown field{hint}")

        expected_type = valid[key]
        if expected_type is not None and not isinstance(value, expected_type):
            raise ValueError(
                f"Invalid config: rules.{rule_id}.params.{key} → "
                f"expected {expected_type.__name__}, got {type(value).__name__} ({value!r})"
            )


def _validate_rule_ids(cfg: CleanCloudConfig, rule_map: Dict[str, Callable]) -> None:
    """
    Check that rule IDs in the config that share the current provider's prefix
    actually exist in the RULE_MAP.  Cross-provider IDs (e.g. azure.* in an AWS scan)
    are silently ignored — the same config file can cover multiple providers.

    Raises ValueError with a "did you mean?" hint on the first unknown ID found.
    """
    if not rule_map:
        return

    # Infer provider prefix from the first entry in rule_map (e.g. "aws", "azure", "gcp")
    provider_prefix = next(iter(rule_map)).split(".")[0]

    for rule_id in cfg.rules:
        if not rule_id.startswith(provider_prefix + "."):
            continue  # different provider — skip
        if rule_id not in rule_map:
            close = difflib.get_close_matches(rule_id, rule_map.keys(), n=1, cutoff=0.6)
            hint = (
                f" (did you mean '{close[0]}'?)"
                if close
                else f". Valid {provider_prefix} rule IDs: {sorted(rule_map)}"
            )
            raise ValueError(f"Unknown rule ID '{rule_id}' in cleancloud.yaml{hint}")


def _effective_rule_config(rule_id: str, cfg: CleanCloudConfig) -> RuleConfig:
    """
    Return the effective RuleConfig for a rule, merging per-rule settings over defaults.
    Per-rule values always win; defaults fill in unset fields.
    """
    per_rule = cfg.rules.get(rule_id)
    defaults: Optional[DefaultsConfig] = cfg.defaults

    if per_rule is None and defaults is None:
        return RuleConfig()

    if per_rule is None:
        return RuleConfig(
            min_cost=defaults.min_cost if defaults else None,
            confidence=defaults.confidence if defaults else None,
            override_risk_level=defaults.override_risk_level if defaults else None,
        )

    if defaults is None:
        return per_rule

    # Merge: per-rule wins, defaults fill gaps
    return RuleConfig(
        enabled=per_rule.enabled,
        params=per_rule.params,
        min_cost=per_rule.min_cost if per_rule.min_cost is not None else defaults.min_cost,
        confidence=per_rule.confidence if per_rule.confidence is not None else defaults.confidence,
        override_risk_level=(
            per_rule.override_risk_level
            if per_rule.override_risk_level is not None
            else defaults.override_risk_level
        ),
    )


def apply_rule_config(
    rules: List[Callable],
    rule_map: Dict[str, Callable],
    cfg: CleanCloudConfig,
    skip_ids: Optional[List[str]] = None,
) -> Tuple[List[Callable], List[str]]:
    """
    Filter a list of rule functions based on policy config and --skip flags.
    Returns (active_rules, skipped_rule_ids).

    Rules not mentioned in config are included by default (opt-out model).
    --skip takes precedence over config.
    Params from config are validated then bound to rule functions via functools.partial.
    Raises ValueError on unknown rule IDs (for the current provider), or unknown/wrongly-typed params.
    """
    _validate_rule_ids(cfg, rule_map)

    func_to_id = {v: k for k, v in rule_map.items()}
    skip_set = set(skip_ids or [])

    active = []
    skipped = []
    for rule in rules:
        rule_id = func_to_id.get(rule)

        if rule_id and rule_id in skip_set:
            skipped.append(rule_id)
            continue

        if rule_id:
            effective = _effective_rule_config(rule_id, cfg)
            if not effective.enabled:
                skipped.append(rule_id)
                continue
            if effective.params:
                _validate_params(rule_id, effective.params, rule)
                rule = functools.partial(rule, **effective.params)
        else:
            # Rule not in RULE_MAP — include as-is (no config to apply)
            pass

        active.append(rule)

    return active, skipped


def _exception_matches(finding, exc) -> bool:
    """
    Return True if an ExceptionConfig matches the given finding.

    Matching rules (all must pass):
    - rule_id: exact match
    - resource_id: glob pattern via fnmatch (*, ?, [seq]) — e.g. "test-*", "*-staging"
    - account_id: exact match if set; omit to match any account
    - region: exact match if set; omit to match any region
    """
    if exc.rule_id != finding.rule_id:
        return False
    if not fnmatch.fnmatch(finding.resource_id, exc.resource_id):
        return False
    if exc.account_id is not None and finding.account_id != exc.account_id:
        return False
    if exc.region is not None and finding.region != exc.region:
        return False
    return True


def apply_exceptions(
    findings: List[Finding],
    cfg: CleanCloudConfig,
) -> Tuple[List[Finding], List[SuppressedFinding], List[Dict[str, Any]]]:
    """
    Apply exception suppression — the ABSOLUTE first filter in the pipeline.

    Exceptions are human approvals. A matched finding bypasses ALL downstream
    filters without exception: min_cost, confidence, tag rules, and thresholds
    never see it. This is a hard invariant — do not pass exception-matched
    findings to apply_policy_filters or filter_findings_by_tags.

    Matching rules (all must pass):
    - rule_id: exact match
    - resource_id: glob pattern (*, ?, [seq])
    - account_id: exact match if set; omit to match any account
    - region: exact match if set; omit to match any region
    - expires_at: exception is skipped if past this date; the match is recorded
      in expired_events so auditors can see why the exception was not applied.

    Returns (kept_findings, suppressed_list, expired_events).
    - kept_findings: findings not matched by any live exception (proceed in pipeline)
    - suppressed_list: findings matched by a live exception (bypasses all other filters)
    - expired_events: list of {rule_id, resource_id, finding_resource_id, expired_at, reason}
      for exceptions that matched but were past their expires_at date
    """
    today = _today_date.today()
    kept = []
    suppressed_list: List[SuppressedFinding] = []
    expired_events: List[Dict[str, Any]] = []

    # Index exceptions by rule_id so each finding only scans its own candidates —
    # O(findings + exceptions) instead of O(findings × exceptions).
    _exc_index: Dict[str, list] = defaultdict(list)
    for exc in cfg.exceptions:
        _exc_index[exc.rule_id].append(exc)

    for f in findings:
        live_exc = None  # first matching, non-expired exception

        for exc in _exc_index.get(f.rule_id, []):
            if not _exception_matches(f, exc):
                continue

            # This exception matches the finding — now check expiry.
            if exc.expires_at is not None:
                try:
                    expiry = _today_date.fromisoformat(exc.expires_at)
                    if expiry < today:
                        # Always record expired matches — even when a live exception also exists.
                        # Audit trail completeness: "why wasn't exception X applied?" must be
                        # answerable even when exception Y took effect for the same finding.
                        expired_events.append(
                            {
                                "step": DecisionStep.EXCEPTION_EXPIRED,
                                "exception_rule_id": exc.rule_id,
                                "exception_resource_id": exc.resource_id,
                                "expired_at": exc.expires_at,
                                "reason": exc.reason,
                                "finding_rule_id": f.rule_id,
                                "finding_resource_id": f.resource_id,
                            }
                        )
                        continue
                except ValueError:
                    pass  # validated at load time; skip silently

            if live_exc is None:
                live_exc = exc  # first live match wins; keep scanning for expired matches

        if live_exc is not None:
            suppressed_list.append(
                SuppressedFinding(
                    finding=f,
                    suppression_reason=SuppressionReason.EXCEPTION_MATCH,
                    suppression_detail=live_exc.reason or "(no reason given)",
                    decision_path=[
                        DecisionStep.EVALUATED,
                        f"{DecisionStep.EXCEPTION_MATCHED}: {live_exc.rule_id} / {live_exc.resource_id}",
                        DecisionStep.SUPPRESSED,
                    ],
                )
            )
        else:
            kept.append(f)

    return kept, suppressed_list, expired_events


def apply_policy_filters(
    findings: List[Finding],
    cfg: CleanCloudConfig,
) -> Tuple[List[Finding], List[SuppressedFinding]]:
    """
    Apply per-rule policy filters: min_cost, confidence threshold, and override_risk_level.

    This runs AFTER apply_exceptions. Exception-approved findings never reach here.
    The decision_path includes PASSED_EXCEPTIONS to make clear that exception evaluation
    already occurred.

    Returns (kept_findings, suppressed_list).
    """
    kept = []
    suppressed_list: List[SuppressedFinding] = []

    # Precompute effective config once per unique rule_id — avoids repeated dict lookups
    # across N findings that share the same rule.
    unique_rule_ids = {f.rule_id for f in findings}
    effective_configs = {
        rule_id: _effective_rule_config(rule_id, cfg) for rule_id in unique_rule_ids
    }

    for f in findings:
        effective = effective_configs[f.rule_id]

        # ── min_cost — per finding, using estimated_monthly_cost_usd ──────────
        if (
            effective.min_cost is not None
            and f.estimated_monthly_cost_usd is not None
            and f.estimated_monthly_cost_usd < effective.min_cost
        ):
            suppressed_list.append(
                SuppressedFinding(
                    finding=f,
                    suppression_reason=SuppressionReason.BELOW_MIN_COST,
                    suppression_detail=(
                        f"estimated ${f.estimated_monthly_cost_usd:.2f}/mo"
                        f" < min_cost ${effective.min_cost:.2f}"
                    ),
                    decision_path=[
                        DecisionStep.EVALUATED,
                        DecisionStep.PASSED_EXCEPTIONS,
                        f"{DecisionStep.MIN_COST_FILTERED}:"
                        f" ${f.estimated_monthly_cost_usd:.2f}/mo < ${effective.min_cost:.2f}",
                        DecisionStep.SUPPRESSED,
                    ],
                )
            )
            continue

        # ── Confidence filter ─────────────────────────────────────────────────
        if effective.confidence is not None:
            finding_level = CONFIDENCE_ORDER.get(f.confidence.name.upper(), 0)
            min_level = CONFIDENCE_ORDER.get(effective.confidence, 0)
            if finding_level < min_level:
                suppressed_list.append(
                    SuppressedFinding(
                        finding=f,
                        suppression_reason=SuppressionReason.LOW_CONFIDENCE,
                        suppression_detail=(
                            f"confidence {f.confidence.name} below minimum {effective.confidence}"
                        ),
                        decision_path=[
                            DecisionStep.EVALUATED,
                            DecisionStep.PASSED_EXCEPTIONS,
                            f"{DecisionStep.CONFIDENCE_FILTERED}:"
                            f" {f.confidence.name} < {effective.confidence}",
                            DecisionStep.SUPPRESSED,
                        ],
                    )
                )
                continue

        # ── override_risk_level (cosmetic — finding is kept, not suppressed) ──
        # Uses dataclasses.replace() to produce a new object rather than mutating the
        # original. Safe for caching, parallelism, and any future immutable Finding variant.
        if effective.override_risk_level is not None:
            f = _dc_replace(f, risk=RiskLevel[effective.override_risk_level])

        kept.append(f)

    return kept, suppressed_list
