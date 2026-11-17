from __future__ import annotations

"""群组统计的统一口径。

本模块是群组分析（privacy k/l、缺失、撤回）、撤回影响和发布风险三者共同的
计量基础，集中处理三件事：

1. 单位归一：``27.2`` 表示 27.2%，不能按 1.0 截断；比例字段统一落到 [0, 1]。
2. 有效记录：先扣除缺失，再扣除撤回，只有仍然保留的记录才可用于估计区间。
   没有有效记录、参数缺失或撤回量超过观测记录时，区间返回 ``None``，并给出
   原因，不能伪装成确定的观察值。
3. 可解释性：每个估计结果都带 ``*_estimable`` 标志和 ``basis``/``evidence``，
   供发布评审追溯阈值、有效记录和缺失范围。
"""

import math
from collections import defaultdict
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping

from lineage_consent.assets.asset_contract import DomainRecord, normalized_text


def payload_of(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    payload = getattr(value, "payload", None)
    if isinstance(payload, Mapping):
        return payload
    raise TypeError("expected a payload mapping or a record with payload")


def _number(value: Any) -> float | None:
    """Best-effort finite number; malformed or non-finite input is unavailable."""
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        result = float(Decimal(str(value)))
    except (InvalidOperation, ValueError, TypeError):
        return None
    if not math.isfinite(result):
        return None
    return result


def ratio_value(value: Any) -> float | None:
    """Normalise a reported ratio.

    Values in [0, 1] are already ratios.  Values in (1, 100] are percentages and
    are divided by 100.  Anything else is not a usable ratio and returns None so
    callers do not silently clamp it into a misleading observation.
    """
    number = _number(value)
    if number is None or number < 0:
        return None
    if number <= 1.0:
        return number
    if number <= 100.0:
        return number / 100.0
    return None


def count_value(value: Any) -> float | None:
    number = _number(value)
    if number is None or number < 0:
        return None
    return number


def wilson_interval(successes: float | None, total: float | None, z: float = 1.96) -> tuple[float | None, float | None]:
    """Wilson score interval.

    Returns ``(None, None)`` when the interval cannot be estimated (no
    denominator, non-finite input, or successes outside the denominator).  An
    empty sample must not be reported as the certainty interval ``(0, 1)``.
    """
    if successes is None or total is None:
        return None, None
    if not (math.isfinite(successes) and math.isfinite(total)):
        return None, None
    if total <= 0:
        return None, None
    if successes < -1e-9 or successes > total + 1e-9:
        return None, None
    successes = min(max(successes, 0.0), total)
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = z * math.sqrt(proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total)) / denominator
    return max(0.0, min(1.0, center - margin)), max(0.0, min(1.0, center + margin))


def purpose_tokens(payload: Mapping[str, Any]) -> set[str]:
    text = normalized_text(payload.get("licensed_purposes", ""))
    return {token for token in text.replace(";", ",").replace("|", ",").replace(" ", ",").split(",") if token}


def purpose_is_licensed(payload: Mapping[str, Any], requested: Any) -> bool:
    """Shared purpose-scope check for consent, group analysis and release risk."""
    licensed = purpose_tokens(payload)
    if not licensed:
        return False
    purpose = normalized_text(requested)
    if not purpose:
        return True
    return purpose in licensed or "all" in licensed


def effective_record_basis(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Compute the records that can actually support an estimate.

    ``observed_records`` = reported rows minus the missing share.
    ``retained_records`` = observed records minus withdrawn records.
    The raw ``withdrawal_share`` is deliberately not clamped: values above one
    are evidence of inconsistent source data, not a normal 100% withdrawal.
    """
    row_count = count_value(payload.get("row_count"))
    missing = ratio_value(payload.get("missing_rate"))
    withdrawn = count_value(payload.get("revocation_count"))

    reasons: list[str] = []
    if row_count is None or row_count <= 0:
        reasons.append("row_count_unavailable")
    if missing is None:
        reasons.append("missing_rate_unavailable")
    if withdrawn is None:
        reasons.append("revocation_count_unavailable")

    observed = row_count * (1.0 - missing) if row_count is not None and missing is not None else None
    if observed is not None and observed <= 0:
        reasons.append("no_observed_records")
    retained = observed - withdrawn if observed is not None and withdrawn is not None else None
    overflow = retained is not None and retained < -1e-9
    if overflow:
        reasons.append("withdrawals_exceed_observed_records")
    retained = max(0.0, retained) if retained is not None else None
    if retained is not None and retained <= 0:
        reasons.append("no_retained_records")

    if observed is not None and observed > 0 and withdrawn is not None:
        withdrawal_share: float | None = withdrawn / observed
    elif withdrawn == 0 and observed is None:
        withdrawal_share = 0.0
    else:
        withdrawal_share = None
    withdrawal_pressure = (
        None if withdrawal_share is None else min(1.0, max(0.0, withdrawal_share))
    )

    estimable = (
        row_count is not None
        and row_count > 0
        and missing is not None
        and withdrawn is not None
        and observed is not None
        and observed > 0
        and retained is not None
        and retained > 0
    )
    return {
        "row_count": row_count,
        "missing_rate": missing,
        "withdrawn_count": withdrawn,
        "observed_records": observed,
        "retained_records": retained,
        "effective_records": retained,
        "withdrawal_share": withdrawal_share,
        "withdrawal_pressure": withdrawal_pressure,
        "withdrawal_overflow": overflow,
        "estimable": estimable,
        "reasons": tuple(dict.fromkeys(reasons)),
    }


def confusion_counts(value: Any) -> dict[str, Any]:
    """Confusion counts on retained (effective) records, or None when unavailable."""
    payload = payload_of(value)
    basis = effective_record_basis(payload)
    sensitive = ratio_value(payload.get("sensitive_share"))
    privacy_k = ratio_value(payload.get("privacy_k"))
    privacy_l = ratio_value(payload.get("privacy_l"))
    retained = basis["retained_records"]
    reasons = list(basis["reasons"])
    if sensitive is None:
        reasons.append("sensitive_share_unavailable")
    if privacy_k is None:
        reasons.append("privacy_k_unavailable")
    if privacy_l is None:
        reasons.append("privacy_l_unavailable")
    if not basis["estimable"] or sensitive is None or privacy_k is None or privacy_l is None:
        return {"tp": None, "fn": None, "tn": None, "fp": None, "estimable": False,
                "observed_records": basis["observed_records"], "retained_records": retained,
                "reasons": tuple(dict.fromkeys(reasons))}
    positives = retained * sensitive
    negatives = retained - positives
    return {"tp": positives * privacy_k, "fn": positives * (1.0 - privacy_k),
            "tn": negatives * privacy_l, "fp": negatives * (1.0 - privacy_l),
            "estimable": True, "observed_records": basis["observed_records"],
            "retained_records": retained, "reasons": tuple(reasons)}


def _reported(payload: Mapping[str, Any], field: str) -> dict[str, Any]:
    reported = payload.get(field)
    normalized = ratio_value(reported)
    if normalized is None:
        unit = "unknown"
    elif float(reported) > 1.0:
        unit = "percent"
    else:
        unit = "ratio"
    return {"field": field, "reported": reported, "normalized": normalized,
            "unit": unit, "valid": normalized is not None}


def cohort_metrics(value: Any) -> dict[str, Any]:
    """Group metrics on a single shared basis.

    Accepts a payload mapping or a record carrying ``payload``.  Interval keys
    are ``None`` when they cannot be estimated from the available data;
    ``estimable``/``*_estimable`` and ``evidence`` explain why, so consumers do
    not mistake an unavailable interval for a precise observation.
    """
    payload = payload_of(value)
    basis = effective_record_basis(payload)
    counts = confusion_counts(payload)
    sensitive = ratio_value(payload.get("sensitive_share"))
    privacy_k = ratio_value(payload.get("privacy_k"))
    privacy_l = ratio_value(payload.get("privacy_l"))
    missing = basis["missing_rate"]
    retained = basis["retained_records"]

    privacy_k_low = privacy_k_high = None
    privacy_k_basis: dict[str, Any] = {"retained_records": retained, "sensitive_share": sensitive,
                                       "threshold": privacy_k}
    if counts["estimable"]:
        positives = counts["tp"] + counts["fn"]
        privacy_k_low, privacy_k_high = wilson_interval(counts["tp"], positives)
        privacy_k_basis.update({"denominator": positives, "successes": counts["tp"]})
    else:
        privacy_k_basis["reasons"] = tuple(counts["reasons"])
    privacy_k_estimable = privacy_k_low is not None and privacy_k_high is not None

    privacy_l_low = privacy_l_high = None
    privacy_l_basis: dict[str, Any] = {"retained_records": retained, "sensitive_share": sensitive,
                                       "threshold": privacy_l}
    if counts["estimable"]:
        negatives = counts["tn"] + counts["fp"]
        privacy_l_low, privacy_l_high = wilson_interval(counts["tn"], negatives)
        privacy_l_basis.update({"denominator": negatives, "successes": counts["tn"]})
    else:
        privacy_l_basis["reasons"] = tuple(counts["reasons"])
    privacy_l_estimable = privacy_l_low is not None and privacy_l_high is not None

    missing_low = missing_high = None
    missing_basis: dict[str, Any] = {"reported": payload.get("missing_rate"),
                                     "normalized": missing, "row_count": basis["row_count"]}
    if missing is not None and basis["row_count"] is not None and basis["row_count"] > 0:
        missing_low, missing_high = wilson_interval(basis["row_count"] * missing, basis["row_count"])
        missing_basis.update({"denominator": basis["row_count"],
                              "successes": basis["row_count"] * missing})
    missing_estimable = missing_low is not None and missing_high is not None

    evidence = {
        "basis": basis,
        "privacy": {"k": _reported(payload, "privacy_k"), "l": _reported(payload, "privacy_l")},
        "sensitive_share": _reported(payload, "sensitive_share"),
        "privacy_k_basis": privacy_k_basis,
        "privacy_l_basis": privacy_l_basis,
        "missing_basis": missing_basis,
        "reasons": tuple(dict.fromkeys(tuple(basis["reasons"]) + tuple(counts["reasons"]))),
    }
    return {
        "privacy_k_low": privacy_k_low,
        "privacy_k_high": privacy_k_high,
        "privacy_l_low": privacy_l_low,
        "privacy_l_high": privacy_l_high,
        "privacy_k": privacy_k,
        "privacy_l": privacy_l,
        "privacy_k_estimable": privacy_k_estimable,
        "privacy_l_estimable": privacy_l_estimable,
        "interval_estimable": privacy_k_estimable and privacy_l_estimable,
        "missing_rate": missing,
        "missing_low": missing_low,
        "missing_high": missing_high,
        "missing_estimable": missing_estimable,
        "missing_range": (missing_low, missing_high),
        "observed_records": basis["observed_records"],
        "retained_records": retained,
        "effective_records": retained,
        "withdrawal_share": basis["withdrawal_share"],
        "withdrawal_pressure": basis["withdrawal_pressure"],
        "withdrawal_overflow": basis["withdrawal_overflow"],
        "licenses_signal": basis["withdrawal_pressure"],
        "estimable": basis["estimable"] and privacy_k_estimable and privacy_l_estimable,
        "evidence": evidence,
    }


def consent_allows(record: DomainRecord, purpose: str) -> bool:
    return purpose_is_licensed(payload_of(record), purpose)


def stratified_gap(records: Iterable[DomainRecord]) -> dict[str, Any]:
    groups: dict[str, list[float]] = defaultdict(list)
    details: dict[str, dict[str, Any]] = {}
    for record in records:
        group = normalized_text(payload_of(record).get("owner_group", "unknown"))
        metrics = cohort_metrics(record)
        details[group] = {"privacy_k_low": metrics["privacy_k_low"],
                          "privacy_k_high": metrics["privacy_k_high"],
                          "estimable": metrics["privacy_k_estimable"],
                          "reasons": metrics["evidence"]["reasons"]}
        if metrics["privacy_k_low"] is not None:
            groups[group].append(metrics["privacy_k_low"])
    means = {group: sum(values) / len(values) for group, values in groups.items()}
    comparable = len(means) >= 2
    gap = max(means.values()) - min(means.values()) if comparable else 0.0
    return {"group_count": float(len(details)),
            "comparable_group_count": float(len(means)),
            "privacy_k_gap": gap,
            "stability": max(0.0, min(1.0, 1.0 - gap)) if comparable else 0.0,
            "comparable": comparable,
            "groups": details}


def derive_context(record: DomainRecord, repository: Any) -> dict[str, Any]:
    rows = repository.list_records() or [record]
    metrics = cohort_metrics(record)
    gap = stratified_gap(rows)
    consent = 1.0 if consent_allows(record, "validation") else 0.0
    # Unavailable estimates get the conservative end of the range, never the
    # favourable one: a missing privacy interval must not raise a score, and a
    # missing withdrawal figure must not look like zero withdrawals.
    privacy_k_low = metrics["privacy_k_low"] if metrics["privacy_k_low"] is not None else 0.0
    withdrawal_pressure = metrics["withdrawal_pressure"] if metrics["withdrawal_pressure"] is not None else 0.5
    return {
        "cohort_representativeness_weight": 0.6 + gap["stability"] * 0.5,
        "consent_coverage_weight": 0.5 + consent * 0.6,
        "performance_stability_weight": 0.6 + privacy_k_low * 0.5,
        "licenses_signal_weight": 0.8 - withdrawal_pressure * 0.7,
        "transferability_weight": 0.6 + gap["stability"] * 0.5,
        # Record-level estimability drives release evidence.  A single-group
        # batch cannot yield a stratified gap, so non-comparability is reported
        # separately as a caveat rather than making every record unestimable.
        "evidence_estimable": bool(metrics["estimable"]),
        "record_estimable": bool(metrics["estimable"]),
        "stratified_comparable": bool(gap["comparable"]),
        "withdrawal_share": metrics["withdrawal_share"],
        "retained_records": metrics["retained_records"],
        "observed_records": metrics["observed_records"],
        "_cohort_metrics": metrics,
        "_stratified_gap": gap,
    }
