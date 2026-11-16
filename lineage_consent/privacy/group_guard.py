from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Iterable

from lineage_consent.assets.asset_contract import DomainRecord, bounded, finite_number, normalized_text


def confusion_counts(record: DomainRecord) -> dict[str, float]:
    size = max(1.0, finite_number(record.payload.get("row_count", 1.0)))
    prevalence = bounded(finite_number(record.payload.get("sensitive_share", 0.0)))
    privacy_k = bounded(finite_number(record.payload.get("privacy_k", 0.0)))
    privacy_l = bounded(finite_number(record.payload.get("privacy_l", 0.0)))
    positives = size * prevalence
    negatives = size - positives
    return {"tp": positives * privacy_k, "fn": positives * (1.0 - privacy_k),
            "tn": negatives * privacy_l, "fp": negatives * (1.0 - privacy_l)}


def wilson_interval(successes: float, total: float, z: float = 1.96) -> tuple[float, float]:
    if total <= 0:
        return 0.0, 1.0
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = z * math.sqrt(proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total)) / denominator
    return bounded(center - margin), bounded(center + margin)


def cohort_metrics(record: DomainRecord) -> dict[str, float]:
    counts = confusion_counts(record)
    privacy_k_interval = wilson_interval(counts["tp"], counts["tp"] + counts["fn"])
    privacy_l_interval = wilson_interval(counts["tn"], counts["tn"] + counts["fp"])
    missing = bounded(finite_number(record.payload.get("missing_rate", 0.0)))
    adverse = max(0.0, finite_number(record.payload.get("revocation_count", 0.0)))
    return {"privacy_k_low": privacy_k_interval[0], "privacy_k_high": privacy_k_interval[1],
            "privacy_l_low": privacy_l_interval[0], "privacy_l_high": privacy_l_interval[1],
            "missing_rate": missing, "licenses_signal": bounded(adverse / max(1.0, sum(counts.values())))}


def consent_allows(record: DomainRecord, purpose: str) -> bool:
    scopes = {item.strip() for item in normalized_text(record.payload.get("licensed_purposes", "")).replace(";", ",").split(",") if item.strip()}
    return purpose in scopes or "all" in scopes


def stratified_gap(records: Iterable[DomainRecord]) -> dict[str, float]:
    groups: dict[str, list[float]] = defaultdict(list)
    for record in records:
        group = normalized_text(record.payload.get("owner_group", "unknown"))
        groups[group].append(cohort_metrics(record)["privacy_k_low"])
    means = {group: sum(values) / len(values) for group, values in groups.items()}
    gap = max(means.values()) - min(means.values()) if means else 0.0
    return {"group_count": float(len(means)), "privacy_k_gap": gap, "stability": bounded(1.0 - gap)}


def derive_context(record: DomainRecord, repository: Any) -> dict[str, float]:
    rows = repository.list_records() or [record]
    metrics = cohort_metrics(record)
    gap = stratified_gap(rows)
    consent = 1.0 if consent_allows(record, "validation") else 0.0
    return {"cohort_representativeness_weight": 0.6 + gap["stability"] * 0.5,
            "consent_coverage_weight": 0.5 + consent * 0.6,
            "performance_stability_weight": 0.6 + metrics["privacy_k_low"] * 0.5,
            "licenses_signal_weight": 0.8 + metrics["licenses_signal"] * 0.7,
            "transferability_weight": 0.6 + gap["stability"] * 0.5}
