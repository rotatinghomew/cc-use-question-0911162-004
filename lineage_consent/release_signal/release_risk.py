from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from lineage_consent.privacy.group_guard import (
    cohort_metrics,
    payload_of,
    purpose_is_licensed,
    ratio_value,
)


@dataclass(frozen=True)
class DomainSignal:
    code: str
    score: float
    severity: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "score": self.score, "severity": self.severity,
                "evidence": self.evidence}


def clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def release_risk(record: Any) -> DomainSignal:
    """Release risk computed from the same basis as group analysis.

    The severity reflects the measured withdrawal pressure, not merely the
    presence of a non-zero ``revocation_count``: one withdrawal in a large
    cohort is a warning, a withdrawal mass that overwhelms the retained cohort
    is critical.
    """
    payload = payload_of(record)
    metrics = cohort_metrics(payload)
    basis = metrics["evidence"]["basis"]

    sensitive = metrics["evidence"]["sensitive_share"]["normalized"]
    missing = basis["missing_rate"]
    privacy_k = metrics["privacy_k"]
    privacy_l = metrics["privacy_l"]
    purpose_mismatch = not purpose_is_licensed(payload, payload.get("purpose_code", ""))
    demand = payload.get("licensed_purposes")

    sensitive = 0.0 if sensitive is None else sensitive
    missing = 0.0 if missing is None else missing
    group_risk = clamp(1.0 - min(1.0, (privacy_k or 0.0) / 10.0) * 0.65
                       - min(1.0, (privacy_l or 0.0) / 5.0) * 0.35)
    withdrawal = 0.0 if metrics["withdrawal_pressure"] is None else metrics["withdrawal_pressure"]
    risk = clamp(sensitive * 0.25 + missing * 0.12 + group_risk * 0.23
                 + withdrawal * 0.22 + (1.0 if purpose_mismatch else 0.0) * 0.35)

    severity = "info"
    reasons: list[str] = []
    if purpose_mismatch:
        severity = "critical"
        reasons.append("purpose_scope_mismatch")
    elif metrics["withdrawal_overflow"]:
        severity = "critical"
        reasons.append("withdrawals_exceed_observed_records")
    elif not metrics["estimable"]:
        severity = "warning"
        reasons.append("interval_not_estimable")
    elif withdrawal >= 0.5:
        severity = "critical"
        reasons.append("withdrawal_pressure_high")
    elif withdrawal > 0.0 or risk >= 0.38:
        severity = "warning"
        if withdrawal > 0.0:
            reasons.append("withdrawal_pressure_present")

    evidence = {
        "purpose_mismatch": bool(purpose_mismatch),
        "requested_purpose": payload.get("purpose_code", ""),
        "licensed_purposes": demand if isinstance(demand, str) else demand,
        "group_risk": group_risk,
        "withdrawal_share": metrics["withdrawal_share"],
        "withdrawal_pressure": metrics["withdrawal_pressure"],
        "withdrawal_overflow": metrics["withdrawal_overflow"],
        "withdrawn_count": basis["withdrawn_count"],
        "observed_records": metrics["observed_records"],
        "retained_records": metrics["retained_records"],
        "effective_records": metrics["effective_records"],
        "missing_rate": missing,
        "missing_range": metrics["missing_range"],
        "privacy_k": privacy_k,
        "privacy_l": privacy_l,
        "privacy_k_interval": (metrics["privacy_k_low"], metrics["privacy_k_high"]),
        "privacy_l_interval": (metrics["privacy_l_low"], metrics["privacy_l_high"]),
        "sensitive_share": sensitive,
        "interval_estimable": metrics["estimable"],
        "estimable": metrics["estimable"],
        "reasons": tuple(dict.fromkeys(tuple(metrics["evidence"]["reasons"]) + tuple(reasons))),
    }
    return DomainSignal("release_risk", risk, severity, evidence)


def peer_distribution(records: Iterable[Any], group_field: str = "owner_group") -> dict[str, Any]:
    materialized = list(records)
    rows = [release_risk(getattr(record, "payload", record)) for record in materialized]
    groups = {payload_of(getattr(record, "payload", record)).get(group_field, "unknown")
              for record in materialized}
    return {"count": len(rows), "groups": len(groups),
            "blocked": sum(signal.severity == "critical" for signal in rows),
            "warnings": sum(signal.severity == "warning" for signal in rows),
            "unestimated": sum(not signal.evidence.get("estimable", False) for signal in rows),
            "risk_budget": sum(signal.score for signal in rows)}


def augment_context(record: Any, repository: Any) -> dict[str, Any]:
    signal = release_risk(record)
    peers = peer_distribution(repository.list_records())
    return {"domain_signal": signal.score, "domain_severity": signal.severity,
            "blocked_assets": peers["blocked"], "warning_assets": peers["warnings"],
            "unestimated_assets": peers["unestimated"], "risk_budget": peers["risk_budget"],
            "release_evidence": signal.evidence}
