from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping

@dataclass(frozen=True)
class DomainSignal:
    code: str
    score: float
    severity: str
    evidence: dict[str, Any]

def number(payload: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    try:
        value = float(payload.get(key, default))
    except (TypeError, ValueError):
        return default
    return default if value != value or value in (float('inf'), float('-inf')) else value

def ratio(payload: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    value = number(payload, key, default)
    if value > 1.0:
        value /= 100.0
    return max(0.0, min(1.0, value))

def clamp(value: float) -> float:
    return max(0.0, min(1.0, value))

def release_risk(payload: Mapping[str, Any]) -> DomainSignal:
    sensitive=ratio(payload,'sensitive_share'); missing=ratio(payload,'missing_rate'); revocations=max(0.0,number(payload,'revocation_count'))
    rows=max(1.0,number(payload,'row_count',1)); k=max(1.0,number(payload,'privacy_k',1)); diversity=max(0.0,number(payload,'privacy_l'))
    purposes=str(payload.get('licensed_purposes','')).strip(); requested=str(payload.get('purpose_code','')).strip()
    purpose_mismatch=1.0 if not purposes or (requested and requested not in purposes.split(',')) else 0.0
    group_risk=clamp(1.0-min(1.0,k/10.0)*.65-min(1.0,diversity/5.0)*.35)
    withdrawal=min(1.0,revocations/rows)
    risk=clamp(sensitive*.25+missing*.12+group_risk*.23+withdrawal*.22+purpose_mismatch*.35)
    severity='critical' if purpose_mismatch or revocations>0 else 'warning' if risk>=.38 else 'info'
    return DomainSignal('release_risk',risk,severity,{'purpose_mismatch':bool(purpose_mismatch),'group_risk':group_risk,'withdrawal_share':withdrawal,'sensitive_share':sensitive})

def peer_distribution(records:Iterable[Any],group_field:str='owner_group')->dict[str,Any]:
    rows=[release_risk(getattr(r,'payload',r)) for r in records]
    return {'count':len(rows),'blocked':sum(s.severity=='critical' for s in rows),'risk_budget':sum(s.score for s in rows)}

def augment_context(record:Any,repository:Any)->dict[str,Any]:
    signal=release_risk(record.payload); peers=peer_distribution(repository.list_records())
    return {'domain_signal':signal.score,'domain_severity':signal.severity,'blocked_assets':peers['blocked'],'risk_budget':peers['risk_budget']}
