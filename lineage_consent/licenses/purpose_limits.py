from __future__ import annotations

import math
from typing import Any, Callable, Mapping

from lineage_consent.assets.asset_contract import DomainRecord, RuleResult, bounded, finite_number, normalized_text

RuleFunction = Callable[[DomainRecord, Mapping[str, Any]], RuleResult]

def _number(record: DomainRecord, field: str) -> float:
    value = record.payload.get(field)
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return finite_number(value)
    text = normalized_text(value)
    if not text:
        return 0.0
    try:
        return finite_number(text)
    except ValueError:
        tokens = [item for item in text.replace(',', ' ').replace(';', ' ').split() if item]
        return float(min(100, len(text) + len(set(tokens)) * 5))

def _context_number(context: Mapping[str, Any], key: str, default: float) -> float:
    try:
        return finite_number(context.get(key, default))
    except ValueError:
        return default

def _result(code: str, value: float, threshold: float, higher_is_better: bool, message: str, lineage: dict[str, Any]) -> RuleResult:
    distance = (value - threshold) if higher_is_better else (threshold - value)
    passed = distance >= 0
    scale = max(1.0, abs(threshold))
    score = bounded(0.5 + distance / (2.0 * scale))
    severity = 'info' if passed else ('critical' if score < 0.2 else 'error')
    return RuleResult(code, passed, score, severity, message, lineage)

def check_asset_id_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'asset_id')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_asset_id_presence_threshold', 10.333)
    return _result('check_asset_id_presence', adjusted, threshold, True, 'validates asset_id presence',
                   {'field': 'asset_id', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_asset_id_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'asset_id')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_asset_id_range_threshold', 12.667)
    return _result('check_asset_id_range', adjusted, threshold, True, 'validates asset_id range',
                   {'field': 'asset_id', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_asset_id_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'asset_id')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_asset_id_stability_threshold', 15.0)
    return _result('check_asset_id_stability', adjusted, threshold, False, 'validates asset_id stability',
                   {'field': 'asset_id', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_asset_id_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'asset_id')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_asset_id_freshness_threshold', 17.333)
    return _result('check_asset_id_freshness', adjusted, threshold, True, 'validates asset_id freshness',
                   {'field': 'asset_id', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_asset_id_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'asset_id')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_asset_id_coverage_threshold', 19.667)
    return _result('check_asset_id_coverage', adjusted, threshold, True, 'validates asset_id coverage',
                   {'field': 'asset_id', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_asset_id_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'asset_id')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_asset_id_consistency_threshold', 22.0)
    return _result('check_asset_id_consistency', adjusted, threshold, False, 'validates asset_id consistency',
                   {'field': 'asset_id', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_asset_id_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'asset_id')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_asset_id_risk_threshold', 24.333)
    return _result('check_asset_id_risk', adjusted, threshold, True, 'validates asset_id risk',
                   {'field': 'asset_id', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_asset_id_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'asset_id')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_asset_id_confidence_threshold', 26.667)
    return _result('check_asset_id_confidence', adjusted, threshold, True, 'validates asset_id confidence',
                   {'field': 'asset_id', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_asset_id_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'asset_id')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_asset_id_dependency_threshold', 29.0)
    return _result('check_asset_id_dependency', adjusted, threshold, False, 'validates asset_id dependency',
                   {'field': 'asset_id', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_asset_id_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'asset_id')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_asset_id_readiness_threshold', 31.333)
    return _result('check_asset_id_readiness', adjusted, threshold, True, 'validates asset_id readiness',
                   {'field': 'asset_id', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_owner_group_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'owner_group')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_owner_group_presence_threshold', 9.333)
    return _result('check_owner_group_presence', adjusted, threshold, True, 'validates owner_group presence',
                   {'field': 'owner_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_owner_group_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'owner_group')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_owner_group_range_threshold', 11.667)
    return _result('check_owner_group_range', adjusted, threshold, False, 'validates owner_group range',
                   {'field': 'owner_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_owner_group_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'owner_group')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_owner_group_stability_threshold', 14.0)
    return _result('check_owner_group_stability', adjusted, threshold, True, 'validates owner_group stability',
                   {'field': 'owner_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_owner_group_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'owner_group')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_owner_group_freshness_threshold', 16.333)
    return _result('check_owner_group_freshness', adjusted, threshold, True, 'validates owner_group freshness',
                   {'field': 'owner_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_owner_group_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'owner_group')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_owner_group_coverage_threshold', 18.667)
    return _result('check_owner_group_coverage', adjusted, threshold, False, 'validates owner_group coverage',
                   {'field': 'owner_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_owner_group_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'owner_group')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_owner_group_consistency_threshold', 21.0)
    return _result('check_owner_group_consistency', adjusted, threshold, True, 'validates owner_group consistency',
                   {'field': 'owner_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_owner_group_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'owner_group')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_owner_group_risk_threshold', 23.333)
    return _result('check_owner_group_risk', adjusted, threshold, True, 'validates owner_group risk',
                   {'field': 'owner_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_owner_group_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'owner_group')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_owner_group_confidence_threshold', 25.667)
    return _result('check_owner_group_confidence', adjusted, threshold, False, 'validates owner_group confidence',
                   {'field': 'owner_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_owner_group_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'owner_group')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_owner_group_dependency_threshold', 28.0)
    return _result('check_owner_group_dependency', adjusted, threshold, True, 'validates owner_group dependency',
                   {'field': 'owner_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_owner_group_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'owner_group')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_owner_group_readiness_threshold', 30.333)
    return _result('check_owner_group_readiness', adjusted, threshold, True, 'validates owner_group readiness',
                   {'field': 'owner_group', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_purpose_code_presence_threshold', 8.333)
    return _result('check_purpose_code_presence', adjusted, threshold, False, 'validates purpose_code presence',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_purpose_code_range_threshold', 10.667)
    return _result('check_purpose_code_range', adjusted, threshold, True, 'validates purpose_code range',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_purpose_code_stability_threshold', 13.0)
    return _result('check_purpose_code_stability', adjusted, threshold, True, 'validates purpose_code stability',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_purpose_code_freshness_threshold', 15.333)
    return _result('check_purpose_code_freshness', adjusted, threshold, False, 'validates purpose_code freshness',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_purpose_code_coverage_threshold', 17.667)
    return _result('check_purpose_code_coverage', adjusted, threshold, True, 'validates purpose_code coverage',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_purpose_code_consistency_threshold', 20.0)
    return _result('check_purpose_code_consistency', adjusted, threshold, True, 'validates purpose_code consistency',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_purpose_code_risk_threshold', 22.333)
    return _result('check_purpose_code_risk', adjusted, threshold, False, 'validates purpose_code risk',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_purpose_code_confidence_threshold', 24.667)
    return _result('check_purpose_code_confidence', adjusted, threshold, True, 'validates purpose_code confidence',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_purpose_code_dependency_threshold', 27.0)
    return _result('check_purpose_code_dependency', adjusted, threshold, True, 'validates purpose_code dependency',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_purpose_code_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'purpose_code')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_purpose_code_readiness_threshold', 29.333)
    return _result('check_purpose_code_readiness', adjusted, threshold, False, 'validates purpose_code readiness',
                   {'field': 'purpose_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_row_count_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'row_count')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_row_count_presence_threshold', 31.667)
    return _result('check_row_count_presence', adjusted, threshold, True, 'validates row_count presence',
                   {'field': 'row_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_row_count_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'row_count')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_row_count_range_threshold', 9.667)
    return _result('check_row_count_range', adjusted, threshold, True, 'validates row_count range',
                   {'field': 'row_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_row_count_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'row_count')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_row_count_stability_threshold', 12.0)
    return _result('check_row_count_stability', adjusted, threshold, False, 'validates row_count stability',
                   {'field': 'row_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_row_count_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'row_count')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_row_count_freshness_threshold', 14.333)
    return _result('check_row_count_freshness', adjusted, threshold, True, 'validates row_count freshness',
                   {'field': 'row_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_row_count_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'row_count')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_row_count_coverage_threshold', 16.667)
    return _result('check_row_count_coverage', adjusted, threshold, True, 'validates row_count coverage',
                   {'field': 'row_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_row_count_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'row_count')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_row_count_consistency_threshold', 19.0)
    return _result('check_row_count_consistency', adjusted, threshold, False, 'validates row_count consistency',
                   {'field': 'row_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_row_count_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'row_count')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_row_count_risk_threshold', 21.333)
    return _result('check_row_count_risk', adjusted, threshold, True, 'validates row_count risk',
                   {'field': 'row_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_row_count_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'row_count')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_row_count_confidence_threshold', 23.667)
    return _result('check_row_count_confidence', adjusted, threshold, True, 'validates row_count confidence',
                   {'field': 'row_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_row_count_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'row_count')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_row_count_dependency_threshold', 26.0)
    return _result('check_row_count_dependency', adjusted, threshold, False, 'validates row_count dependency',
                   {'field': 'row_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_row_count_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'row_count')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_row_count_readiness_threshold', 28.333)
    return _result('check_row_count_readiness', adjusted, threshold, True, 'validates row_count readiness',
                   {'field': 'row_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_sensitive_share_presence_threshold', 30.667)
    return _result('check_sensitive_share_presence', adjusted, threshold, True, 'validates sensitive_share presence',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_sensitive_share_range_threshold', 8.667)
    return _result('check_sensitive_share_range', adjusted, threshold, False, 'validates sensitive_share range',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_sensitive_share_stability_threshold', 11.0)
    return _result('check_sensitive_share_stability', adjusted, threshold, True, 'validates sensitive_share stability',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_sensitive_share_freshness_threshold', 13.333)
    return _result('check_sensitive_share_freshness', adjusted, threshold, True, 'validates sensitive_share freshness',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_sensitive_share_coverage_threshold', 15.667)
    return _result('check_sensitive_share_coverage', adjusted, threshold, False, 'validates sensitive_share coverage',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_sensitive_share_consistency_threshold', 18.0)
    return _result('check_sensitive_share_consistency', adjusted, threshold, True, 'validates sensitive_share consistency',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_sensitive_share_risk_threshold', 20.333)
    return _result('check_sensitive_share_risk', adjusted, threshold, True, 'validates sensitive_share risk',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_sensitive_share_confidence_threshold', 22.667)
    return _result('check_sensitive_share_confidence', adjusted, threshold, False, 'validates sensitive_share confidence',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_sensitive_share_dependency_threshold', 25.0)
    return _result('check_sensitive_share_dependency', adjusted, threshold, True, 'validates sensitive_share dependency',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_sensitive_share_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'sensitive_share')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_sensitive_share_readiness_threshold', 27.333)
    return _result('check_sensitive_share_readiness', adjusted, threshold, True, 'validates sensitive_share readiness',
                   {'field': 'sensitive_share', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_licensed_purposes_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'licensed_purposes')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_licensed_purposes_presence_threshold', 29.667)
    return _result('check_licensed_purposes_presence', adjusted, threshold, False, 'validates licensed_purposes presence',
                   {'field': 'licensed_purposes', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_licensed_purposes_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'licensed_purposes')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_licensed_purposes_range_threshold', 32.0)
    return _result('check_licensed_purposes_range', adjusted, threshold, True, 'validates licensed_purposes range',
                   {'field': 'licensed_purposes', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_licensed_purposes_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'licensed_purposes')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_licensed_purposes_stability_threshold', 10.0)
    return _result('check_licensed_purposes_stability', adjusted, threshold, True, 'validates licensed_purposes stability',
                   {'field': 'licensed_purposes', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_licensed_purposes_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'licensed_purposes')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_licensed_purposes_freshness_threshold', 12.333)
    return _result('check_licensed_purposes_freshness', adjusted, threshold, False, 'validates licensed_purposes freshness',
                   {'field': 'licensed_purposes', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_licensed_purposes_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'licensed_purposes')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_licensed_purposes_coverage_threshold', 14.667)
    return _result('check_licensed_purposes_coverage', adjusted, threshold, True, 'validates licensed_purposes coverage',
                   {'field': 'licensed_purposes', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_licensed_purposes_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'licensed_purposes')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_licensed_purposes_consistency_threshold', 17.0)
    return _result('check_licensed_purposes_consistency', adjusted, threshold, True, 'validates licensed_purposes consistency',
                   {'field': 'licensed_purposes', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_licensed_purposes_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'licensed_purposes')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_licensed_purposes_risk_threshold', 19.333)
    return _result('check_licensed_purposes_risk', adjusted, threshold, False, 'validates licensed_purposes risk',
                   {'field': 'licensed_purposes', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_licensed_purposes_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'licensed_purposes')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_licensed_purposes_confidence_threshold', 21.667)
    return _result('check_licensed_purposes_confidence', adjusted, threshold, True, 'validates licensed_purposes confidence',
                   {'field': 'licensed_purposes', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_licensed_purposes_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'licensed_purposes')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_licensed_purposes_dependency_threshold', 24.0)
    return _result('check_licensed_purposes_dependency', adjusted, threshold, True, 'validates licensed_purposes dependency',
                   {'field': 'licensed_purposes', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_licensed_purposes_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'licensed_purposes')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_licensed_purposes_readiness_threshold', 26.333)
    return _result('check_licensed_purposes_readiness', adjusted, threshold, False, 'validates licensed_purposes readiness',
                   {'field': 'licensed_purposes', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_schema_version_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'schema_version')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_schema_version_presence_threshold', 28.667)
    return _result('check_schema_version_presence', adjusted, threshold, True, 'validates schema_version presence',
                   {'field': 'schema_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_schema_version_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'schema_version')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_schema_version_range_threshold', 31.0)
    return _result('check_schema_version_range', adjusted, threshold, True, 'validates schema_version range',
                   {'field': 'schema_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_schema_version_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'schema_version')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_schema_version_stability_threshold', 9.0)
    return _result('check_schema_version_stability', adjusted, threshold, False, 'validates schema_version stability',
                   {'field': 'schema_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_schema_version_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'schema_version')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_schema_version_freshness_threshold', 11.333)
    return _result('check_schema_version_freshness', adjusted, threshold, True, 'validates schema_version freshness',
                   {'field': 'schema_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_schema_version_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'schema_version')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_schema_version_coverage_threshold', 13.667)
    return _result('check_schema_version_coverage', adjusted, threshold, True, 'validates schema_version coverage',
                   {'field': 'schema_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_schema_version_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'schema_version')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_schema_version_consistency_threshold', 16.0)
    return _result('check_schema_version_consistency', adjusted, threshold, False, 'validates schema_version consistency',
                   {'field': 'schema_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_schema_version_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'schema_version')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_schema_version_risk_threshold', 18.333)
    return _result('check_schema_version_risk', adjusted, threshold, True, 'validates schema_version risk',
                   {'field': 'schema_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_schema_version_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'schema_version')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_schema_version_confidence_threshold', 20.667)
    return _result('check_schema_version_confidence', adjusted, threshold, True, 'validates schema_version confidence',
                   {'field': 'schema_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_schema_version_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'schema_version')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_schema_version_dependency_threshold', 23.0)
    return _result('check_schema_version_dependency', adjusted, threshold, False, 'validates schema_version dependency',
                   {'field': 'schema_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_schema_version_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'schema_version')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_schema_version_readiness_threshold', 25.333)
    return _result('check_schema_version_readiness', adjusted, threshold, True, 'validates schema_version readiness',
                   {'field': 'schema_version', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_missing_rate_presence_threshold', 27.667)
    return _result('check_missing_rate_presence', adjusted, threshold, True, 'validates missing_rate presence',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_missing_rate_range_threshold', 30.0)
    return _result('check_missing_rate_range', adjusted, threshold, False, 'validates missing_rate range',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_missing_rate_stability_threshold', 8.0)
    return _result('check_missing_rate_stability', adjusted, threshold, True, 'validates missing_rate stability',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_missing_rate_freshness_threshold', 10.333)
    return _result('check_missing_rate_freshness', adjusted, threshold, True, 'validates missing_rate freshness',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_missing_rate_coverage_threshold', 12.667)
    return _result('check_missing_rate_coverage', adjusted, threshold, False, 'validates missing_rate coverage',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_missing_rate_consistency_threshold', 15.0)
    return _result('check_missing_rate_consistency', adjusted, threshold, True, 'validates missing_rate consistency',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_missing_rate_risk_threshold', 17.333)
    return _result('check_missing_rate_risk', adjusted, threshold, True, 'validates missing_rate risk',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_missing_rate_confidence_threshold', 19.667)
    return _result('check_missing_rate_confidence', adjusted, threshold, False, 'validates missing_rate confidence',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_missing_rate_dependency_threshold', 22.0)
    return _result('check_missing_rate_dependency', adjusted, threshold, True, 'validates missing_rate dependency',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_missing_rate_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'missing_rate')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_missing_rate_readiness_threshold', 24.333)
    return _result('check_missing_rate_readiness', adjusted, threshold, True, 'validates missing_rate readiness',
                   {'field': 'missing_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_k_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_k')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_privacy_k_presence_threshold', 26.667)
    return _result('check_privacy_k_presence', adjusted, threshold, False, 'validates privacy_k presence',
                   {'field': 'privacy_k', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_k_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_k')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_privacy_k_range_threshold', 29.0)
    return _result('check_privacy_k_range', adjusted, threshold, True, 'validates privacy_k range',
                   {'field': 'privacy_k', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_k_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_k')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_privacy_k_stability_threshold', 31.333)
    return _result('check_privacy_k_stability', adjusted, threshold, True, 'validates privacy_k stability',
                   {'field': 'privacy_k', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_k_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_k')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_privacy_k_freshness_threshold', 9.333)
    return _result('check_privacy_k_freshness', adjusted, threshold, False, 'validates privacy_k freshness',
                   {'field': 'privacy_k', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_k_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_k')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_privacy_k_coverage_threshold', 11.667)
    return _result('check_privacy_k_coverage', adjusted, threshold, True, 'validates privacy_k coverage',
                   {'field': 'privacy_k', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_k_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_k')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_privacy_k_consistency_threshold', 14.0)
    return _result('check_privacy_k_consistency', adjusted, threshold, True, 'validates privacy_k consistency',
                   {'field': 'privacy_k', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_k_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_k')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_privacy_k_risk_threshold', 16.333)
    return _result('check_privacy_k_risk', adjusted, threshold, False, 'validates privacy_k risk',
                   {'field': 'privacy_k', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_k_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_k')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_privacy_k_confidence_threshold', 18.667)
    return _result('check_privacy_k_confidence', adjusted, threshold, True, 'validates privacy_k confidence',
                   {'field': 'privacy_k', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_k_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_k')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_privacy_k_dependency_threshold', 21.0)
    return _result('check_privacy_k_dependency', adjusted, threshold, True, 'validates privacy_k dependency',
                   {'field': 'privacy_k', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_k_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_k')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_privacy_k_readiness_threshold', 23.333)
    return _result('check_privacy_k_readiness', adjusted, threshold, False, 'validates privacy_k readiness',
                   {'field': 'privacy_k', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_l_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_l')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_privacy_l_presence_threshold', 25.667)
    return _result('check_privacy_l_presence', adjusted, threshold, True, 'validates privacy_l presence',
                   {'field': 'privacy_l', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_l_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_l')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_privacy_l_range_threshold', 28.0)
    return _result('check_privacy_l_range', adjusted, threshold, True, 'validates privacy_l range',
                   {'field': 'privacy_l', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_l_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_l')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_privacy_l_stability_threshold', 30.333)
    return _result('check_privacy_l_stability', adjusted, threshold, False, 'validates privacy_l stability',
                   {'field': 'privacy_l', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_l_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_l')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_privacy_l_freshness_threshold', 8.333)
    return _result('check_privacy_l_freshness', adjusted, threshold, True, 'validates privacy_l freshness',
                   {'field': 'privacy_l', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_l_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_l')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_privacy_l_coverage_threshold', 10.667)
    return _result('check_privacy_l_coverage', adjusted, threshold, True, 'validates privacy_l coverage',
                   {'field': 'privacy_l', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_l_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_l')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_privacy_l_consistency_threshold', 13.0)
    return _result('check_privacy_l_consistency', adjusted, threshold, False, 'validates privacy_l consistency',
                   {'field': 'privacy_l', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_l_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_l')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_privacy_l_risk_threshold', 15.333)
    return _result('check_privacy_l_risk', adjusted, threshold, True, 'validates privacy_l risk',
                   {'field': 'privacy_l', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_l_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_l')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_privacy_l_confidence_threshold', 17.667)
    return _result('check_privacy_l_confidence', adjusted, threshold, True, 'validates privacy_l confidence',
                   {'field': 'privacy_l', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_l_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_l')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_privacy_l_dependency_threshold', 20.0)
    return _result('check_privacy_l_dependency', adjusted, threshold, False, 'validates privacy_l dependency',
                   {'field': 'privacy_l', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_privacy_l_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'privacy_l')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_privacy_l_readiness_threshold', 22.333)
    return _result('check_privacy_l_readiness', adjusted, threshold, True, 'validates privacy_l readiness',
                   {'field': 'privacy_l', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_revocation_count_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'revocation_count')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_revocation_count_presence_threshold', 24.667)
    return _result('check_revocation_count_presence', adjusted, threshold, True, 'validates revocation_count presence',
                   {'field': 'revocation_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_revocation_count_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'revocation_count')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_revocation_count_range_threshold', 27.0)
    return _result('check_revocation_count_range', adjusted, threshold, False, 'validates revocation_count range',
                   {'field': 'revocation_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_revocation_count_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'revocation_count')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_revocation_count_stability_threshold', 29.333)
    return _result('check_revocation_count_stability', adjusted, threshold, True, 'validates revocation_count stability',
                   {'field': 'revocation_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_revocation_count_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'revocation_count')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_revocation_count_freshness_threshold', 31.667)
    return _result('check_revocation_count_freshness', adjusted, threshold, True, 'validates revocation_count freshness',
                   {'field': 'revocation_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_revocation_count_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'revocation_count')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_revocation_count_coverage_threshold', 9.667)
    return _result('check_revocation_count_coverage', adjusted, threshold, False, 'validates revocation_count coverage',
                   {'field': 'revocation_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_revocation_count_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'revocation_count')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_revocation_count_consistency_threshold', 12.0)
    return _result('check_revocation_count_consistency', adjusted, threshold, True, 'validates revocation_count consistency',
                   {'field': 'revocation_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_revocation_count_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'revocation_count')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_revocation_count_risk_threshold', 14.333)
    return _result('check_revocation_count_risk', adjusted, threshold, True, 'validates revocation_count risk',
                   {'field': 'revocation_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_revocation_count_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'revocation_count')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_revocation_count_confidence_threshold', 16.667)
    return _result('check_revocation_count_confidence', adjusted, threshold, False, 'validates revocation_count confidence',
                   {'field': 'revocation_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_revocation_count_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'revocation_count')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_revocation_count_dependency_threshold', 19.0)
    return _result('check_revocation_count_dependency', adjusted, threshold, True, 'validates revocation_count dependency',
                   {'field': 'revocation_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_revocation_count_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'revocation_count')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_revocation_count_readiness_threshold', 21.333)
    return _result('check_revocation_count_readiness', adjusted, threshold, True, 'validates revocation_count readiness',
                   {'field': 'revocation_count', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_review_authority_presence_threshold', 23.667)
    return _result('check_review_authority_presence', adjusted, threshold, False, 'validates review_authority presence',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_review_authority_range_threshold', 26.0)
    return _result('check_review_authority_range', adjusted, threshold, True, 'validates review_authority range',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_review_authority_stability_threshold', 28.333)
    return _result('check_review_authority_stability', adjusted, threshold, True, 'validates review_authority stability',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_review_authority_freshness_threshold', 30.667)
    return _result('check_review_authority_freshness', adjusted, threshold, False, 'validates review_authority freshness',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_review_authority_coverage_threshold', 8.667)
    return _result('check_review_authority_coverage', adjusted, threshold, True, 'validates review_authority coverage',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_review_authority_consistency_threshold', 11.0)
    return _result('check_review_authority_consistency', adjusted, threshold, True, 'validates review_authority consistency',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_review_authority_risk_threshold', 13.333)
    return _result('check_review_authority_risk', adjusted, threshold, False, 'validates review_authority risk',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_review_authority_confidence_threshold', 15.667)
    return _result('check_review_authority_confidence', adjusted, threshold, True, 'validates review_authority confidence',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_review_authority_dependency_threshold', 18.0)
    return _result('check_review_authority_dependency', adjusted, threshold, True, 'validates review_authority dependency',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_review_authority_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'review_authority')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_review_authority_readiness_threshold', 20.333)
    return _result('check_review_authority_readiness', adjusted, threshold, False, 'validates review_authority readiness',
                   {'field': 'review_authority', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

RULES: tuple[RuleFunction, ...] = (
    check_asset_id_presence,
    check_asset_id_range,
    check_asset_id_stability,
    check_asset_id_freshness,
    check_asset_id_coverage,
    check_asset_id_consistency,
    check_asset_id_risk,
    check_asset_id_confidence,
    check_asset_id_dependency,
    check_asset_id_readiness,
    check_owner_group_presence,
    check_owner_group_range,
    check_owner_group_stability,
    check_owner_group_freshness,
    check_owner_group_coverage,
    check_owner_group_consistency,
    check_owner_group_risk,
    check_owner_group_confidence,
    check_owner_group_dependency,
    check_owner_group_readiness,
    check_purpose_code_presence,
    check_purpose_code_range,
    check_purpose_code_stability,
    check_purpose_code_freshness,
    check_purpose_code_coverage,
    check_purpose_code_consistency,
    check_purpose_code_risk,
    check_purpose_code_confidence,
    check_purpose_code_dependency,
    check_purpose_code_readiness,
    check_row_count_presence,
    check_row_count_range,
    check_row_count_stability,
    check_row_count_freshness,
    check_row_count_coverage,
    check_row_count_consistency,
    check_row_count_risk,
    check_row_count_confidence,
    check_row_count_dependency,
    check_row_count_readiness,
    check_sensitive_share_presence,
    check_sensitive_share_range,
    check_sensitive_share_stability,
    check_sensitive_share_freshness,
    check_sensitive_share_coverage,
    check_sensitive_share_consistency,
    check_sensitive_share_risk,
    check_sensitive_share_confidence,
    check_sensitive_share_dependency,
    check_sensitive_share_readiness,
    check_licensed_purposes_presence,
    check_licensed_purposes_range,
    check_licensed_purposes_stability,
    check_licensed_purposes_freshness,
    check_licensed_purposes_coverage,
    check_licensed_purposes_consistency,
    check_licensed_purposes_risk,
    check_licensed_purposes_confidence,
    check_licensed_purposes_dependency,
    check_licensed_purposes_readiness,
    check_schema_version_presence,
    check_schema_version_range,
    check_schema_version_stability,
    check_schema_version_freshness,
    check_schema_version_coverage,
    check_schema_version_consistency,
    check_schema_version_risk,
    check_schema_version_confidence,
    check_schema_version_dependency,
    check_schema_version_readiness,
    check_missing_rate_presence,
    check_missing_rate_range,
    check_missing_rate_stability,
    check_missing_rate_freshness,
    check_missing_rate_coverage,
    check_missing_rate_consistency,
    check_missing_rate_risk,
    check_missing_rate_confidence,
    check_missing_rate_dependency,
    check_missing_rate_readiness,
    check_privacy_k_presence,
    check_privacy_k_range,
    check_privacy_k_stability,
    check_privacy_k_freshness,
    check_privacy_k_coverage,
    check_privacy_k_consistency,
    check_privacy_k_risk,
    check_privacy_k_confidence,
    check_privacy_k_dependency,
    check_privacy_k_readiness,
    check_privacy_l_presence,
    check_privacy_l_range,
    check_privacy_l_stability,
    check_privacy_l_freshness,
    check_privacy_l_coverage,
    check_privacy_l_consistency,
    check_privacy_l_risk,
    check_privacy_l_confidence,
    check_privacy_l_dependency,
    check_privacy_l_readiness,
    check_revocation_count_presence,
    check_revocation_count_range,
    check_revocation_count_stability,
    check_revocation_count_freshness,
    check_revocation_count_coverage,
    check_revocation_count_consistency,
    check_revocation_count_risk,
    check_revocation_count_confidence,
    check_revocation_count_dependency,
    check_revocation_count_readiness,
    check_review_authority_presence,
    check_review_authority_range,
    check_review_authority_stability,
    check_review_authority_freshness,
    check_review_authority_coverage,
    check_review_authority_consistency,
    check_review_authority_risk,
    check_review_authority_confidence,
    check_review_authority_dependency,
    check_review_authority_readiness,
)

RULE_INDEX = {rule.__name__: rule for rule in RULES}

def evaluate(record: DomainRecord, context: Mapping[str, Any] | None = None) -> tuple[RuleResult, ...]:
    context = context or {}
    return tuple(rule(record, context) for rule in RULES)

def summarize(results: tuple[RuleResult, ...]) -> dict[str, Any]:
    if not results:
        return {'score': 0.0, 'passed': 0, 'failed': 0, 'critical': 0}
    return {'score': sum(item.score for item in results) / len(results),
            'passed': sum(item.passed for item in results),
            'failed': sum(not item.passed for item in results),
            'critical': sum(item.severity == 'critical' for item in results)}
