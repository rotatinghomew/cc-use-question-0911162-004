from __future__ import annotations

import unittest
from lineage_consent.assets.asset_contract import DomainRecord
from lineage_consent.privacy.group_guard import cohort_metrics, consent_allows, stratified_gap, wilson_interval


class CohortGuardTests(unittest.TestCase):
    def record(self, key, group="a"):
        return DomainRecord(key, {"asset_id": "h", "owner_group": group, "purpose_code": "c", "row_count": 200,
            "sensitive_share": .2, "licensed_purposes": "validation,research", "schema_version": "1", "missing_rate": .05,
            "privacy_k": .9, "privacy_l": .85, "revocation_count": 1, "review_authority": "rb"})

    def test_intervals_and_consent(self):
        low, high = wilson_interval(90, 100)
        self.assertLess(low, high)
        self.assertTrue(consent_allows(self.record("a"), "validation"))
        self.assertGreater(cohort_metrics(self.record("a"))["privacy_k_low"], 0.0)

    def test_stratified_gap(self):
        self.assertEqual(stratified_gap([self.record("a", "x"), self.record("b", "y")])["group_count"], 2.0)
