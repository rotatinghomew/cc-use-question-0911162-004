from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lineage_consent.assets.asset_contract import ContractError, DomainRecord, stable_hash
from lineage_consent.control_plane import Application
from lineage_consent.lineage.lineage_store import Repository
from lineage_consent.privacy.group_guard import (
    cohort_metrics,
    effective_record_basis,
    stratified_gap,
    wilson_interval,
)
from lineage_consent.release_signal.release_risk import release_risk
from lineage_consent.revocation.impact_flow import advance_for_outcome, decide


def payload(**overrides):
    value = {
        "asset_id": "asset-1",
        "owner_group": "group-a",
        "purpose_code": "validation",
        "row_count": 1000,
        "sensitive_share": 0.3,
        "licensed_purposes": "validation,research",
        "schema_version": "1",
        "missing_rate": 0.05,
        "privacy_k": 0.9,
        "privacy_l": 0.85,
        "revocation_count": 0,
        "review_authority": "rb",
    }
    value.update(overrides)
    return value


def record(**overrides):
    return DomainRecord("asset-1", payload(**overrides))


class SharedBasisTests(unittest.TestCase):
    def test_percentages_are_not_flattened_to_one(self):
        metrics = cohort_metrics(payload(privacy_k=27.2, privacy_l=29.1, missing_rate=25.3))
        self.assertAlmostEqual(metrics["privacy_k"], 0.272)
        self.assertAlmostEqual(metrics["privacy_l"], 0.291)
        self.assertAlmostEqual(metrics["missing_rate"], 0.253)
        self.assertTrue(metrics["privacy_k_estimable"])

    def test_different_thresholds_produce_different_intervals(self):
        low_threshold = cohort_metrics(payload(privacy_k=0.5))["privacy_k_low"]
        high_threshold = cohort_metrics(payload(privacy_k=0.9))["privacy_k_low"]
        self.assertNotAlmostEqual(low_threshold, high_threshold)

    def test_withdrawals_define_effective_records(self):
        metrics = cohort_metrics(payload(revocation_count=100))
        self.assertAlmostEqual(metrics["observed_records"], 950.0)
        self.assertAlmostEqual(metrics["retained_records"], 850.0)
        self.assertAlmostEqual(metrics["effective_records"], 850.0)
        self.assertAlmostEqual(metrics["withdrawal_share"], 100 / 950)

    def test_withdrawal_shrinks_the_interval(self):
        quiet = cohort_metrics(payload(revocation_count=0))
        withdrawn = cohort_metrics(payload(revocation_count=800))
        self.assertGreater(withdrawn["privacy_k_high"] - withdrawn["privacy_k_low"],
                           quiet["privacy_k_high"] - quiet["privacy_k_low"])

    def test_missing_is_reported_as_a_range(self):
        metrics = cohort_metrics(payload(missing_rate=0.2))
        self.assertTrue(metrics["missing_estimable"])
        self.assertLess(metrics["missing_low"], 0.2)
        self.assertGreater(metrics["missing_high"], 0.2)


class UnestimableTests(unittest.TestCase):
    def test_empty_sample_is_not_a_certain_interval(self):
        self.assertEqual(wilson_interval(0, 0), (None, None))

    def assert_unestimable(self, **overrides):
        metrics = cohort_metrics(payload(**overrides))
        self.assertFalse(metrics["estimable"])
        self.assertIsNone(metrics["privacy_k_low"])
        self.assertIsNone(metrics["privacy_k_high"])
        self.assertTrue(metrics["evidence"]["reasons"])
        return metrics

    def test_missing_rows(self):
        self.assert_unestimable(row_count=None)

    def test_missing_missing_rate(self):
        self.assert_unestimable(missing_rate=None)

    def test_missing_revocation_count(self):
        self.assert_unestimable(revocation_count=None)

    def test_missing_threshold(self):
        self.assert_unestimable(privacy_k=None)

    def test_out_of_range_ratio(self):
        self.assert_unestimable(privacy_k=250)

    def test_all_rows_missing(self):
        self.assert_unestimable(missing_rate=1.0)

    def test_withdrawals_exceed_observed_records(self):
        metrics = self.assert_unestimable(revocation_count=5000)
        self.assertIn("withdrawals_exceed_observed_records", metrics["evidence"]["reasons"])
        self.assertTrue(metrics["withdrawal_overflow"])

    def test_unestimable_interval_is_warned_not_critical(self):
        signal = release_risk(payload(privacy_k=None))
        self.assertEqual(signal.severity, "warning")
        self.assertFalse(signal.evidence["estimable"])
        self.assertIn("interval_not_estimable", signal.evidence["reasons"])


class ReleaseSignalTests(unittest.TestCase):
    def test_single_withdrawal_is_not_critical(self):
        signal = release_risk(payload(revocation_count=1))
        self.assertEqual(signal.severity, "warning")
        self.assertLess(signal.evidence["withdrawal_pressure"], 0.01)

    def test_threshold_changes_release_risk(self):
        weak = release_risk(payload(privacy_k=0.5, privacy_l=0.5))
        strong = release_risk(payload(privacy_k=0.95, privacy_l=0.9))
        self.assertGreater(weak.score, strong.score)

    def test_purpose_mismatch_is_critical(self):
        signal = release_risk(payload(purpose_code="marketing"))
        self.assertEqual(signal.severity, "critical")
        self.assertTrue(signal.evidence["purpose_mismatch"])

    def test_release_signal_uses_same_effective_records(self):
        signal = release_risk(payload(revocation_count=100))
        metrics = cohort_metrics(payload(revocation_count=100))
        self.assertEqual(signal.evidence["effective_records"], metrics["effective_records"])
        self.assertEqual(signal.evidence["observed_records"], metrics["observed_records"])
        self.assertEqual(signal.evidence["missing_range"], metrics["missing_range"])


class StratifiedTests(unittest.TestCase):
    def test_gap_uses_only_estimable_groups(self):
        good = DomainRecord("a", payload(owner_group="x"))
        bad = DomainRecord("b", payload(owner_group="y", row_count=None))
        result = stratified_gap([good, bad])
        self.assertEqual(result["group_count"], 2.0)
        self.assertEqual(result["comparable_group_count"], 1.0)
        self.assertFalse(result["comparable"])
        self.assertFalse(result["groups"]["y"]["estimable"])

    def test_gap_is_zero_when_nothing_is_comparable(self):
        result = stratified_gap([DomainRecord("a", payload(privacy_k=None))])
        self.assertFalse(result["comparable"])
        self.assertEqual(result["privacy_k_gap"], 0.0)


class DecisionEvidenceTests(unittest.TestCase):
    def test_decision_carries_estimability_and_ranges(self):
        application = Application(Path(tempfile.mkdtemp()) / "db.sqlite3")
        _, decision = application.process(record())
        self.assertIn("evidence_estimable", decision.evidence)
        self.assertIn("privacy_k_low", decision.evidence["cohort"])
        self.assertIn("missing_range", decision.evidence["release"])
        self.assertTrue(any("evidence_estimable" in reason for reason in decision.reasons))

    def test_hold_does_not_rewrite_record_to_revoked(self):
        original = record(purpose_code="marketing")
        decision = decide(original)
        self.assertEqual(decision.outcome, "hold")
        self.assertEqual(advance_for_outcome(original, decision).state, original.state)


class AuditTraceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "audit.sqlite3"
        self.output = self.root / "out"

    def fixture(self):
        return {"records": [{"record_id": "asset-1", "payload": payload(),
                             "source": "synthetic-local-acceptance"}]}

    def test_withdrawal_amounts_are_never_silently_clamped(self):
        application = Application(self.database)
        changed = self.fixture()
        changed["records"][0]["payload"]["revocation_count"] = 4000
        application.run_fixture(changed, self.output)
        stored = Repository(self.database).get_record("asset-1")
        self.assertEqual(stored.payload["revocation_count"], 4000)

    def test_withdrawal_change_keeps_both_versions_and_events(self):
        application = Application(self.database)
        application.run_fixture(self.fixture(), self.output)
        changed = self.fixture()
        changed["records"][0]["payload"]["revocation_count"] = 12
        application.run_fixture(changed, self.root / "out2")
        repository = Repository(self.database)
        self.assertEqual(repository.snapshot()["counts"]["record_versions"], 2)
        saved = [event["payload"] for event in repository.event_rows()
                 if event["aggregate_id"] == "asset-1" and event["event_type"] == "record.saved"]
        self.assertEqual(saved[0]["revocation_count"], 0)
        self.assertEqual(saved[1]["revocation_count"], 12)
        self.assertEqual(saved[1]["previous_revocation_count"], 0)
        self.assertTrue(saved[1]["withdrawal_changed"])
        self.assertEqual(repository.verify_chain(), [])

    def test_prior_decisions_are_not_overwritten(self):
        application = Application(self.database)
        first = application.run_fixture(self.fixture(), self.output)
        changed = self.fixture()
        changed["records"][0]["payload"]["revocation_count"] = 12
        application.run_fixture(changed, self.root / "out2")
        repository = Repository(self.database)
        self.assertEqual(repository.snapshot()["counts"]["decisions"], 2)
        self.assertIsNotNone(first["decisions"])

    def test_completed_run_records_its_analysis_basis(self):
        application = Application(self.database)
        result = application.run_fixture(self.fixture(), self.output)
        runs = Repository(self.database).run_versions()
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["analysis_version"], result["analysis_version"])

    def test_stale_basis_is_not_replayed(self):
        application = Application(self.database)
        first = application.run_fixture(self.fixture(), self.output)
        repository = Repository(self.database)
        with repository.transaction() as connection:
            connection.execute("UPDATE runs SET result_json='{}' WHERE run_id=?", (first["run_id"],))
        with self.assertRaisesRegex(ContractError, "different analysis basis"):
            application.run_fixture(self.fixture(), self.root / "out2")

    def test_legacy_run_is_preserved_and_reanalysed(self):
        application = Application(self.database)
        fixture = self.fixture()
        fixture_hash = stable_hash(fixture)
        legacy = Repository(self.database).begin_run(fixture_hash, len(fixture["records"]))
        Repository(self.database).finish_run(legacy, {"run_id": legacy, "fixture_hash": fixture_hash,
                                                      "records": 1, "decisions": 1})
        result = application.run_fixture(fixture, self.output)
        self.assertNotEqual(result["run_id"], legacy)
        runs = {run["run_id"]: run for run in Repository(self.database).run_versions()}
        self.assertEqual(len(runs), 2)
        self.assertIsNone(runs[legacy]["analysis_version"])
        self.assertEqual(runs[result["run_id"]]["analysis_version"], result["analysis_version"])


if __name__ == "__main__":
    unittest.main()
