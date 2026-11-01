"""Exercise reporting with files left behind by interrupted evidence steps."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("summarize-evidence.py").resolve()
STEPS = {"REGISTRY_AUDITS": "success", "EVIDENCE_BUILD": "success", "NOSTR_BROWSER": "success"}


class EvidenceSummaryTest(unittest.TestCase):
    def report(self, status=None, log=None, complete=True, tier="blocking", steps=None,
               advisory_complete=True):
        """Run the summary over one healthy group per tier plus an optional extra group.

        Returns (exit status, summary text)."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir()
            results = root / "evidence-results"
            for name, group in [("blocking", "http::real_client_test"),
                                ("advisory", "client/nats::e2e_test")]:
                (results / name).mkdir(parents=True)
                (results / name / "healthy.status").write_text(f"passed\t{group}\n")
                (results / name / "healthy.log").write_text("test result: ok. 3 passed; 0 failed;\n")
            if status is not None:
                (results / tier / "interrupted.status").write_text(status)
            if log is not None:
                (results / tier / "interrupted.log").write_text(log)
            if complete:
                (results / "blocking" / "complete").touch()
            if advisory_complete:
                (results / "advisory" / "complete").touch()
            summary = root / "summary.md"
            run = subprocess.run(
                [sys.executable, str(SCRIPT)], cwd=checkout,
                env={**os.environ, "GITHUB_STEP_SUMMARY": str(summary),
                     "EVIDENCE_DIR": str(results), **(STEPS if steps is None else steps)},
                capture_output=True, text=True,
            )
            self.assertIn(run.returncode, (0, 1), run.stderr)
            self.assertEqual(run.stdout, summary.read_text() + "\n")
            self.assertEqual(list(checkout.iterdir()), [], "evidence must not modify the Cargo checkout")
            return run.returncode, summary.read_text()

    def test_complete_success_requires_positive_test_evidence(self):
        code, report = self.report()
        self.assertEqual(code, 0)
        self.assertIn("### Blocking real-client evidence: PASSED", report)
        self.assertIn("### Advisory real-client evidence: PASSED", report)
        self.assertIn("1/1 started groups, 3 passed tests", report)
        self.assertIn("**Job verdict: PASSED**", report)

    def test_partial_status_files_do_not_discard_healthy_groups(self):
        for status in ["", "passed", "passed\t", "unexpected\tsmb::real_client_test", "passed\tsmb\textra"]:
            with self.subTest(status=status):
                code, report = self.report(status)
                self.assertEqual(code, 1)
                self.assertIn("### Blocking real-client evidence: FAILED / INCOMPLETE", report)
                self.assertIn("| `http::real_client_test` | passed | 3 |", report)
                self.assertIn("INCOMPLETE (malformed status)", report)

    def test_missing_zero_or_truncated_logs_are_not_success(self):
        for log in [None, "", "test result: ok. 0 passed; 0 failed;", "test result: ok. 2"]:
            with self.subTest(log=log):
                code, report = self.report("passed\tsmb::real_client_test", log)
                self.assertEqual(code, 1)
                self.assertIn("### Blocking real-client evidence: FAILED / INCOMPLETE", report)
                self.assertIn("INCOMPLETE (no passing test result)", report)

    def test_a_loop_without_its_completion_marker_is_incomplete(self):
        code, report = self.report(complete=False)
        self.assertEqual(code, 1)
        self.assertIn("### Blocking real-client evidence: FAILED / INCOMPLETE", report)
        self.assertIn("unstarted groups have no evidence", report)

    def test_a_failed_blocking_group_fails_the_job(self):
        code, report = self.report("FAILED\tredis::real_client_test",
                                   "test result: FAILED. 1 passed; 1 failed;")
        self.assertEqual(code, 1)
        self.assertIn("| `redis::real_client_test` | FAILED | 0 |", report)
        self.assertIn("**Job verdict: FAILED - blocking evidence groups**", report)

    def test_a_failed_advisory_group_is_reported_but_does_not_fail_the_job(self):
        for kwargs in [dict(status="FAILED\tredis::resp3_test", log="test result: FAILED. 1 passed; 1 failed;"),
                       dict(advisory_complete=False)]:
            with self.subTest(**kwargs):
                code, report = self.report(tier="advisory", **kwargs)
                self.assertEqual(code, 0)
                self.assertIn("### Advisory real-client evidence: FAILED / INCOMPLETE", report)
                self.assertIn("### Blocking real-client evidence: PASSED", report)
                self.assertIn("**Job verdict: PASSED**", report)

    def test_a_failed_or_skipped_blocking_step_fails_the_job(self):
        for variable in STEPS:
            for outcome in ["failure", "skipped", "cancelled"]:
                with self.subTest(variable=variable, outcome=outcome):
                    code, report = self.report(steps={**STEPS, variable: outcome})
                    self.assertEqual(code, 1)
                    self.assertIn(f": {outcome}", report)
                    self.assertIn("**Job verdict: FAILED - ", report)

    def test_no_evidence_at_all_fails_the_job(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            run = subprocess.run(
                [sys.executable, str(SCRIPT)], cwd=directory,
                env={**os.environ, "GITHUB_STEP_SUMMARY": str(summary),
                     "EVIDENCE_DIR": str(Path(directory) / "absent"), "EVIDENCE_BUILD": "failure"},
                capture_output=True, text=True,
            )
            self.assertEqual(run.returncode, 1)
            self.assertIn("### Blocking real-client evidence: FAILED / INCOMPLETE", summary.read_text())
            self.assertIn("0/0 started groups", summary.read_text())


if __name__ == "__main__":
    unittest.main()
