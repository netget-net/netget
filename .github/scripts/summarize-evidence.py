#!/usr/bin/env python3
"""Publish partial evidence as well as a complete run; never infer success from silence.

Evidence groups are recorded under $EVIDENCE_DIR/<tier>/ by run-evidence-group.sh, where the
tier is `blocking` or `advisory`. Both are reported. The script exits non-zero when a blocking
part of the job did not pass: a blocking group that failed, ran no test, or never finished
(no `complete` marker), or a blocking step whose outcome the workflow passes in the
environment. Advisory failures are reported and never change the exit status.
"""

import os
from pathlib import Path
import re
import sys

results = Path(os.environ.get("EVIDENCE_DIR", "evidence-results"))

# Blocking steps outside the group loops, as `steps.<id>.outcome` values. An unset variable
# means the workflow did not pass it, which is not the same as a failure.
BLOCKING_STEPS = [
    ("Registry audits", "REGISTRY_AUDITS"),
    ("Evidence build", "EVIDENCE_BUILD"),
    ("Nostr browser exchange", "NOSTR_BROWSER"),
]


def read_tier(directory):
    rows = []
    for status_file in sorted(directory.glob("*.status")):
        # A cancellation can land after shell redirection truncates the file but before
        # printf writes its row. Preserve the other groups and report this one honestly.
        fields = status_file.read_text(errors="replace").strip().split("\t")
        if len(fields) == 2 and fields[0] in {"running", "passed", "FAILED"} and fields[1]:
            status, name = fields
        else:
            status, name = "INCOMPLETE (malformed status)", status_file.stem
        log = status_file.with_suffix(".log")
        counts = re.findall(r"test result: ok\. (\d+) passed;", log.read_text(errors="replace")) if log.exists() else []
        if status == "passed" and not sum(map(int, counts)):
            status = "INCOMPLETE (no passing test result)"
        rows.append((name, status, sum(map(int, counts))))
    complete = (directory / "complete").exists()
    passed = sum(status == "passed" for _, status, _ in rows)
    ok = complete and bool(rows) and passed == len(rows)
    return rows, complete, passed, ok


summary = []
blocking_failures = []

for tier, title in [("blocking", "Blocking"), ("advisory", "Advisory")]:
    rows, complete, passed, ok = read_tier(results / tier)
    verdict = "PASSED" if ok else "FAILED / INCOMPLETE"
    if tier == "blocking" and not ok:
        blocking_failures.append("blocking evidence groups")
    summary.extend([
        f"### {title} real-client evidence: {verdict}",
        "",
        f"Completed successfully: {passed}/{len(rows)} started groups, "
        f"{sum(count for _, status, count in rows if status == 'passed')} passed tests.",
        "" if complete else "The loop did not finish; unstarted groups have no evidence in this run.",
        "",
        "| Group | Result | Passed tests |",
        "| --- | --- | ---: |",
    ])
    summary.extend(f"| `{name}` | {status} | {count} |" for name, status, count in rows)
    summary.append("")

summary.extend(["### Blocking steps", ""])
for label, variable in BLOCKING_STEPS:
    outcome = os.environ.get(variable)
    if outcome is None:
        continue
    summary.append(f"- {label}: {outcome}")
    if outcome != "success":
        blocking_failures.append(label.lower())
summary.append(f"- Chromium setup (peer install, surfaces through the exchange): "
               f"{os.environ.get('NOSTR_BROWSER_SETUP', 'not run')}")
summary.append("")
summary.append("**Job verdict: " + ("PASSED" if not blocking_failures else
                                    "FAILED - " + ", ".join(blocking_failures)) + "**")

text = "\n".join(summary) + "\n"
print(text)
with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
    output.write(text)
sys.exit(1 if blocking_failures else 0)
