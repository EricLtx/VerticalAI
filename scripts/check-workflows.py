#!/usr/bin/env python3
"""Load every GitHub Actions workflow and assert its job names.

Not part of `cargo test`: nothing here is Rust, and the thing being checked
— that a workflow file still parses as YAML, and that a job was not silently
renamed or dropped while editing one — is a YAML-and-GitHub-Actions concern,
not a Rust one. Block-style YAML is required throughout the workflows for
exactly the failure mode this script exists to catch: a flow mapping
(`{ key: value }`) containing a `${{ }}` expression reads as a broken map to
a standard YAML parser even though GitHub's own preprocessor accepts it, so a
`yaml.safe_load` here is the same check a contributor's editor cannot give
them.

Usage: `python scripts/check-workflows.py`. Exits non-zero on any failure.
"""

import pathlib
import sys

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

# The job names each workflow must have, by exact set. A job silently
# renamed, dropped, or gained is exactly the kind of mistake worth catching
# in one place rather than by reading a diff carefully every time.
EXPECTED_JOBS = {
    "ci.yml": {"test", "arch-ollama", "sign"},
    "release.yml": {"build"},
}


def check_one(path: pathlib.Path) -> list[str]:
    """Return the failures found in one workflow file (empty: none)."""
    failures: list[str] = []
    text = path.read_text(encoding="utf-8")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return [f"{path.name}: does not parse as YAML: {e}"]

    if not isinstance(doc, dict):
        return [f"{path.name}: top level is not a mapping"]

    # PyYAML resolves an unquoted `on` as the YAML 1.1 boolean `True`, not the
    # string "on" — every workflow here writes `on:` as the trigger mapping,
    # so this also catches an `on:` block that stopped parsing as one (for
    # instance a stray flow-style `{ ... }` swallowing the key after it).
    if "on" not in doc and True not in doc:
        failures.append(f"{path.name}: no 'on:' trigger block")

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        failures.append(f"{path.name}: no non-empty 'jobs:' mapping")
        return failures

    job_names = set(jobs.keys())
    expected = EXPECTED_JOBS.get(path.name)
    if expected is None:
        print(f"{path.name}: no expected-jobs entry for this file; found {sorted(job_names)}")
    elif job_names != expected:
        missing = expected - job_names
        extra = job_names - expected
        detail = []
        if missing:
            detail.append(f"missing {sorted(missing)}")
        if extra:
            detail.append(f"unexpected {sorted(extra)}")
        failures.append(f"{path.name}: job names wrong — {', '.join(detail)}")
    else:
        print(f"{path.name}: jobs ok ({', '.join(sorted(job_names))})")

    return failures


def main() -> int:
    workflows = sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml"))
    if not workflows:
        print(f"no workflow files found under {WORKFLOWS_DIR}", file=sys.stderr)
        return 1

    failures: list[str] = []
    seen = set()
    for path in workflows:
        seen.add(path.name)
        failures.extend(check_one(path))

    missing_files = set(EXPECTED_JOBS) - seen
    if missing_files:
        failures.append(f"expected workflow file(s) not found: {sorted(missing_files)}")

    if failures:
        print("FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"{len(workflows)} workflow file(s) OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
