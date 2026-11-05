"""Command line interface."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from .analyzer import analyze_bundle, load_bundle, load_policy


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate AI model and image supply-chain evidence")
    parser.add_argument("bundle", help="Release evidence bundle JSON")
    parser.add_argument("--policy", default="policy/supply-chain-policy.json")
    parser.add_argument("--now", help="ISO-8601 evaluation time for deterministic replay")
    parser.add_argument("--output", choices=("text", "json"), default="text")
    args = parser.parse_args()
    now = datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now else datetime.now(timezone.utc)
    report = analyze_bundle(load_bundle(args.bundle), load_policy(args.policy), now)
    if args.output == "json":
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Decision: {report.decision} | Score: {report.score} | Verified artifacts: {report.verified_artifacts}")
        for finding in report.findings:
            print(f"[{finding.severity}] {finding.rule_id} {finding.subject}: {finding.message}")
    return 0 if report.decision == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
