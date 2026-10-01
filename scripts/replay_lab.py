"""Replay Lab CLI: python scripts/replay_lab.py input.json [--bank A] [--out report.json]

input.json = list of DecideRequest-shaped records (optional confirmed_fraud,
incumbent_decision, signals per record). Prints the executive summary and
writes the full signed report."""
import argparse, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.policy import DEFAULT_BANK_A, DEFAULT_BANK_B          # noqa: E402
from app.replaylab import replay, verify_report                 # noqa: E402
from tests.test_core import signed                              # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("--bank", default="A", choices=["A", "B"])
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    records = json.loads(Path(a.input).read_text(encoding="utf-8"))
    bad = [i for i, r in enumerate(records)
           if not (isinstance(r.get("amount"), (int, float)) and r.get("amount", 0) > 0
                   and isinstance(r.get("account_mean", 1), (int, float)) and r.get("account_mean", 0) > 0)]
    if bad:
        print(f"ERROR: records {bad} need positive amount and account_mean"); return 2
    doc = DEFAULT_BANK_A if a.bank == "A" else DEFAULT_BANK_B
    report = replay(records, signed(doc))
    v, b, fr, ex = report["volumes"], report["bypass"], report["friction"], report["exposure"]
    print(f"Replay Lab — {v['records']} records ({v['labeled']} labeled), bank {a.bank}")
    print(f"  bands: {v['bands']}")
    print(f"  tiers: {v['tiers']}   would-cost: ${v['would_cost_usd']}")
    print(f"  BYPASS (confirmed fraud approved): {b['count']}")
    for r in b["rows"][:5]:
        print(f"    - {r['txn_id']} ({r['band']})")
    print(f"  caught: {report['caught']['count']} | friction: {fr['count']} | tier-0 exposure: {ex['count']}")
    print(f"  incumbent matrix: {report['incumbent']}")
    print(f"  signature verifies: {verify_report(report)}")
    if a.out:
        Path(a.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"  full report -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
