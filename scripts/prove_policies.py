"""Print a human-readable proof certificate for every signed policy on disk.

Usage:  python scripts/prove_policies.py
Exit code 1 if any invariant is violated (CI gate equivalent of
tests/test_policy_proofs.py::test_signed_policies_prove_all_invariants).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.policy import verify_bundle                      # noqa: E402
from app.policy_proofs import prove_all, evasion_report   # noqa: E402

POLICIES = Path(__file__).resolve().parent.parent / "policies"


def main() -> int:
    ok = True
    for f in sorted(POLICIES.glob("*.signed.json")):
        bundle = verify_bundle(__import__("json").loads(f.read_text()))
        name = bundle.get("policy_id", f.name)
        print(f"\n=== {name} ({f.name}) ===")
        for inv, res in prove_all(bundle["rules"]).items():
            mark = "PROVED" if res["proved"] else "VIOLATED"
            print(f"  [{mark}] {inv}  ({res['ms']} ms)")
            if not res["proved"]:
                ok = False
                print(f"          counterexample: {res['counterexample']}")
        ev = evasion_report(bundle["rules"])
        print(f"  [EVASION] tier-0 radar-quiet ceiling: "
              f"{ev['tier0_bypass_max_amount_vs_mean']}x mean, "
              f"{ev['telecom_signals_bought']} telecom signals bought "
              f"(payee age {ev['payee_age_min']} min) — residual only: requires no "
              f"sensitive event in window AND escaping keyed sampling")
    print("\n" + ("ALL POLICIES PROVE ALL INVARIANTS" if ok
                  else "POLICY VIOLATION — DO NOT SIGN/SHIP"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
