"""Verify everything: suite + proofs + CURRENT_BUILD_STATE regeneration.
The one command a reviewer runs. Exit 0 only if all green."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

steps = [
    ("test suite", [sys.executable, "-m", "pytest", "tests/", "-q"]),
    ("Z3 proof certificate", [sys.executable, "scripts/prove_policies.py"]),
    ("build state regeneration", [sys.executable, "scripts/build_state.py"]),
]
ok = True
for name, cmd in steps:
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    last = (r.stdout or "").strip().splitlines()[-1] if (r.stdout or "").strip() else r.returncode
    good = r.returncode == 0
    ok &= good
    print(f"[verify] {name}: {'PASS' if good else 'FAIL'} — {last}")
print(f"[verify] RESULT: {'ALL GREEN' if ok else 'RED'}")
raise SystemExit(0 if ok else 1)
