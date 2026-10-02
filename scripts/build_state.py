"""Generate CURRENT_BUILD_STATE.md from LIVE results — the single source of
truth for build state. Hand-maintained docs drift; this file cannot.

Runs the suite + proof certificate, then writes the state file.
Exit 1 if anything red. Usage:
    python scripts/build_state.py            # run + write
    python scripts/verify.py                 # verify == build_state + report
"""
from __future__ import annotations
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "CURRENT_BUILD_STATE.md"


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def git(*args: str) -> str:
    r = run(["git", *args])
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def main() -> int:
    t0 = time.time()
    suite = run([sys.executable, "-m", "pytest", "tests/", "-q"])
    passed = suite.stdout.strip().splitlines()[-1] if suite.stdout else "NO OUTPUT"
    suite_ok = " passed" in passed and "failed" not in passed and suite.returncode == 0

    proofs = run([sys.executable, "scripts/prove_policies.py"])
    proofs_ok = "ALL POLICIES PROVE ALL INVARIANTS" in proofs.stdout and proofs.returncode == 0
    inv_lines = [l.strip() for l in proofs.stdout.splitlines() if "PROVED" in l or "VIOLATED" in l]
    n_proved = sum(1 for l in inv_lines if "[PROVED]" in l)
    n_violated = sum(1 for l in inv_lines if "[VIOLATED]" in l)

    ok = suite_ok and proofs_ok
    commit = git("rev-parse", "--short", "HEAD")
    date = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    dirty = git("status", "--porcelain", "--", ".")
    # ignore the generated file itself: a fresh regeneration must not turn a
    # clean tree dirty (timestamp-only churn) — the file's own stamp stays true
    dirty = "\n".join(l for l in dirty.splitlines()
                      if l.strip() and "CURRENT_BUILD_STATE.md" not in l)

    body = f"""# CURRENT BUILD STATE

> GENERATED FILE — do not edit by hand. Regenerate: `python scripts/build_state.py`
> Verify everything: `python scripts/verify.py` (or `make verify`)

**Generated:** {date} · **branch:** {branch} · **commit:** {commit} · **tree:** {'clean' if not dirty else 'DIRTY'}

## Status: {'ALL GREEN' if ok else 'RED — SEE BELOW'}

| Check | Result |
|---|---|
| Test suite | {passed} |
| Z3 proof certificate | {n_proved} invariants PROVED, {n_violated} violated ({'ALL PROVE ALL INVARIANTS' if proofs_ok else 'FAILURE'}) |

## Wired (build-week commits d8526b5..8b750b9 + later)

Cost tiers T0/T1/T2 ($0 quiet traffic) · jitter (default OFF, HMAC-keyed, opt-in per bank)
· aged-swap rule R6 · payee-velocity hard rule R7 · coached-payment hold R8 (cooling-off +
bank-held callback) · event-forced screening (payee_added→T1; reset/device/login→T2) +
keyed 2% Tier-0 sampling · UNKNOWN ≠ clean semantics (data_quality + trigger provenance)
· severe-signal floor (green never dilutes red) · ChannelLock signed step-up grants
(local verify, shadow/alert/enforce, mock gateway + audit) · governor/sidecar mode
(never-downgrade + Tier-0 counterfactual) · verdict signatures (stable-field canonical,
ledger-persisted) · Replay Lab (signed lift/bypass/counterfactual reports) · Z3 invariants
I1–I6 as a signing gate + CLI certificate + randomized differential vs the live engine.

## Open items (honest, tracked)

| Item | Owner | Note |
|---|---|---|
| Rotate exposed keys (NaC / Gemini / GitHub PAT) | FOUNDER | oldest open item — before anything public-adjacent |
| Tenant identity from mTLS (bank field still selects policy) | production | prototype-only; pre-enforce MUST |
| KMS/HSM key custody (maker/checker/channellock/verdict on one host) | production | demo theater until split custody |
| In-process nonce store + decision cache (restart = one re-decide in flight) | production | gateway store closes it |
| JSONL ledgers single-host (no HA/DR; ~3k appends/s offline proof) | production | pilot-scale sufficient |
| Commercial CAMARA coverage (sandbox resolves simulator numbers only) | GATE | Qatar live (Ooredoo/VF); KSA entitlement = the question |
| p95 525 ms > 450 budget at sandbox RTT (internal ~3 ms; 94% in budget) | posture-cache workstream | panel-approved corrected spec queued |
| Entity filing / advisor / outreach emails | FOUNDER | modal death while unsent (review panel unanimous) |

## Companion repos

- github.com/omarxhero/tasdiq — frozen hackathon archive (21 tests)
- github.com/omarxhero/tasdiq-business — public business repo (curated publish tree)
- this private fork — full history incl. internal sales kit
"""
    if OUT.exists():
        old = OUT.read_text(encoding="utf-8").splitlines()
        new_body = [l for l in body.splitlines() if not l.startswith("**Generated:**")]
        old_cmp = [l for l in old if not l.startswith("**Generated:**")]
        if old_cmp == new_body:
            print("[build_state] unchanged (timestamp-only) — keeping stable file")
            print(f"[build_state] suite: {passed} | proofs: {n_proved} proved / {n_violated} violated -> {'GREEN' if ok else 'RED'}")
            return 0 if ok else 1
    OUT.write_text(body, encoding="utf-8")
    print(f"[build_state] suite: {passed} | proofs: {n_proved} proved / {n_violated} violated")
    print(f"[build_state] wrote {OUT.name} in {time.time()-t0:.1f}s -> {'GREEN' if ok else 'RED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
