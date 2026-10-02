# CURRENT BUILD STATE

> GENERATED FILE — do not edit by hand. Regenerate: `python scripts/build_state.py`
> Verify everything: `python scripts/verify.py` (or `make verify`)

**Generated:** 2026-10-02 15:23 UTC · **branch:** main · **commit:** 8ed6500 · **tree:** DIRTY

## Status: ALL GREEN

| Check | Result |
|---|---|
| Test suite | 166 passed, 2 skipped, 1 warning in 15.04s |
| Z3 proof certificate | 16 invariants PROVED, 0 violated (ALL PROVE ALL INVARIANTS) |

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
