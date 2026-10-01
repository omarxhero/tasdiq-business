# Tasdiq — Threat Model & Production Delta

Read this before the code review, not after. Stating our own limits first is
the design principle (claims boundary); this document is that principle
applied to security and operations.

## 1. What this prototype is NOT (the delta to production)

| Area | Prototype (today) | Production delta |
|---|---|---|
| Key custody | **Maker + checker Ed25519 keys generated on one machine, held by one person — the two-person control is DEMO THEATER and we say so.** Production requires KMS/HSM split custody, one persona per officer, ceremony-log generation | KMS/HSM (bank-held or sovereign cloud), signing ceremony, key-rotation policy |
| Transport | Plain HTTP; optional gateway HMAC (`TASDIQ_GATEWAY_SECRET`) over raw body | mTLS both directions, gateway-enforced IP allowlists, payload signatures, nonce/replay window at the gateway idempotency store |
| Vault pepper / ledger pepper | env var / default dev value on the demo deploy | KMS-managed, per-deployment, rotation procedure |
| Operator routing | Static 4-prefix map behind `OperatorResolver` | MNP feed / HLR dip behind `CachedMNPResolver` (the seam exists: `app/signals/resolver.py`) |
| Number Verification | OAuth client wired (`NUMVERIFY_MODE=oauth`); device-bound consent is the documented environmental limit — degrades labeled, never fabricates | Bank-app SDK completes the 3-legged device consent; full silent-auth path |
| Scale | Single process, JSONL ledgers, O(1) appends after startup scan (see `loadtest.py` + `evidence/load_test.json`) | Partitioned ledger store, replicated writes; the load table is the baseline to beat |
| Idempotency | In-process decision cache keyed on `txn_id`; a restart may re-decide an in-flight txn once | Gateway idempotency-key store (Redis/class) shared across instances |
| LLM lane | Gemini via API key; schema-locked outputs; template fallback | Self-hosted open weights in the bank's private cloud for data-sovereign deployments (model-agnostic design) |
| Z3 proofs | **Wired**: `app/policy_proofs.py` models the engine symbolically (incl. degradation states + early exit) and PROVES per signed bundle: I1 live-swap never approves · I2 all-signals-lost + anomaly never approves · I3 payee-velocity trap always fires · I4 amount never UN-blocks. Differential check vs real engine (80 random inputs, boundary-guarded) keeps the model faithful; CLI certificate `scripts/prove_policies.py`; CI gate = tests. Findings already shipped: prover exposed bank-b escalate 62 > trap score 60 → trap became hard rule R7; also quantified Tier-0 radar-quiet ceiling (19x, zero signals) for the queued event-forced fix | Model rule 6 (aged window) + keyed jitter; proof-of-uniqueness survey before claiming "first" |
| Severe-signal floor | **Wired**: evaluate() floors the weighted risk at the strongest single signal contribution — green signals can never dilute a red one (40-risk swap stayed 40, not 10); Z3 model floored identically, differential re-verified | calibrated floors per bank once real labels exist |
| Jitter default | **Flipped OFF** (panel verdict 4–1): threshold_jitter_pct now defaults to 0; opt-in per bank; keying fixed — HMAC(deployment pepper, txn_id) instead of predictable sha256(txn_id); exact used thresholds still recorded per verdict for replay |
| Verdict signatures | **Wired**: `app/verdict_sig.py` — every /v1/decide verdict carries an Ed25519 signature over a canonical replay-stable projection (decision, band, risks, policy hash, thresholds, step_up, cost core, data_quality, hold; latency deliberately excluded — timing is not identity, idempotent replays return the identical signature); ledger intercept records persist the signature (the evidence chain carries the decision's own proof, not just the policy's); verify_verdict() recomputes — tamper matrix breaks, msisdn binding enforced | KMS/HSM custody + rotation for the maker persona (same known limit as policy keys) |
| UNKNOWN context semantics | **Wired**: omitted fields never read as clean — engine sentinels + API model_fields_set injection make missing payee-age / attempts / account_mean = UNKNOWN ⇒ forced screening (tier ≥ 1), data_quality.unknown_fields on the verdict, trigger provenance `unknown:…`; missing account_mean no longer produces phantom spike math (old default 1.0 made ratio = amount); explicitly-sent values honored as known; Replay Lab rows carry data_quality so a bank log missing a column is visible, not silently clean | per-field source/timestamp envelopes (full provenance objects) if a buyer asks |
| Tier-0 event-forced screening | **Wired**: sensitive events (payee_added → SIM screening; credential_reset / device_registration / login_anomaly → full sweep) force signal purchase regardless of radar quietness, within policy window (event_window_minutes default 60); keyed deterministic 2% Tier-0 sampling (tier0_sample_rate, pepper = VAULT_KEY — grind-resistant, replay-stable); provenance trigger field (event:X / sample / severe / radar / none) on every verdict; Z3 invariant I6: an event can never ride Tier 0 — structural, policy-independent | confirmed-fraud feedback into tier rules (calibration on real labels — needs pilot data); CAMARA event subscriptions (push instead of poll) |
| Replay Lab | **Wired**: `app/replaylab.py` + `/v1/replaylab` + `scripts/replay_lab.py` — ingests a pseudonymized historical log (DecideRequest-shaped; optional confirmed_fraud labels, incumbent_decision, recorded signals), replays OFFLINE (recorded signals or UNAVAILABLE(replay) — never fabricated green), and returns an Ed25519-signed report (maker persona, content-hash + signature, tamper-evident): decision/band/tier distribution + would-cost, BYPASS = confirmed-fraud records the policy APPROVES (listed), caught count, friction on non-fraud traffic, tier-0 counterfactual exposure, incumbent agreement matrix. 10 tests incl. tamper + determinism + endpoint | Real bank log ingestion adapters; per-record recorded-signal schemas; label-quality caveats documented in report header |
| Coached payment (R8) | **Wired**: bank-app call-state inputs (call_in_progress/direction/duration, Literal-validated) → hard rule COOLING_OFF_HOLD — nothing completes while the call is live (allowed=[], SMS+VOICE prohibited; the ChannelLock grant therefore dispatches nothing), hold block carries release window (policy call_cooldown_minutes, default 30) + bank-held-number callback; coached forces tier-2 full sweep; swap evidence still outranks; Z3 invariant I5 proves a live call NEVER yields APPROVE for every input | Telecom Scam Signal (call-in-progress from the network, not just the handset) when Gulf-available; callback orchestration is bank-side |
| Governor / sidecar | **Wired**: `mode="sidecar"` accepts the incumbent fraud engine's score/decision (incumbent_score, incumbent_vendor, incumbent_decision); guarantees G1 never-downgrade (final ≥ incumbent, monotone in score — tested 0..100) and G2 hardening (telecom hard rules still fire on top); swap-band SMS prohibitions survive governor composition; Tier-0 verdicts carry the COUNTERFACTUAL (verdict under a hypothetical live swap, synthetic $0 signal) — per-decision evidence of no-coverage exposure; rail mode default unchanged | Incumbent-adapter schemas per vendor (Feedzai/Actimize score semantics), counterfactual aggregation dashboard = Replay Lab |
| ChannelLock | **Wired**: every verdict carries a short-lived (60–120 s) Ed25519-signed step-up grant (allowed/prohibited channels, policy hash, nonce, tenant audience); reference verifier `app/channellock.py` = the bank-side SDK — local verification, no Tasdiq call, outage never re-enables SMS; mock OTP gateway `/v1/stepup/dispatch` with enforce/alert/shadow modes + audit trail; 12 tests | Bank-side SDK packaging + key distribution ceremony; nonce store moves to gateway-local store; KMS/HSM custody for the channellock key persona |
| Cost tiers | **Wired**: Tier 0 quiet traffic buys no signal ($0, basis BEHAVIORAL_ONLY); Tier 1 mild flag buys SIM Swap; Tier 2 severe flag full sweep + aged-window SIM query. `signals_bought` + `cost_estimate_usd` recorded per verdict | Per-bank tier aggressiveness tuning against live mix; per-signal price feed instead of policy constants |
| Threshold jitter | **Wired**: deterministic ±3% (policy `threshold_jitter_pct`) seeded on `txn_id`; exact values in `thresholds_used` for replay | Wider knob set per bank; adversarial probing telemetry |
| Aged-swap window | **Wired**: rule 6 corroboration — swap inside `aged_window_hours` (default 240h) but outside recent window + behavioral anomaly ⇒ ESCALATE (SMS allowed); +20 risk; never declines alone | Calibrate two windows per bank on real swap-recency distributions |
| Payee-velocity trap | **Wired**: `new_payee_repeats` request field (bank-computed) — >=2 adds +30 and forces Tier 2 | Bank-side payee-graph service computing repeats across accounts |

## 2. STRIDE-lite over the decision path

| Threat | Control (present) | Gap (named) |
|---|---|---|
| **S**poofed bank caller | gateway HMAC over raw body when secret set | mTLS + allowlist (delta above) |
| **T**ampered policy thresholds | Ed25519 maker-checker signatures; tampered bundle rejected on every decide; bootstrap re-signs only from trusted templates | Real two-person custody (delta above) |
| **R**epudiated decision | hash-chained intercept ledger, content-hash recompute on verify, RFC 3161 anchor queue, policy_version_hash bound per decision | anchor receipts stored, not yet verified on read |
| **I**nformation disclosure (PII) | HMAC-pseudonymized MSISDNs in ledgers; Fernet vault; PII-sealed tool belt; LLM context is free-text-free by construction | vault map file rewrite per put (fine at pilot scale; batch flush at volume) |
| **D**enial of service on the rail | per-operator breakers, deadline budgeter, degrade-never-approve semantics | rate limiting + worker isolation at gateway |
| **E**levation via prompt injection | memos excluded from model context by construction; schema-locked outputs (now constrained decoding); canary test; deterministic proportionality policy | none known — canary must stay in CI forever |

## 3. Known accepted limitations (honest list)

1. `replay()` / `verify_chains()` read the JSONL without the append lock — a
   read racing an append could see a partial last line (rare; local append +
   newline-atomic on the platforms we run).
2. `txn_index` and the idempotency cache are in-memory; restart loses them
   (one re-decide per in-flight txn worst case). Two *simultaneous* requests
   with the same `txn_id` (race before the first response lands) can also
   both decide — the gateway idempotency-key store closes this in production.
3. Number Verification's device-consent step cannot complete server-side in
   the sandbox (dated attempt log, HANDOFF §7.5). The client is wired; the
   limitation is documented, and the degraded path TIGHTENS decisions.
4. The demo deployment (`render.yaml`) runs the prototype surface for
   evaluators; production topology is the README "Deployment topology" note.

*This file is the leave-behind for bank security reviewers. If they find
something not on this list, the document failed — tell us and it gets added
the same day.*
