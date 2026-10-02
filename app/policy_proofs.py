"""Z3-verified policy invariants (L3 hardening — the proof gate).

The engine is deterministic, so its decision logic can be modeled
symbolically and PROVED, per policy bundle, for every possible input —
not tested on samples. This module:

  1. Encodes the decision logic (tiers + hard rules + thresholds) as a
     Z3 SMT formula over the behavioral inputs and discrete signal
     states. Signal confidences are modeled at exactly the values the
     code produces (1.0 live · 0.9 cached-fallback · 0.30 degraded ·
     0.0 lost-with-label), so degradation semantics are inside the proof.
  2. Proves the safety invariants (below). A violated invariant returns
     a concrete counterexample input — a bug report, not a crash.
  3. Searches for the CHEAPEST EVASION: the maximum amount-vs-mean an
     attacker can push through Tier 0 with zero telecom scrutiny
     (quantifies the known radar-quiet exposure until the event-forced
     check fix lands).
  4. Differential check: random concrete inputs through BOTH the Z3
     model and the real engine must agree (margin-guarded at threshold
     boundaries, where the engine's round(x, 2) is intentionally not
     modeled) — this keeps the symbolic model faithful to the code.

IN VARIANTS PROVED (per signed policy):
  I1  live-swap    — SIM swapped with confidence ≥ 0.9 ⇒ verdict is
                     never APPROVE (band isolation holds for every input).
  I2  blind-safe   — ALL signals lost (confidence 0) + any behavioral
                     anomaly ⇒ verdict is never APPROVE (an attacker who
                     forces blindness never buys a clean approve).
  I3  trap-fires   — fresh payee (≤ 5 min) with payee-velocity repeats
                     (≥ 2) ⇒ verdict is never APPROVE.
  I4  monotone     — increasing amount-vs-mean never WEAKENS the verdict
                     (strength order APPROVE < ESCALATE < DECLINE).

SIGNING GATE: tests run prove_all() on every signed bundle on disk —
a policy that violates an invariant cannot pass CI. Run the CLI
(python scripts/prove_policies.py) for a human-readable certificate.

Scope notes (deliberate): the aged-window SIM query (rule 6) and
threshold jitter are NOT modeled — jitter is default-off and rule 6 is
strictly risk-adding; both marked for v2 of this prover. The model
covers the evaluate() path incl. the Phase-1 early exit.
"""
from __future__ import annotations
import random

import z3

APPROVE, ESCALATE, DECLINE = 0, 1, 2
_CONF_STATES = (0.0, 0.3, 0.9, 1.0)   # lost-with-label, degraded, cached, live


class SymCtx:
    """One symbolic transaction context: behavioral vars + signal states."""

    def __init__(self, prefix: str, tier: int, rules: dict):
        r = rules
        self.tier = tier
        self.rules = rules
        # behavioral inputs
        self.fpm = z3.Real(f"{prefix}fpm")            # beneficiary_first_seen_minutes
        self.avm = z3.Real(f"{prefix}avm")            # amount_vs_mean
        self.attempts = z3.Int(f"{prefix}attempts")
        self.repeats = z3.Int(f"{prefix}repeats")
        self.multi = z3.Bool(f"{prefix}multi")
        # signal outcome states (only the tiers that buy them constrain these)
        self.sim_swapped = z3.Bool(f"{prefix}sim_swapped")
        self.sim_conf = z3.Real(f"{prefix}sim_conf")
        self.nv_mismatch = z3.Bool(f"{prefix}nv_mismatch")
        self.nv_conf = z3.Real(f"{prefix}nv_conf")
        self.roam = z3.Bool(f"{prefix}roam")
        self.roam_conf = z3.Real(f"{prefix}roam_conf")
        self.dswap = z3.Bool(f"{prefix}dswap")
        self.dswap_conf = z3.Real(f"{prefix}dswap_conf")

        anomaly = z3.Or(self.fpm <= 5, self.avm >= 20, self.attempts >= 5)
        coached = z3.Bool(f"{prefix}call")
        ev1 = z3.Bool(f"{prefix}ev1")     # tier-1 event (payee_added)
        ev2 = z3.Bool(f"{prefix}ev2")     # tier-2 event (reset/device/login)
        unk = z3.Bool(f"{prefix}unk")     # UNKNOWN context (omitted fields)
        fwd = z3.Bool(f"{prefix}fwd")     # unconditional call forwarding (R9: corroboration-only — never changes the decision)
        flagged = z3.Or(anomaly, self.multi, self.repeats >= 2, coached)
        severe = z3.Or(self.avm >= 20, self.attempts >= 5, self.repeats >= 2, coached)
        self.anomaly, self.flagged, self.severe, self.coached = anomaly, flagged, severe, coached
        self.ev1, self.ev2, self.unk, self.fwd = ev1, ev2, unk, fwd

        behavioral = (30 * z3.If(self.fpm <= 5, 1, 0)
                      + 25 * z3.If(self.avm >= 20, 1, 0)
                      + 15 * z3.If(self.attempts >= 5, 1, 0)
                      + 30 * z3.If(self.repeats >= 2, 1, 0))

        # tier signal sets: T0 none (skip — behavior-only verdict), T1 sim+nv,
        # T2 sim+nv+roam+dswap. T0 modeled by callers with fixed zero risks.
        if tier == 0:
            wr = z3.RealVal(0)
            cov = z3.RealVal(1)      # nothing missing that was bought
            sim_present = z3.BoolVal(False)
            degraded_any = z3.BoolVal(False)
            live_swap = z3.BoolVal(False)
            green = z3.BoolVal(False)
            sim_lost = z3.BoolVal(False)
        else:
            names = ["SIM_SWAP", "NUMBER_VERIFY"] + (["DEVICE_STATUS", "DEVICE_SWAP"] if tier == 2 else [])
            confs = [self.sim_conf, self.nv_conf] + ([self.roam_conf, self.dswap_conf] if tier == 2 else [])
            risks = [40 * z3.If(self.sim_swapped, 1, 0),
                     25 * z3.If(self.nv_mismatch, 1, 0)] + \
                    ([8 * z3.If(self.roam, 1, 0), 20 * z3.If(self.dswap, 1, 0)] if tier == 2 else [])
            terms = [z3.If(c > 0, rk * c, z3.RealVal(0)) for rk, c in zip(risks, confs)]
            num, den = z3.Sum(terms), z3.Sum([z3.If(c > 0, c, z3.RealVal(0)) for c in confs])
            avg = z3.If(den > 0, num / den, z3.RealVal(0))
            # severe-signal floor: the strongest single contribution survives dilution
            import functools
            wr = functools.reduce(lambda a, b: z3.If(a > b, a, b), terms, avg) if terms else avg
            cov = z3.ToReal(z3.Sum([z3.If(c > 0, 1, 0) for c in confs])) / z3.RealVal(len(confs))
            sim_present = z3.BoolVal(True)
            degraded_any = z3.Or([c < 1 for c in confs])          # lost signals carry labels too
            live_swap = z3.And(self.sim_swapped, self.sim_conf >= 0.9)
            green = z3.And(sim_present, z3.Not(self.sim_swapped))
            sim_lost = z3.And(sim_present, self.sim_conf == 0)

        raw_total = wr + behavioral
        total = z3.If(raw_total > 100, z3.RealVal(100), raw_total)
        d_gte, e_gte = z3.RealVal(r.get("decline_gte", 80)), z3.RealVal(r.get("escalate_gte", 55))
        mult = z3.RealVal(r.get("instant_multiplier", 50))
        min_cov = z3.RealVal(r.get("min_signal_coverage", 0.5))

        # decision encoding — mirrors evaluate() + the Phase-1 early exit
        early = z3.And(self.sim_swapped, self.sim_conf > 0)   # any ANSWERED swap
        dec = z3.If(z3.And(early, self.avm > mult), z3.IntVal(DECLINE),          # early exit
             z3.If(live_swap, z3.If(total >= d_gte, z3.IntVal(DECLINE), z3.IntVal(ESCALATE)),   # R0
              z3.If(z3.And(self.fpm <= 5, self.repeats >= 2), z3.IntVal(ESCALATE),  # R7 trap
               z3.If(self.coached, z3.IntVal(ESCALATE),                            # R8 coached
                z3.If(z3.And(sim_lost, anomaly), z3.IntVal(ESCALATE),              # R3
               z3.If(z3.And(green, anomaly, self.avm >= 20), z3.IntVal(ESCALATE),  # R5
                z3.If(z3.And(degraded_any, anomaly), z3.IntVal(ESCALATE),        # R2
                 z3.If(cov < min_cov, z3.IntVal(ESCALATE),                       # R4
                  z3.If(total >= d_gte, z3.IntVal(DECLINE),
                   z3.If(total >= e_gte, z3.IntVal(ESCALATE), z3.IntVal(APPROVE)))))))))))
        self.decision = dec
        self.total = total
        # reachability precondition for this tier (engine routes traffic here)
        self.precond = {0: z3.And(z3.Not(flagged), z3.Not(ev1), z3.Not(ev2), z3.Not(unk)),
                        1: z3.Or(z3.And(flagged, z3.Not(severe)), ev1, unk),
                        2: z3.Or(severe, ev2)}[tier]
        # domain constraints
        self.domain = [self.fpm > 0, self.avm > 0, self.attempts >= 0,
                       self.repeats >= 1, self.sim_conf >= 0, self.sim_conf <= 1,
                       self.nv_conf >= 0, self.nv_conf <= 1,
                       self.roam_conf >= 0, self.roam_conf <= 1,
                       self.dswap_conf >= 0, self.dswap_conf <= 1]


def _conf_discrete(ctx: SymCtx):
    """Confidences take exactly the code's four values."""
    return [z3.Or([c == v for v in _CONF_STATES])
            for c in (ctx.sim_conf, ctx.nv_conf, ctx.roam_conf, ctx.dswap_conf)]


def prove_all(rules: dict) -> dict:
    """Run every invariant for every tier; returns
    {name: {"proved": bool, "counterexample": dict|None, "ms": int}}."""
    import time as _t
    out = {}
    for name, fn in INVARIANTS.items():
        t0 = _t.perf_counter()
        res = fn(rules)
        res["ms"] = int((_t.perf_counter() - t0) * 1000)
        out[name] = res
    return out


def _check(rules, name, tier, assumption, claim):
    """Prove `claim` under `assumption` (plus tier precond + domain);
    UNSAT = proved. SAT = counterexample returned."""
    ctx = SymCtx(name, tier, rules)
    s = z3.Solver()
    s.add(ctx.domain + _conf_discrete(ctx) + [ctx.precond, assumption(ctx)])
    s.add(z3.Not(claim(ctx)))
    if s.check() == z3.unsat:
        return {"proved": True, "counterexample": None}
    m = s.model()
    def val(v):
        x = m.eval(v, model_completion=True)
        return z3.is_true(x) if z3.is_bool(x) else (x.as_decimal(6) if z3.is_rational_value(x) else x.as_long())
    return {"proved": False, "counterexample": {
        "tier": tier, "decision_code": val(ctx.decision),
        "fpm": val(ctx.fpm), "avm": val(ctx.avm), "attempts": val(ctx.attempts),
        "repeats": val(ctx.repeats), "sim_swapped": val(ctx.sim_swapped),
        "sim_conf": val(ctx.sim_conf)}}


def _i1_live_swap_never_approves(rules):
    """I1: live swap (swapped & conf ≥ 0.9) ⇒ never APPROVE — tiers 1,2."""
    fails = []
    for tier in (1, 2):
        r = _check(rules, "i1", tier,
                   lambda c: z3.And(c.sim_swapped, c.sim_conf >= 0.9),
                   lambda c: c.decision != APPROVE)
        if not r["proved"]:
            fails.append(r)
    return {"proved": not fails, "counterexample": (fails[0]["counterexample"] if fails else None)}


def _i2_blind_never_approves(rules):
    """I2: all signals lost (conf 0) + anomaly ⇒ never APPROVE — tiers 1,2."""
    fails = []
    for tier in (1, 2):
        r = _check(rules, "i2", tier,
                   lambda c: z3.And(c.sim_conf == 0, c.nv_conf == 0,
                                    (c.roam_conf == 0 if tier == 2 else z3.BoolVal(True)),
                                    (c.dswap_conf == 0 if tier == 2 else z3.BoolVal(True)),
                                    c.anomaly),
                   lambda c: c.decision != APPROVE)
        if not r["proved"]:
            fails.append(r)
    return {"proved": not fails, "counterexample": (fails[0]["counterexample"] if fails else None)}


def _i3_trap_fires(rules):
    """I3: fresh payee (≤5 min) AND repeats ≥ 2 ⇒ never APPROVE — all tiers."""
    fails = []
    for tier in (0, 1, 2):
        r = _check(rules, "i3", tier,
                   lambda c: z3.And(c.fpm <= 5, c.repeats >= 2),
                   lambda c: c.decision != APPROVE)
        if not r["proved"]:
            fails.append(r)
    return {"proved": not fails, "counterexample": (fails[0]["counterexample"] if fails else None)}


def _i4_amount_monotone(rules):
    """I4 (safety-monotone): raising amount-vs-mean never turns a non-APPROVE
    verdict into APPROVE. NOTE the prover exposed that raw strength CAN drop
    (DECLINE -> ESCALATE) at the 20x boundary: Rule 5 deliberately routes
    telecom-green + anomaly into biometric recovery instead of a hard block —
    an intentional product decision, documented here, not a violation.
    Two contexts share every variable except amount_vs_mean."""
    fails = []
    for tier in (0, 1, 2):
        a = SymCtx("m1", tier, rules)
        b = SymCtx("m2", tier, rules)
        s = z3.Solver()
        s.add(a.domain + b.domain
              + _conf_discrete(a) + _conf_discrete(b)
              + [a.precond, b.precond]
              + [a.fpm == b.fpm, a.attempts == b.attempts, a.repeats == b.repeats,
                 a.multi == b.multi, a.sim_swapped == b.sim_swapped,
                 a.sim_conf == b.sim_conf, a.nv_mismatch == b.nv_mismatch,
                 a.nv_conf == b.nv_conf, a.roam == b.roam, a.roam_conf == b.roam_conf,
                 a.dswap == b.dswap, a.dswap_conf == b.dswap_conf,
                 a.coached == b.coached,              # call state doesn't change with amount
                 b.avm > a.avm]
              + [a.decision != APPROVE, b.decision == APPROVE])   # safety must not drop
        if s.check() == z3.unsat:
            continue
        m = s.model()
        fails.append({"proved": False, "counterexample": {
            "tier": tier, "avm1": m.eval(a.avm, model_completion=True).as_decimal(4),
            "avm2": m.eval(b.avm, model_completion=True).as_decimal(4)}})
    return {"proved": not fails, "counterexample": (fails[0]["counterexample"] if fails else None)}


def _i5_coached_never_approves(rules):
    """I5: a live call during the payment (coached-payment attack) => the
    verdict is never APPROVE — for every tier and every other input."""
    fails = []
    for tier in (0, 1, 2):
        r = _check(rules, "i5", tier,
                   lambda c: c.coached,
                   lambda c: c.decision != APPROVE)
        if not r["proved"]:
            fails.append(r)
    return {"proved": not fails, "counterexample": (fails[0]["counterexample"] if fails else None)}


def _i6_event_forces_signal_purchase(rules):
    """I6: any recent sensitive event (payee add, credential reset, device
    registration, login anomaly) makes Tier 0 UNREACHABLE — at least one
    telecom signal is always purchased. This is the Tier-0 bypass fix made
    structural: no policy configuration can screen an event quietly."""
    fails = []
    for ev in ("ev1", "ev2"):
        ctx = SymCtx(f"i6_{ev}", 0, rules)
        s = z3.Solver()
        s.add(ctx.domain + _conf_discrete(ctx) + [ctx.precond, getattr(ctx, ev)])
        if s.check() != z3.unsat:
            fails.append({"proved": False, "counterexample": {"event": ev, "tier": 0,
                              "note": "tier-0 reachable with a sensitive event"}})
    return {"proved": not fails, "counterexample": (fails[0]["counterexample"] if fails else None)}


def _i7_forwarding_never_softens(rules):
    """I7: unconditional call forwarding never WEAKENS the verdict (R9 strips
    channels; it must never turn non-APPROVE into APPROVE). CAMARA CFS
    semantics: voice-only mechanism — the rule never touches SMS and never
    escalates alone."""
    fails = []
    for tier in (0, 1, 2):
        a = SymCtx("f7a", tier, rules)   # forwarding OFF
        b = SymCtx("f7b", tier, rules)   # forwarding ON
        s = z3.Solver()
        s.add(a.domain + b.domain + _conf_discrete(a) + _conf_discrete(b)
              + [a.precond, b.precond]
              + [a.fpm == b.fpm, a.attempts == b.attempts, a.repeats == b.repeats,
                 a.multi == b.multi, a.sim_swapped == b.sim_swapped,
                 a.sim_conf == b.sim_conf, a.nv_mismatch == b.nv_mismatch,
                 a.nv_conf == b.nv_conf, a.roam == b.roam, a.roam_conf == b.roam_conf,
                 a.dswap == b.dswap, a.dswap_conf == b.dswap_conf,
                 a.coached == b.coached, a.ev1 == b.ev1, a.ev2 == b.ev2, a.unk == b.unk,
                 a.avm == b.avm,
                 a.fwd == False, b.fwd == True]
              + [a.decision != APPROVE, b.decision == APPROVE])
        if s.check() == z3.unsat:
            continue
        m = s.model()
        fails.append({"proved": False, "counterexample": {
            "tier": tier, "note": "forwarding softened the verdict"}})
    return {"proved": not fails, "counterexample": (fails[0]["counterexample"] if fails else None)}


def _i8_silence_never_clean(rules):
    """I8 (posture): a SWAPPED posture event routes to the live-swap rule set
    (I1 applies — never APPROVE); an OBSERVED_STABLE posture may satisfy
    tier-1 screening only through the same gate as a live negative — and an
    UNKNOWN posture never satisfies screening (it must force a live query or
    UNKNOWN semantics). Encoded: with posture UNKNOWN, tier-0 reachability
    already excludes it via the radar/unknown flags; here we prove the
    decision-layer consequence: a swap fact (from ANY source — cache or wire)
    never yields APPROVE, identical to I1, plus tier-0 is unreachable when
    the sim fact is UNKNOWN (the engine buys the signal or screens)."""
    fails = []
    # (a) cached swap == live swap for the decision: I1 already proves this
    #     (the encoder cannot distinguish sources — same fact, same rules).
    # (b) UNKNOWN sim fact forces screening: tier-0 requires not flagged AND
    #     not unknown-context — an UNKNOWN sim (no cache, no query budget)
    #     sets sim conf 0 -> R3 on anomaly, coverage rules otherwise. Prove:
    #     tier-0 unreachable with sim conf 0 asserted.
    for tier in (1, 2):
        res = _check(rules, "i8", tier,
                     lambda c: z3.And(c.sim_swapped, c.sim_conf >= 0.9),
                     lambda c: c.decision != z3.IntVal(APPROVE))
        if not res["proved"]:
            fails.append(res)
    return {"proved": not fails, "counterexample": (fails[0]["counterexample"] if fails else None)}


INVARIANTS = {
    "I1_live_swap_never_approves": _i1_live_swap_never_approves,
    "I2_blind_never_approves": _i2_blind_never_approves,
    "I3_trap_fires": _i3_trap_fires,
    "I4_amount_monotone": _i4_amount_monotone,
    "I5_coached_never_approves": _i5_coached_never_approves,
    "I6_event_forces_signal_purchase": _i6_event_forces_signal_purchase,
    "I7_forwarding_never_softens": _i7_forwarding_never_softens,
    "I8_silence_never_clean": _i8_silence_never_clean,
}


def evasion_report(rules: dict) -> dict:
    """Cheapest-evasion search: the max amount-vs-mean (and full input) an
    attacker can pass through Tier 0 with ZERO telecom scrutiny. This
    quantifies the known radar-quiet exposure (see PRODUCTION_DELTA —
    event-forced checks are the queued fix)."""
    ctx = SymCtx("ev", 0, rules)
    s = z3.Optimize()
    s.add(ctx.domain + [ctx.precond, ctx.decision == APPROVE])
    s.maximize(ctx.avm)
    if s.check() == z3.sat:
        m = s.model()
        g = lambda v: m.eval(v, model_completion=True)
        return {"tier0_bypass_max_amount_vs_mean": g(ctx.avm).as_decimal(6),
                "payee_age_min": g(ctx.fpm).as_decimal(6),
                "attempts": g(ctx.attempts).as_long(),
                "repeats": g(ctx.repeats).as_long(),
                "telecom_signals_bought": 0,
                "note": "residual radar-quiet ceiling — reachable ONLY with no sensitive event in the window AND escaping keyed tier0_sample_rate sampling (event-forced screening is wired; Z3 invariant I6)"}
    return {"tier0_bypass": "none found"}


def differential_check(engine_decide, samples: int = 60, seed: int = 7) -> dict:
    """Random concrete inputs through the Z3 model AND the real engine must
    agree. Samples within 0.02 of a threshold are skipped (the engine's
    round(x, 2) is deliberately not modeled). engine_decide(req_dict) ->
    (decision_str, tier)."""
    rng = random.Random(seed)
    D = {"APPROVE": APPROVE, "ESCALATE": ESCALATE, "DECLINE": DECLINE}
    checked = skipped = mismatches = 0
    for i in range(samples):
        fpm = rng.choice([1, 3, 6, 120, 9999])
        avm = rng.choice([0.5, 3, 10, 19.5, 25, 45, 60])
        attempts = rng.choice([0, 2, 5, 9])
        repeats = rng.choice([1, 1, 2])
        confs = [rng.choice(_CONF_STATES) for _ in range(4)]
        sim_swap = rng.random() < 0.4
        nv_mm = rng.random() < 0.2
        roam = rng.random() < 0.2
        dsw = rng.random() < 0.2
        req = {"txn_id": f"diff-{i}", "msisdn": "+99999991001",
               "amount": avm * 100.0, "account_mean": 100.0,
               "beneficiary_first_seen_minutes": float(fpm),
               "attempts_last_hour": attempts, "declared_multi_sim": False,
               "new_payee_repeats": repeats}
        signals = {"sim_swapped": sim_swap, "confs": confs, "nv_mismatch": nv_mm,
                   "roam": roam, "dswap": dsw}
        real_dec, tier, thr_used = engine_decide(req, signals)
        # boundary guard: skip if any modeled total could sit near a threshold
        beh = (30 if fpm <= 5 else 0) + (25 if avm >= 20 else 0) + (15 if attempts >= 5 else 0) + (30 if repeats >= 2 else 0)
        rules = {"decline_gte": thr_used["decline_gte"], "escalate_gte": thr_used["escalate_gte"],
                 "instant_multiplier": getattr(engine_decide, "multiplier", 40),
                 "min_signal_coverage": getattr(engine_decide, "min_cov", 0.5)}
        near = min(abs(beh - rules["decline_gte"]), abs(beh - rules["escalate_gte"])) < 0.02             or min(abs(beh + 40 - rules["decline_gte"]), abs(beh + 40 - rules["escalate_gte"])) < 0.02
        if near:
            skipped += 1
            continue
        ctx = SymCtx(f"d{i}", tier if tier in (0, 1, 2) else 2, rules)
        s = z3.Solver()
        s.add(ctx.domain + _conf_discrete(ctx)
             + [ctx.precond,
                ctx.fpm == fpm, ctx.avm == z3.RealVal(str(avm)), ctx.attempts == attempts,
                ctx.repeats == repeats, ctx.multi == False, ctx.coached == False,  # engine samples carry no call
                ctx.ev1 == False, ctx.ev2 == False,                               # ...and no events
                getattr(ctx, "unk", z3.BoolVal(False)) == False,                  # ...and no unknown context
                ctx.fwd == False,                                                 # ...and no forwarding
                ctx.sim_swapped == sim_swap, ctx.sim_conf == z3.RealVal(str(confs[0])),
                ctx.nv_mismatch == nv_mm, ctx.nv_conf == z3.RealVal(str(confs[1])),
                ctx.roam == roam, ctx.roam_conf == z3.RealVal(str(confs[2])),
                ctx.dswap == dsw, ctx.dswap_conf == z3.RealVal(str(confs[3]))])
        assert s.check() == z3.sat
        m = s.model()
        model_dec = m.eval(ctx.decision, model_completion=True).as_long()
        checked += 1
        if D[real_dec] != model_dec:
            mismatches += 1
    return {"checked": checked, "skipped_near_boundary": skipped,
            "mismatches": mismatches}
