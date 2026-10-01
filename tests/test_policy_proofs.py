"""Z3 policy proofs — the signing gate + model faithfulness.

Gate: every signed bundle on disk must PROVE all four safety invariants
for every possible input. A policy that violates an invariant cannot
pass CI — this is the certificate a bank risk team can read.

Faithfulness: random concrete inputs through the Z3 model AND the real
engine must agree (boundary-margin-guarded) — the proof is about the
code, not a wish.

Evasion: the Tier-0 radar-quiet ceiling is QUANTIFIED (max amount-vs-
mean with zero telecom scrutiny) — the number the event-forced-check
fix will shrink."""
import math
import pytest
z3 = pytest.importorskip("z3")

from app.policy_proofs import (prove_all, evasion_report, differential_check,
                               APPROVE, ESCALATE, DECLINE)
from app.policy import verify_bundle, DEFAULT_BANK_A, DEFAULT_BANK_B
from app.engine.decide import DecisionEngine
from app.signals.nac import Signal

class PrgNac:
    """Programmable stub: returns exactly the configured signal states."""
    def __init__(self, swapped=False, confs=(1.0, 1.0, 1.0, 1.0),
                 nv_mismatch=False, roam=False, dswap=False):
        self.swapped, self.confs = swapped, confs
        self.nv_mismatch, self.roam, self.dswap = nv_mismatch, roam, dswap

    def _sig(self, name, value, risk, conf):
        # conf 0.0 = LOST: the real client returns value None (no answer), risk 0
        if conf == 0.0:
            return Signal(name, None, 0.0, 0.0, degradation="UNAVAILABLE(x)")
        deg = None if conf == 1.0 else "DEGRADED(x)"
        return Signal(name, value, conf, risk, degradation=deg)

    def sim_swap(self, msisdn, hours, deadline_remaining):
        return self._sig("SIM_SWAP", {"swapped": self.swapped},
                         40.0 if self.swapped else 0.0, self.confs[0])

    def number_verify(self, msisdn, dual, deadline_remaining):
        return self._sig("NUMBER_VERIFY",
                         "MISMATCH" if self.nv_mismatch else "MATCH",
                         25.0 if self.nv_mismatch else 0.0, self.confs[1])

    def roaming(self, msisdn, deadline_remaining):
        return self._sig("DEVICE_STATUS", {"roaming": self.roam},
                         8.0 if self.roam else 0.0, self.confs[2])

    def device_swap(self, msisdn, deadline_remaining):
        return self._sig("DEVICE_SWAP", {"swapped": self.dswap},
                         20.0 if self.dswap else 0.0, self.confs[3])


def _signed(doc):
    import copy
    from tests.test_core import signed as _s
    return _s(copy.deepcopy(doc))


A_RULES = verify_bundle(_signed(DEFAULT_BANK_A))["rules"]
B_RULES = verify_bundle(_signed(DEFAULT_BANK_B))["rules"]


# ---------------- THE GATE ----------------------------------------------------
@pytest.mark.parametrize("name,rules", [("bank-a-v1", A_RULES), ("bank-b-v1", B_RULES)])
def test_signed_policies_prove_all_invariants(name, rules):
    res = prove_all(rules)
    violated = {k: v for k, v in res.items() if not v["proved"]}
    assert not violated, f"{name} violates invariants: {violated}"


def test_invariant_timing_is_ci_friendly():
    res = prove_all(A_RULES)
    worst = max(v["ms"] for v in res.values())
    assert worst < 20000, f"slowest proof {worst} ms — too slow for CI"


# ---------------- MODEL FAITHFULNESS -----------------------------------------
def _engine_decide(req, signals):
    nac = PrgNac(swapped=signals["sim_swapped"], confs=tuple(signals["confs"]),
                 nv_mismatch=signals["nv_mismatch"], roam=signals["roam"],
                 dswap=signals["dswap"])
    out = DecisionEngine(nac).decide(req, _signed(DEFAULT_BANK_A))
    tier = out["cost"]["tier"]
    assert tier in (0, 1, 2)
    _engine_decide.multiplier = 40
    _engine_decide.min_cov = 0.5
    return out["decision"], tier, out["thresholds_used"]


def test_differential_model_matches_engine():
    res = differential_check(_engine_decide, samples=80, seed=11)
    assert res["mismatches"] == 0, res
    assert res["checked"] >= 40


# ---------------- EVASION QUANTIFICATION --------------------------------------
def test_tier0_evasion_is_quantified():
    rep = evasion_report(A_RULES)
    mx = float(rep["tier0_bypass_max_amount_vs_mean"].rstrip("?"))
    # known exposure: radar-quiet ceiling sits just under the 20x severe flag
    # (z3 Optimize returns a witness <= the supremum 20)
    assert 19.0 <= mx < 20.0, rep
    assert rep["telecom_signals_bought"] == 0
    assert float(rep["payee_age_min"].rstrip("?")) > 5.0


def test_prover_is_not_rubber_stamp():
    """Teeth check: feed the prover a FALSE claim (live swap always hard-DECLINEs)
    — it must return proved=False with a concrete counterexample, proving the
    machinery cannot rubber-stamp. (The four real invariants became structural
    after R7 — thresholds can no longer break them, which is the design goal.)"""
    import z3 as _z3
    from app.policy_proofs import SymCtx, _conf_discrete
    rules = dict(A_RULES)
    ctx = SymCtx("teeth", 2, rules)
    sol = _z3.Solver()
    sol.add(ctx.domain + _conf_discrete(ctx) + [ctx.precond,
           ctx.sim_swapped, ctx.sim_conf == 1, ctx.avm == 1])   # tiny amount, live swap
    claim = ctx.decision == DECLINE                             # FALSE: R0 escalates, not declines
    sol.add(_z3.Not(claim))
    assert sol.check() == _z3.unsat or sol.check() == _z3.sat
    # direct: the negation is satisfiable => the claim is NOT proved
    sol2 = _z3.Solver()
    sol2.add(ctx.domain + _conf_discrete(ctx) + [ctx.precond,
            ctx.sim_swapped, ctx.sim_conf == 1, ctx.avm == 1])
    sol2.add(_z3.Not(claim))
    assert sol2.check() == _z3.sat
    m = sol2.model()
    assert m.eval(ctx.decision, model_completion=True).as_long() == ESCALATE
