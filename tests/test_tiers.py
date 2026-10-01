"""Tiered signal purchasing, threshold jitter, aged-swap window, payee-velocity
trap — regression tests for the three stc-review fixes. Offline stubs only."""
import copy
import pytest
from app.engine.decide import DecisionEngine
from app.engine.weighting import (Behavioral, evaluate, jitter_thresholds,
                                  behavioral_risk)
from app.signals.nac import Signal
from tests.test_core import signed, DEFAULT_BANK_A, DEFAULT_BANK_B


# Snapshot at import, before any test runs: test_core's tamper test mutates
# these shared dicts in place mid-run; shadowing the names keeps this module's
# copies pristine regardless of execution order.
DEFAULT_BANK_A = copy.deepcopy(DEFAULT_BANK_A)
DEFAULT_BANK_B = copy.deepcopy(DEFAULT_BANK_B)


def bank(doc):
    return signed(doc)


class CountingNac:
    """Stub recording which signals were actually purchased."""
    def __init__(self, sim_swapped=False, aged_swapped=False, dswap=False):
        self.calls = []
        self.sim_swapped = sim_swapped
        self.aged_swapped = aged_swapped
        self.dswap = dswap

    def sim_swap(self, msisdn, hours, deadline_remaining):
        recent = hours <= 48
        self.calls.append(("SIM_SWAP", hours))
        swapped = self.sim_swapped if recent else self.aged_swapped
        return Signal("SIM_SWAP", {"swapped": swapped}, 1.0, 40.0 if swapped else 0.0)

    def number_verify(self, msisdn, dual, deadline_remaining):
        return Signal("NUMBER_VERIFY", "MATCH", 0.30, 0.0)

    def roaming(self, msisdn, deadline_remaining):
        return Signal("DEVICE_STATUS", {"roaming": False}, 1.0, 0.0)

    def device_swap(self, msisdn, deadline_remaining):
        return Signal("DEVICE_SWAP", {"swapped": self.dswap}, 1.0, 20.0 if self.dswap else 0.0)


def _req(**kw):
    base = {"txn_id": "t-quiet", "msisdn": "+99999991001", "amount": 120.0,
            "account_mean": 100.0, "beneficiary_first_seen_minutes": 9999,
            "attempts_last_hour": 0, "declared_multi_sim": False}
    base.update(kw)
    return base


# ---------------- Tier 0: quiet traffic buys nothing -------------------------
def test_tier0_quiet_traffic_buys_zero_signals():
    nac = CountingNac()
    out = DecisionEngine(nac).decide(_req(), bank(DEFAULT_BANK_A))
    assert out["decision"] == "APPROVE" and out["band"] == "CLEAN"
    assert out["cost"]["tier"] == 0 and out["cost"]["signals_bought"] == []
    assert out["cost"]["cost_estimate_usd"] == 0
    assert out["cost"]["decision_basis"] == "BEHAVIORAL_ONLY"
    assert nac.calls == []                      # no API money spent at all

def test_tier0_disabled_by_policy_falls_back_to_full_sweep():
    pol = dict(DEFAULT_BANK_A)
    pol["rules"] = dict(pol["rules"], progressive_tiers=False)
    nac = CountingNac()
    out = DecisionEngine(nac).decide(_req(), bank(pol))
    assert "SIM_SWAP" in out["cost"]["signals_bought"]     # legacy behavior restored

# ---------------- Tier 1: mild flag buys SIM swap only -----------------------
def test_tier1_fresh_payee_buys_only_sim_swap():
    nac = CountingNac()
    out = DecisionEngine(nac).decide(
        _req(beneficiary_first_seen_minutes=3, txn_id="t-t1"), bank(DEFAULT_BANK_A))
    assert out["cost"]["tier"] == 1
    assert out["cost"]["signals_bought"] == ["SIM_SWAP"]
    assert out["cost"]["cost_estimate_usd"] == 0.07
    assert [c[0] for c in nac.calls] == ["SIM_SWAP"]
    assert out["decision"] == "APPROVE"         # fresh payee alone: tier-1 evidence recorded, no escalation (30 < ~55)

# ---------------- Tier 2: severe flags buy the full sweep --------------------
def test_tier2_amount_spike_buys_full_sweep_plus_aged():
    nac = CountingNac()
    out = DecisionEngine(nac).decide(
        _req(amount=3000.0, txn_id="t-t2"), bank(DEFAULT_BANK_A))   # 30x mean
    assert out["cost"]["tier"] == 2
    assert out["cost"]["signals_bought"] == ["SIM_SWAP", "DEVICE_STATUS",
                                             "DEVICE_SWAP", "SIM_SWAP_AGED"]
    assert out["cost"]["cost_estimate_usd"] == 0.28
    assert out["band"] == "BEHAVIORAL_ANOMALY"  # telecom green + spike -> rule 5

def test_tier2_no_aged_query_when_recent_swap_live():
    nac = CountingNac(sim_swapped=True)
    out = DecisionEngine(nac).decide(
        _req(amount=50000.0, txn_id="t-live"), bank(DEFAULT_BANK_A))
    assert out["decision"] == "DECLINE" and out["band"] == "SIM_SWAP_INSTANT_PATTERN"
    assert "SIM_SWAP_AGED" not in out["cost"]["signals_bought"]

# ---------------- Aged-swap corroboration (rule 6) ---------------------------
def test_aged_swap_plus_anomaly_escalates_sms_allowed():
    nac = CountingNac(aged_swapped=True)
    out = DecisionEngine(nac).decide(
        _req(amount=3000.0, txn_id="t-aged"), bank(DEFAULT_BANK_A))
    assert out["decision"] == "ESCALATE"
    assert out["band"] == "SIM_SWAP_AGED_CORROBORATION"
    assert "SMS" in out["step_up"]["allowed"]           # unlike rule 0
    assert out["step_up"]["prohibited"] == []

def test_aged_swap_alone_never_escalates_or_declines():
    aged = Signal("SIM_SWAP_AGED", {"swapped": True}, 1.0, 20.0)
    sigs = [Signal("SIM_SWAP", {"swapped": False}, 1.0, 0.0),
            Signal("NUMBER_VERIFY", "MATCH", 1.0, 0.0),
            Signal("DEVICE_STATUS", {"roaming": False}, 1.0, 0.0),
            Signal("DEVICE_SWAP", {"swapped": False}, 1.0, 0.0)]
    b = Behavioral(9999, 1, 1.0, False)                 # quiet behavior
    out = evaluate(sigs, b, DEFAULT_BANK_A["rules"], aged=aged)
    assert out["decision"] == "APPROVE" and out["total_risk"] == 20.0  # +20 only

# ---------------- Payee-velocity trap -----------------------------------------
def test_payee_velocity_trap_springs_on_second_new_payee_txn():
    nac = CountingNac()
    out = DecisionEngine(nac).decide(
        _req(beneficiary_first_seen_minutes=3, new_payee_repeats=2,
             txn_id="t-trap"), bank(DEFAULT_BANK_A))
    assert out["decision"] == "ESCALATE"
    assert out["band"] == "PAYEE_VELOCITY_TRAP"  # hard rule R7 (was threshold band pre-proof-gate)
    assert out["total_risk"] == 60.0
    assert out["cost"]["tier"] == 2             # repeats force full sweep
    assert "SMS" in out["step_up"]["prohibited"]

def test_payee_velocity_quiet_old_payee_repeats_do_not_escalate():
    aged = None
    sigs = [Signal("SIM_SWAP", {"swapped": False}, 1.0, 0.0)]
    b = Behavioral(9999, 1, 1.0, False, new_payee_repeats=2)
    assert behavioral_risk(b) == 30.0           # counted, but no anomaly rule fires

# ---------------- Threshold jitter --------------------------------------------
def test_jitter_deterministic_same_txn_id():
    rules = {**DEFAULT_BANK_A["rules"], "threshold_jitter_pct": 3.0}
    p1, u1 = jitter_thresholds(rules, "txn-X")
    p2, u2 = jitter_thresholds(rules, "txn-X")
    assert u1 == u2 and p1 == p2                 # exact replay preserved

def test_jitter_within_bounds_and_recorded():
    rules = {**DEFAULT_BANK_A["rules"], "threshold_jitter_pct": 3.0}   # opt-in
    base_d, base_e = rules["decline_gte"], rules["escalate_gte"]
    for i in range(50):
        _, used = jitter_thresholds(rules, f"txn-{i}")
        assert abs(used["decline_gte"] - base_d) <= base_d * 0.031
        assert abs(used["escalate_gte"] - base_e) <= base_e * 0.031
        assert used["jitter_pct"] == 3.0

def test_decision_records_thresholds_used():
    out = DecisionEngine(CountingNac()).decide(
        _req(beneficiary_first_seen_minutes=3, txn_id="t-rec"), bank(DEFAULT_BANK_A))
    assert out["thresholds_used"]["jitter_pct"] == 0.0   # default off; exact values recorded
    assert "decline_gte" in out["thresholds_used"]

def test_jitter_default_off():
    # panel verdict: OFF unless a bank explicitly opts in
    _, used = jitter_thresholds(DEFAULT_BANK_A["rules"], "txn-X")
    assert used["jitter_pct"] == 0.0
    assert used["decline_gte"] == DEFAULT_BANK_A["rules"]["decline_gte"]
    assert used["escalate_gte"] == DEFAULT_BANK_A["rules"]["escalate_gte"]

# ---------------- Existing behavior preserved ---------------------------------
def test_bank_pair_differential_still_works():
    class StubNac(CountingNac):
        pass
    nac = StubNac(sim_swapped=True)
    req = _req(amount=50000.0, account_mean=1000.0, txn_id="t-bank2")  # 50x mean
    a = DecisionEngine(nac).decide(dict(req), bank(DEFAULT_BANK_A))
    bb = DecisionEngine(CountingNac(sim_swapped=True)).decide(dict(req), bank(DEFAULT_BANK_B))
    assert a["decision"] == "DECLINE" and a["band"] == "SIM_SWAP_INSTANT_PATTERN"
    assert bb["band"] != "SIM_SWAP_INSTANT_PATTERN"
