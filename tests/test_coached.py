"""Coached-payment family (rule R8) — the victim-on-the-call attack.
Band: COOLING_OFF_HOLD — nothing completes while the call is live; every
OTP/voice channel prohibited; hold metadata (release window, callback,
direction, duration). Proven by Z3 invariant I5: a live call NEVER
yields APPROVE, every tier, every other input."""
import pytest
from fastapi.testclient import TestClient

from app.engine.decide import DecisionEngine
from tests.test_tiers import CountingNac, _req, bank, DEFAULT_BANK_A


def _decide(**extra):
    txn = extra.pop("txn_id", "cp-1")
    req = _req(txn_id=txn)
    req.update(extra)
    nac = CountingNac(sim_swapped=extra.pop("sim_swapped", False))
    return DecisionEngine(nac).decide(req, bank(DEFAULT_BANK_A))


def test_live_call_goes_to_cooling_off_hold():
    out = _decide(call_in_progress=True, call_direction="inbound",
                  call_duration_minutes=12.5, txn_id="cp-live")
    assert out["decision"] == "ESCALATE"
    assert out["band"] == "COOLING_OFF_HOLD"
    assert out["step_up"]["allowed"] == []                    # NOTHING completes now
    assert set(out["step_up"]["prohibited"]) == {"SMS", "VOICE"}
    h = out["hold"]
    assert h["release_after_minutes"] == 30                   # policy default
    assert h["callback"] == "bank-held number"
    assert h["call_direction"] == "inbound" and h["call_duration_minutes"] == 12.5


def test_outbound_call_also_holds():
    out = _decide(call_in_progress=True, call_direction="outbound", txn_id="cp-out")
    assert out["band"] == "COOLING_OFF_HOLD"                  # direction recorded, both held


def test_coached_forces_full_sweep():
    out = _decide(call_in_progress=True, txn_id="cp-sweep",
                  beneficiary_first_seen_minutes=9999, amount=120.0)
    assert out["cost"]["tier"] == 2                           # severe -> signals bought
    assert out["cost"]["signals_bought"]                      # telecom evidence collected


def test_swap_still_outranks_coaching():
    out = _decide(call_in_progress=True, sim_swapped=True, amount=50000.0, txn_id="cp-swap")
    assert out["decision"] == "DECLINE"
    assert out["band"] == "SIM_SWAP_INSTANT_PATTERN"          # R0 first — worse signal wins


def test_quiet_no_call_unchanged():
    out = _decide(txn_id="cp-quiet", beneficiary_first_seen_minutes=9999, amount=120.0)
    assert out["decision"] == "APPROVE" and out["band"] == "CLEAN"
    assert "hold" not in out


def test_policy_cooldown_knob():
    rules = {"decline_gte": 75, "escalate_gte": 50, "call_cooldown_minutes": 60}
    req = _req(txn_id="cp-knob"); req["call_in_progress"] = True
    out = DecisionEngine(CountingNac()).decide(req, bank({**DEFAULT_BANK_A, "rules": rules}))
    assert out["hold"]["release_after_minutes"] == 60


def test_governor_hardens_over_approving_incumbent():
    req = _req(txn_id="cp-gov"); req.update({"mode": "sidecar", "incumbent_decision": "APPROVE",
                                             "call_in_progress": True})
    out = DecisionEngine(CountingNac()).decide(req, bank(DEFAULT_BANK_A))
    assert out["decision"] == "ESCALATE" and out["band"] == "COOLING_OFF_HOLD"


def test_no_channel_dispatchable_during_call():
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/v1/decide", json={"txn_id": "cp-api", "msisdn": "+99999991001",
                                       "amount": 120.0, "account_mean": 100.0,
                                       "call_in_progress": True,
                                       "call_direction": "inbound",
                                       "call_duration_minutes": 7.0}).json()
        assert r["band"] == "COOLING_OFF_HOLD"
        for ch in ("SMS", "VOICE", "WEBAUTHN"):
            d = c.post("/v1/stepup/dispatch", json={"token": r["step_up_grant"]["token"],
                                                    "channel": ch}).json()
            assert d["dispatched"] is False, ch          # the grant allows nothing
