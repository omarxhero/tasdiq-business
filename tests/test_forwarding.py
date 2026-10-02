"""Call Forwarding Signal (R9) — panel-corrected semantics:
UNCONDITIONAL forwarding strips VOICE + CALLBACK (voice-call redirect is the
mechanism); SMS is NEVER touched by CFS alone; conditional/unknown states
change nothing; corroboration-only — the decision itself never changes
(proved by I7); R8's cooling-off callback gate refuses a forwarded line."""
import copy
import pytest
from fastapi.testclient import TestClient

from app.engine.decide import DecisionEngine
from app.engine.weighting import Behavioral, _evaluate_inner
from tests.test_tiers import CountingNac, _req, bank, DEFAULT_BANK_A


def _decide(**kw):
    txn = kw.pop("txn_id", "cf-1")
    req = _req(txn_id=txn)
    req.update(kw)
    return DecisionEngine(CountingNac(sim_swapped=kw.pop("sim_swapped", False))).decide(
        req, bank(DEFAULT_BANK_A))


# ---- the regression the panel demanded: voice-only, SMS untouched -----------

def test_unconditional_strips_voice_and_callback_not_sms():
    # R0 swap band: SMS banned BY THE SWAP; forwarding adds VOICE+CALLBACK on top
    out = _decide(sim_swapped=True, call_forwarding_state="unconditional",
                  beneficiary_first_seen_minutes=3, txn_id="cf-u")
    assert out["decision"] == "ESCALATE" and out["band"] == "SIM_SWAP_RECENT"
    assert "VOICE" in out["step_up"]["prohibited"] and "CALLBACK" in out["step_up"]["prohibited"]
    assert "WEBAUTHN" in out["step_up"]["allowed"]                  # safe channels survive
    assert "voice OTP" in out["forwarding_note"]
    # THE CFS-alone claim: aged-swap band (R6) ALLOWS SMS — forwarding must not touch it
    from app.signals.nac import Signal
    from app.engine.weighting import evaluate, Behavioral
    sigs = [Signal("SIM_SWAP", {"swapped": False}, 1.0, 0.0),
            Signal("NUMBER_VERIFY", "MATCH", 1.0, 0.0)]
    aged = Signal("SIM_SWAP_AGED", {"swapped": True}, 1.0, 20.0)
    b = Behavioral(2, 1, 30.0, False, call_forwarding_state="unconditional")
    pol = {"decline_gte": 75, "escalate_gte": 50}
    out2 = evaluate(sigs, b, pol, aged=aged)
    assert out2["band"] == "SIM_SWAP_AGED_CORROBORATION"
    assert "SMS" in out2["step_up"]["allowed"]                      # SMS STILL allowed
    assert "VOICE" in out2["step_up"]["prohibited"]                 # voice stripped by CFS
    assert "CALLBACK" in out2["step_up"]["prohibited"]


def test_conditional_states_change_nothing():
    for state in ("conditional_busy", "conditional_unreachable", "conditional_no_answer"):
        out = _decide(call_forwarding_state=state,
                      beneficiary_first_seen_minutes=9999, txn_id=f"cf-{state[:6]}")
        assert out["decision"] == "APPROVE" and out["band"] == "CLEAN"
        assert "forwarding_note" not in out
        assert "VOICE" not in out["step_up"]["prohibited"]


def test_unknown_and_unavailable_are_not_clean_inference():
    for state in ("unknown", "unavailable"):
        out = _decide(call_forwarding_state=state,
                      beneficiary_first_seen_minutes=9999, txn_id=f"cf-{state[:4]}")
        assert out["decision"] == "APPROVE"                          # no clean inference either way
        assert "forwarding_note" not in out


def test_forwarding_never_changes_decision_alone():
    quiet = _decide(beneficiary_first_seen_minutes=9999, txn_id="cf-a")
    fwd = _decide(call_forwarding_state="unconditional",
                  beneficiary_first_seen_minutes=9999, txn_id="cf-b")
    assert quiet["decision"] == fwd["decision"] == "APPROVE"         # I7 in the flesh
    assert fwd["band"] == quiet["band"]


def test_r8_callback_gate_refuses_forwarded_line():
    out = _decide(call_in_progress=True, call_direction="inbound",
                  call_forwarding_state="unconditional", txn_id="cf-r8")
    assert out["band"] == "COOLING_OFF_HOLD"
    assert out["hold"]["callback_allowed"] is False
    assert out["hold"]["callback_block_reason"] == "unconditional_call_forwarding"
    # and without forwarding: callback allowed
    out2 = _decide(call_in_progress=True, call_direction="inbound",
                   call_forwarding_state="inactive", txn_id="cf-r8b")
    assert out2["hold"]["callback_allowed"] is True


def test_swap_band_plus_forwarding_strips_voice_too():
    out = _decide(sim_swapped=True, amount=3000.0, beneficiary_first_seen_minutes=3,
                  call_forwarding_state="unconditional", txn_id="cf-swap")
    assert out["decision"] in ("DECLINE", "ESCALATE")
    assert "VOICE" in out["step_up"]["prohibited"] and "SMS" in out["step_up"]["prohibited"]
    # SMS banned by the SWAP (R0) — not by forwarding; voice banned by BOTH


def test_api_field_enum_validated():
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/v1/decide", json={"txn_id": "cf-api", "msisdn": "+99999991001",
                                       "amount": 120.0, "account_mean": 100.0,
                                       "beneficiary_first_seen_minutes": 9999,
                                       "attempts_last_hour": 0,
                                       "call_forwarding_state": "unconditional"}).json()
        assert r["forwarding_note"]
        bad = c.post("/v1/decide", json={"txn_id": "cf-bad", "msisdn": "+9",
                                         "amount": 10.0,
                                         "call_forwarding_state": "maybe"})
        assert bad.status_code == 422


def test_i7_proved_for_both_banks():
    from app.policy_proofs import prove_all
    from app.policy import DEFAULT_BANK_A, DEFAULT_BANK_B
    from tests.test_core import signed
    import copy as _c
    for doc in (DEFAULT_BANK_A, DEFAULT_BANK_B):
        res = prove_all(signed(_c.deepcopy(doc))["rules"])
        assert res["I7_forwarding_never_softens"]["proved"], doc.get("policy_id")


def test_grant_reflects_stripped_voice():
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/v1/decide", json={"txn_id": "cf-g", "msisdn": "+99999991000",
                                       "amount": 3000.0, "account_mean": 100.0,
                                       "beneficiary_first_seen_minutes": 3,
                                       "attempts_last_hour": 0,
                                       "call_forwarding_state": "unconditional"}).json()
        d = c.post("/v1/stepup/dispatch", json={"token": r["step_up_grant"]["token"],
                                                "channel": "VOICE"}).json()
        assert d["dispatched"] is False                     # the grant carries the strip
        d2 = c.post("/v1/stepup/dispatch", json={"token": r["step_up_grant"]["token"],
                                                 "channel": "WEBAUTHN"}).json()
        assert d2["dispatched"] is True
