"""Tier-0 event-forced fix — the patient-attacker bypass, closed.
Sensitive events (payee add / credential reset / device registration /
login anomaly) force SIM screening regardless of radar; takeover-shaped
events force the full sweep; keyed 2% random sampling covers the rest.
Proven by Z3 invariant I6: an event can never ride Tier 0."""
import pytest
from fastapi.testclient import TestClient

from app.engine.decide import DecisionEngine, _sampled
from tests.test_tiers import CountingNac, _req, bank, DEFAULT_BANK_A


def _decide(**extra):
    txn = extra.pop("txn_id", "ev-1")
    sim = extra.pop("sim_swapped", False)
    req = _req(txn_id=txn, **{k: v for k, v in extra.items()
                              if k in ("beneficiary_first_seen_minutes", "amount",
                                       "attempts_last_hour", "new_payee_repeats")})
    req.update({k: v for k, v in extra.items() if k not in req})
    return DecisionEngine(CountingNac(sim_swapped=sim)).decide(req, bank(DEFAULT_BANK_A))


def test_payee_added_event_forces_sim_screening():
    out = _decide(recent_sensitive_event="payee_added",
                  sensitive_event_minutes_ago=30,
                  beneficiary_first_seen_minutes=120,   # radar-quiet otherwise
                  txn_id="ev-pa")
    assert out["cost"]["tier"] == 1
    assert out["cost"]["signals_bought"] == ["SIM_SWAP"]
    assert out["cost"]["trigger"] == "event:payee_added"
    # screening is not punishment: green telecom -> still approved, now WITH evidence
    assert out["decision"] == "APPROVE" and out["band"] == "CLEAN"


def test_credential_reset_forces_full_sweep():
    out = _decide(recent_sensitive_event="credential_reset",
                  sensitive_event_minutes_ago=10, txn_id="ev-cr")
    assert out["cost"]["tier"] == 2
    assert out["cost"]["trigger"] == "event:credential_reset"
    assert set(out["cost"]["signals_bought"]) >= {"SIM_SWAP", "DEVICE_STATUS", "DEVICE_SWAP"}


def test_bypass_closed_event_plus_swap_catches_attacker():
    # the exact panel scenario: patient attacker resets credentials, waits,
    # pays quietly — the event forces the SIM check and the swap is caught
    out = _decide(recent_sensitive_event="credential_reset", sim_swapped=True,
                  beneficiary_first_seen_minutes=120, amount=500.0, txn_id="ev-att")
    assert out["decision"] == "ESCALATE"          # R0 swap band (amount below mult)
    assert "SMS" in out["step_up"]["prohibited"]


def test_stale_event_outside_window_ignored():
    out = _decide(recent_sensitive_event="credential_reset",
                  sensitive_event_minutes_ago=600,   # > 60-min default window
                  beneficiary_first_seen_minutes=120, txn_id="ev-old")
    assert out["cost"]["tier"] == 0 and out["cost"]["trigger"] == "none"


def test_quiet_traffic_unchanged():
    out = _decide(beneficiary_first_seen_minutes=9999, txn_id="ev-quiet")
    assert out["cost"]["tier"] == 0 and out["cost"]["signals_bought"] == []


def test_sampling_deterministic_and_keyed():
    assert _sampled("txn-X", 0.02) == _sampled("txn-X", 0.02)
    # with rate 1.0 everything samples; with 0.0 nothing does
    assert _sampled("anything", 1.0) is True
    assert _sampled("anything", 0.0) is False
    # rate 0.5 splits a population (both classes exist)
    hits = sum(_sampled(f"s-{i}", 0.5) for i in range(200))
    assert 60 < hits < 140


def test_sampled_quiet_txn_buys_sim():
    # find a txn_id that samples at 100%? use rate via policy: simpler — force
    # by picking an id sampled at default 2% is flaky; override rate in policy
    pol = {**DEFAULT_BANK_A, "rules": {**DEFAULT_BANK_A["rules"], "tier0_sample_rate": 1.0}}
    req = _req(txn_id="ev-sample", beneficiary_first_seen_minutes=9999)
    out = DecisionEngine(CountingNac()).decide(req, bank(pol))
    assert out["cost"]["tier"] == 1
    assert out["cost"]["trigger"] == "sample"
    assert out["cost"]["signals_bought"] == ["SIM_SWAP"]


def test_radar_trigger_provenance_unchanged():
    out = _decide(beneficiary_first_seen_minutes=3, txn_id="ev-radar")  # tier1 via radar
    assert out["cost"]["trigger"] == "radar"
    out2 = _decide(amount=3000.0, txn_id="ev-sev")                      # tier2 via severe
    assert out2["cost"]["trigger"] == "severe"


def test_replay_bypass_count_drops_with_events():
    from app.replaylab import replay
    from app.policy import DEFAULT_BANK_A
    from tests.test_core import signed
    import copy
    base = {"msisdn": "+9", "amount": 1500.0, "account_mean": 100.0,
            "beneficiary_first_seen_minutes": 120, "attempts_last_hour": 0,
            "confirmed_fraud": True}
    before = replay([dict(base, txn_id="rb-1")], copy.deepcopy(signed(DEFAULT_BANK_A)))
    after = replay([dict(base, txn_id="rb-2",
                         recent_sensitive_event="credential_reset",
                         sensitive_event_minutes_ago=5)],
                   copy.deepcopy(signed(DEFAULT_BANK_A)))
    assert before["bypass"]["count"] == 1
    assert after["bypass"]["count"] == 0          # event screening catches it


def test_endpoint_accepts_event_fields():
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/v1/decide", json={"txn_id": "ev-api", "msisdn": "+99999991001",
                                       "amount": 120.0, "account_mean": 100.0,
                                       "recent_sensitive_event": "device_registration"
                                       }).json()
        assert r["cost"]["tier"] == 2 and r["cost"]["trigger"] == "event:device_registration"
        bad = c.post("/v1/decide", json={"txn_id": "ev-bad", "msisdn": "+9",
                                         "amount": 10.0,
                                         "recent_sensitive_event": "burglary"})
        assert bad.status_code == 422
