"""Governor / sidecar mode — the never-downgrade guarantee + hardening +
counterfactual. Rail mode must stay byte-identical (default path)."""
import pytest
from fastapi.testclient import TestClient

from app.engine.decide import DecisionEngine
from app.governor import incumbent_strength
from tests.test_tiers import CountingNac, _req, bank, DEFAULT_BANK_A

_ST = {"APPROVE": 0, "ESCALATE": 1, "DECLINE": 2}


def _decide(mode="rail", **extra):
    req = _req(txn_id=extra.pop("txn_id", "gov-1"), **{k: v for k, v in extra.items()
                                                       if k in ("beneficiary_first_seen_minutes",
                                                                "amount", "new_payee_repeats",
                                                                "attempts_last_hour")})
    req.update({k: v for k, v in extra.items() if k not in req})
    req["mode"] = mode                       # named param -> engine field
    nac = CountingNac(sim_swapped=extra.pop("sim_swapped", False))
    return DecisionEngine(nac).decide(req, bank(DEFAULT_BANK_A))


# G1 — never downgrade the incumbent
def test_g1_incumbent_escalate_held_over_tasdiq_approve():
    out = _decide(mode="sidecar", incumbent_decision="ESCALATE",
                  beneficiary_first_seen_minutes=9999, amount=120.0, txn_id="g1")
    assert out["decision"] == "ESCALATE" and out["band"] == "GOVERNOR_HELD_ESCALATE"
    assert out["governor"]["final"] == "ESCALATE"
    assert out["governor"]["added_by_tasdiq"] is False


def test_g1_incumbent_decline_held_over_tasdiq_approve():
    out = _decide(mode="sidecar", incumbent_decision="DECLINE", txn_id="g1b")
    assert out["decision"] == "DECLINE" and out["band"] == "GOVERNOR_HELD_DECLINE"


def test_g1_score_maps_through_bank_thresholds():
    pol = {"decline_gte": 75, "escalate_gte": 50}
    assert incumbent_strength({"incumbent_score": 80}, pol) == "DECLINE"
    assert incumbent_strength({"incumbent_score": 60}, pol) == "ESCALATE"
    assert incumbent_strength({"incumbent_score": 10}, pol) == "APPROVE"
    assert incumbent_strength({"incumbent_decision": "escalate"}, pol) == "ESCALATE"
    assert incumbent_strength({}, pol) == "APPROVE"


# G1 — monotone: raising the incumbent score never weakens the final
def test_g1_monotone_in_incumbent_score():
    prev = -1
    for score in range(0, 101, 5):
        out = _decide(mode="sidecar", incumbent_score=float(score),
                      beneficiary_first_seen_minutes=9999, amount=120.0,
                      txn_id=f"mon-{score}")
        s = _ST[out["decision"]]
        assert s >= prev, f"final weakened at incumbent_score={score}"
        prev = s


# G2 — Tasdiq still hardens on top of a relaxed incumbent
def test_g2_live_swap_overrides_relaxed_incumbent():
    out = _decide(mode="sidecar", incumbent_decision="APPROVE", sim_swapped=True,
                  amount=50000.0, txn_id="g2")   # 500x -> early-exit decline
    assert out["decision"] == "DECLINE"
    assert out["band"] == "SIM_SWAP_INSTANT_PATTERN"       # rail verdict stands
    assert out["governor"]["added_by_tasdiq"] is True
    assert "SMS" in out["step_up"]["prohibited"]            # channel policy survives


def test_g2_trap_fires_over_approving_incumbent():
    out = _decide(mode="sidecar", incumbent_decision="APPROVE",
                  beneficiary_first_seen_minutes=4, new_payee_repeats=2,
                  txn_id="g2b")
    assert out["decision"] == "ESCALATE" and out["band"] == "PAYEE_VELOCITY_TRAP"


# swap-band SMS prohibition survives an incumbent-driven severity composition
def test_prohibitions_survive_governor_hold():
    out = _decide(mode="sidecar", incumbent_decision="DECLINE", sim_swapped=True,
                  amount=3000.0, txn_id="g3")   # swap band, below early-exit mult
    assert out["decision"] == "DECLINE"
    assert out["band"] == "GOVERNOR_HELD_DECLINE"          # incumbent stronger -> held
    assert out["governor"]["tasdiq_rail"] == "ESCALATE"    # rail verdict preserved inside
    assert "SMS" in out["step_up"]["prohibited"]           # swap-band SMS ban survives


# counterfactual on tier-0 quiet traffic
def test_counterfactual_on_quiet_traffic():
    out = _decide(mode="sidecar", txn_id="cf-1",
                  beneficiary_first_seen_minutes=9999, amount=120.0)
    assert out["cost"]["tier"] == 0
    cf = out["governor"]["counterfactual"]
    assert cf["hypothetical"] == "live_sim_swap"
    assert cf["verdict"] in ("ESCALATE", "DECLINE")
    assert cf["band"].startswith("SIM_SWAP")
    assert out["cost"]["signals_bought"] == []   # hypothetical cost $0, nothing bought


def test_no_counterfactual_when_signals_already_bought():
    out = _decide(mode="sidecar", txn_id="cf-2",
                  beneficiary_first_seen_minutes=3)   # tier 1
    assert out["cost"]["tier"] == 1
    assert out["governor"]["counterfactual"] is None


# rail mode untouched — no governor block at all
def test_rail_mode_has_no_governor_block():
    out = _decide(txn_id="rail-1")
    assert "governor" not in out
    assert out["band"] == "CLEAN"


# through the real API
def test_sidecar_through_api():
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/v1/decide", json={"txn_id": "api-gov", "msisdn": "+99999991001",
                                       "amount": 120.0, "account_mean": 100.0,
                                       "beneficiary_first_seen_minutes": 9999,
                                       "attempts_last_hour": 0,
                                       "mode": "sidecar",
                                       "incumbent_score": 88.0,
                                       "incumbent_vendor": "feedzai"}).json()
        assert r["governor"]["final"] == "DECLINE"          # 88 >= decline 75
        assert r["governor"]["incumbent"]["vendor"] == "feedzai"
        assert r["governor"]["counterfactual"]["verdict"] in ("ESCALATE", "DECLINE")
        # rail default through API stays clean
        r2 = c.post("/v1/decide", json={"txn_id": "api-rail", "msisdn": "+99999991001",
                                        "amount": 120.0, "account_mean": 100.0}).json()
        assert "governor" not in r2 and r2["decision"] == "APPROVE"


def test_bad_mode_rejected():
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/v1/decide", json={"txn_id": "api-bad", "msisdn": "+9",
                                       "amount": 10.0, "mode": "sideways"})
        assert r.status_code == 422


# regression: channel naming was split (SMS vs SMS_OTP) — governor-held
# escalate must be SMS-dispatchable through the signed grant
def test_governor_hold_grant_allows_sms_dispatch():
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/v1/decide", json={"txn_id": "gov-sms", "msisdn": "+99999991001",
                                       "amount": 120.0, "account_mean": 100.0,
                                       "mode": "sidecar", "incumbent_score": 55.0}).json()
        assert r["band"] == "GOVERNOR_HELD_ESCALATE"
        d = c.post("/v1/stepup/dispatch", json={"token": r["step_up_grant"]["token"],
                                                "channel": "SMS"}).json()
        assert d["dispatched"] is True
        r2 = c.post("/v1/decide", json={"txn_id": "gov-sms-2", "msisdn": "+99999991001",
                                        "amount": 120.0, "account_mean": 100.0,
                                        "mode": "sidecar", "incumbent_score": 55.0}).json()
        d2 = c.post("/v1/stepup/dispatch", json={"token": r2["step_up_grant"]["token"],
                                                 "channel": "SMS_OTP"}).json()  # legacy alias
        assert d2["dispatched"] is True and d2["audit"]["reason"] is None
