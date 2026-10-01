"""Replay Lab — labeled synthetic dataset tests: bypass finder, friction,
counterfactual exposure, incumbent matrix, signed-report tamper evidence."""
import copy
import pytest
from fastapi.testclient import TestClient

from app.replaylab import replay, verify_report
from app.policy import DEFAULT_BANK_A
from tests.test_core import signed

BUNDLE = signed(copy.deepcopy(DEFAULT_BANK_A))


def _rec(**kw):
    # complete context by default — omitted fields now mean UNKNOWN (screened),
    # so fixtures that want quiet traffic must declare their fields honestly
    r = {"msisdn": "+99999991001", "amount": 120.0, "account_mean": 100.0,
         "beneficiary_first_seen_minutes": 9999, "attempts_last_hour": 0}
    r.update(kw)
    return r


DATASET = [
    # 1. quiet clean
    _rec(txn_id="t1", confirmed_fraud=False),
    # 2. quiet FRAUD that sails through — the bypass the lab must find
    _rec(txn_id="t2", amount=1500.0, account_mean=100.0, confirmed_fraud=True,
         beneficiary_first_seen_minutes=120),
    # 3. fresh payee + repeat — trap catches (fraud)
    _rec(txn_id="t3", beneficiary_first_seen_minutes=3, new_payee_repeats=2,
         confirmed_fraud=True),
    # 4. coached payment (fraud)
    _rec(txn_id="t4", call_in_progress=True, call_direction="inbound",
         confirmed_fraud=True),
    # 5. clean but escalated (friction): fresh payee alone -> tier1, low score...
    #    quiet-but-flagged records escalate only via rules; use swap-unavailable
    #    + fresh payee -> R3 blind-safe escalation on a clean record
    _rec(txn_id="t5", beneficiary_first_seen_minutes=2, confirmed_fraud=False),
    # 6. incumbent comparison rows
    _rec(txn_id="t6", incumbent_decision="APPROVE", confirmed_fraud=False),
    _rec(txn_id="t7", amount=1500.0, account_mean=100.0,
         incumbent_decision="APPROVE", confirmed_fraud=False),
]


def _run():
    return replay(copy.deepcopy(DATASET), copy.deepcopy(BUNDLE))


def test_bypass_finder_finds_confirmed_fraud_approval():
    rep = _run()
    ids = [r["txn_id"] for r in rep["bypass"]["rows"]]
    assert "t2" in ids                      # 15x mean, payee 2h old -> quiet approve
    assert "t3" not in ids and "t4" not in ids


def test_caught_and_counts_reconcile():
    rep = _run()
    assert rep["caught"]["count"] >= 2       # trap + coached at minimum
    assert rep["volumes"]["records"] == 7
    assert rep["volumes"]["labeled"] == 7


def test_friction_counts_clean_escalations():
    rep = _run()
    ids = [r["txn_id"] for r in rep["friction"]["rows"]]
    # t5: fresh payee + signals UNAVAILABLE -> R3 blind-safe -> escalate (clean record)
    assert "t5" in ids


def test_counterfactual_exposure_on_quiet_approvals():
    rep = _run()
    ids = [r["txn_id"] for r in rep["exposure"]["rows"]]
    assert "t1" in ids and "t2" in ids       # quiet approvals would change under live swap
    assert rep["exposure"]["count"] >= 1


def test_incumbent_matrix():
    rep = _run()
    m = rep["incumbent"]
    assert m["total_labeled"] == 2
    assert m["agree"] + m["tasdiq_added"] + m["tasdiq_softer"] == 2


def test_report_is_signed_and_tamper_evident():
    rep = _run()
    assert verify_report(rep) is True
    tampered = copy.deepcopy(rep)
    tampered["bypass"]["count"] = 0           # silent edit
    assert verify_report(tampered) is False
    again = copy.deepcopy(rep)
    again["rows"][0]["decision"] = "DECLINE"
    assert verify_report(again) is False


def test_report_carries_policy_hash_and_signal_source_label():
    rep = _run()
    assert rep["policy_version_hash"].startswith("sha256:")
    assert "UNAVAILABLE(replay)" in rep["signal_source"]


def test_deterministic():
    a, b = _run(), _run()
    assert a["volumes"] == b["volumes"] and a["bypass"]["count"] == b["bypass"]["count"]


def test_recorded_signals_used_when_present():
    recs = [_rec(txn_id="s1", amount=50000.0, confirmed_fraud=True,
                 beneficiary_first_seen_minutes=120,
                 signals={"sim_swap": {"value": {"swapped": True}, "confidence": 1.0}})]
    rep = replay(recs, copy.deepcopy(BUNDLE))
    row = rep["rows"][0]
    assert row["decision"] == "DECLINE"       # recorded swap drives the early exit
    assert rep["caught"]["count"] == 1


def test_endpoint_end_to_end():
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/v1/replaylab", json={"bank": "A", "records": copy.deepcopy(DATASET)}).json()
        assert r["volumes"]["records"] == 7
        assert "signature" in r and r["signature"]["algorithm"] == "Ed25519"
        assert any(x["txn_id"] == "t2" for x in r["bypass"]["rows"])
        r422 = c.post("/v1/replaylab", json={"bank": "A", "records": []})
        assert r422.status_code == 422


# metric honesty: sidecar incumbent strength must not mask Tasdiq's own verdict
def test_sidecar_bypass_not_masked_by_incumbent():
    recs = [{"txn_id": "sb1", "msisdn": "+9", "amount": 1500.0, "account_mean": 100.0,
             "beneficiary_first_seen_minutes": 120, "attempts_last_hour": 0,
             "mode": "sidecar", "incumbent_decision": "DECLINE",
             "confirmed_fraud": True}]
    rep = replay(recs, copy.deepcopy(BUNDLE))
    # final was DECLINE (governor-held) but the BYPASS is Tasdiq's and must surface
    assert any(r["txn_id"] == "sb1" for r in rep["bypass"]["rows"])
    assert rep["friction"]["count"] == 0


def test_sidecar_incumbent_escalation_is_not_our_friction():
    recs = [{"txn_id": "sf1", "msisdn": "+9", "amount": 120.0, "account_mean": 100.0,
             "beneficiary_first_seen_minutes": 9999, "attempts_last_hour": 0,
             "mode": "sidecar", "incumbent_decision": "ESCALATE",
             "confirmed_fraud": False}]
    rep = replay(recs, copy.deepcopy(BUNDLE))
    assert rep["friction"]["count"] == 0
