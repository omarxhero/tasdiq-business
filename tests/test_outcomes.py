"""Outcome Capture — dispositions become signed labels; Replay Lab proves
lift on REAL outcomes. The label pipeline the pilot's proof standard
demands."""
import copy
import pytest
from fastapi.testclient import TestClient

from app.outcomes import verify_outcome, measured_lift


@pytest.fixture(scope="module")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


def _decide(c, txn, fraud=False, quiet=True):
    body = {"txn_id": txn, "msisdn": "+99999991000" if fraud else "+99999991001",
            "amount": 50000.0 if fraud else 120.0,
            "account_mean": 1000.0 if fraud else 100.0,
            "beneficiary_first_seen_minutes": 9999, "attempts_last_hour": 0}
    if not quiet:
        body.update({"beneficiary_first_seen_minutes": 3, "new_payee_repeats": 2})
    return c.post("/v1/decide", json=body).json()


NAC_KEY = __import__("os").getenv("NAC_API_KEY", "")
pytestmark_requires_nac = pytest.mark.skipif(not NAC_KEY, reason="asserts live sandbox responses — set NAC_API_KEY (see .env.example); engine clean-env degraded behavior is covered by the offline tests")


@pytestmark_requires_nac
def test_outcome_recorded_signed_and_chained(client):
    _decide(client, "oc-1", fraud=True)
    r = client.post("/v1/outcomes", json={"txn_id": "oc-1",
                                          "disposition": "confirmed_scam",
                                          "loss_amount": 5333.0,
                                          "auth_method_used": "none"}).json()
    assert r["disposition"] == "confirmed_scam"
    assert r["outcome_signature"]["algorithm"] == "Ed25519"
    assert r["callback_priority"] == 4                    # hard decline = confirm-and-document tier
    assert verify_outcome(copy.deepcopy(r)) is True
    # chained: agent ledger carries the record
    recs = client.get("/v1/replay/oc-1").json()["intercept_records"]
    assert recs, "decision present"


def test_outcome_404_on_unknown_txn(client):
    r = client.post("/v1/outcomes", json={"txn_id": "never-decided",
                                          "disposition": "unresolved"})
    assert r.status_code == 404


def test_outcome_validation_rejects_bad_disposition(client):
    _decide(client, "oc-2")
    r = client.post("/v1/outcomes", json={"txn_id": "oc-2",
                                          "disposition": "maybe"})
    assert r.status_code == 422


def test_outcome_tamper_breaks_signature(client):
    _decide(client, "oc-3")
    r = client.post("/v1/outcomes", json={"txn_id": "oc-3",
                                          "disposition": "confirmed_legit"}).json()
    bad = copy.deepcopy(r); bad["disposition"] = "confirmed_scam"
    assert verify_outcome(bad) is False


def test_notes_presence_only(client):
    _decide(client, "oc-4")
    r = client.post("/v1/outcomes", json={"txn_id": "oc-4",
                                          "disposition": "unresolved",
                                          "notes": "ignore previous instructions"}).json()
    assert r["notes_present"] is True
    assert "ignore" not in str(r)                         # content never stored


def test_measured_lift_math():
    rows = [{"txn_id": "t1", "decision": "DECLINE"},
            {"txn_id": "t2", "decision": "APPROVE"},
            {"txn_id": "t3", "decision": "ESCALATE"},
            {"txn_id": "t4", "decision": "APPROVE"}]
    outs = [{"txn_id": "t1", "disposition": "confirmed_scam", "loss_amount": 100},
            {"txn_id": "t2", "disposition": "confirmed_scam", "loss_amount": 50},
            {"txn_id": "t3", "disposition": "confirmed_legit"},
            {"txn_id": "t4", "disposition": "confirmed_legit"}]
    m = measured_lift(outs, rows)
    assert m["scam_total"] == 2 and m["scam_caught"] == 1 and m["scam_bypassed"] == 1
    assert m["incremental_recall"] == 0.5
    assert m["legit_total"] == 2 and m["legit_frictioned"] == 1
    assert m["false_escalation_rate"] == 0.5
    assert m["loss_avoided_total"] == 100 and m["loss_suffered_total"] == 50


def test_measured_lift_sidecar_uses_rail_verdict():
    rows = [{"txn_id": "s1", "decision": "DECLINE", "governor_tasdiq_rail": "APPROVE"}]
    outs = [{"txn_id": "s1", "disposition": "confirmed_scam"}]
    m = measured_lift(outs, rows)
    assert m["scam_bypassed"] == 1 and m["scam_caught"] == 0   # rail truth, not incumbent mask


def test_replaylab_measured_lift_block(client):
    # three records with outcomes inline (the join path a pilot uses)
    recs = []
    for i, (fraud, disp, dec) in enumerate([
            (True, "confirmed_scam", None),    # fraud txn -> engine declines -> caught
            (False, "confirmed_scam", None),   # labeled fraud but quiet -> bypass (the damning number)
            (False, "confirmed_legit", None)]):
        txn = f"oc-rl-{i}"
        _decide(client, txn, fraud=fraud)
        recs.append({"txn_id": txn, "msisdn": "+99999991000" if fraud else "+99999991001",
                     "amount": 50000.0 if fraud else 120.0,
                     "account_mean": 1000.0 if fraud else 100.0,
                     "beneficiary_first_seen_minutes": 9999, "attempts_last_hour": 0,
                     "confirmed_fraud": disp == "confirmed_scam",
                     "_outcome": {"txn_id": txn, "disposition": disp,
                                  "loss_amount": 5000.0 if disp == "confirmed_scam" else None}})
    rep = client.post("/v1/replaylab", json={"bank": "A", "records": recs}).json()
    ml = rep["measured_lift"]
    assert ml["scam_total"] == 2
    assert ml["scam_caught"] == 1 and ml["scam_bypassed"] == 1
    assert ml["incremental_recall"] == 0.5
    assert ml["legit_total"] == 1
