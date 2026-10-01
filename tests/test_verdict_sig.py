"""Verdict signatures — the decision itself is signed, tamper-evident,
replay-stable (latency deliberately outside the signature)."""
import copy
from fastapi.testclient import TestClient

from app.verdict_sig import sign_verdict, verify_verdict


def _api_decide(c, txn, **extra):
    body = {"txn_id": txn, "msisdn": "+99999991001", "amount": 120.0,
            "account_mean": 100.0, "beneficiary_first_seen_minutes": 9999,
            "attempts_last_hour": 0}
    body.update(extra)
    return c.post("/v1/decide", json=body).json()


def test_verdict_signed_and_verifies():
    from app.main import app
    with TestClient(app) as c:
        r = _api_decide(c, "vs-1")
        vs = r["verdict_signature"]
        assert vs["algorithm"] == "Ed25519" and vs["signing_key_id"] == "maker@1"
        assert "decision" in vs["signed_fields"] and "policy_version_hash" in vs["signed_fields"]
        assert verify_verdict(r, "+99999991001") is True


def test_tamper_matrix_breaks_signature():
    from app.main import app
    with TestClient(app) as c:
        r = _api_decide(c, "vs-2")
        for path, val in [(["decision"], "DECLINE"), (["band"], "WHATEVER"),
                          (["total_risk"], 1.0), (["step_up", "allowed"], ["SMS"]),
                          (["cost", "trigger"], "event:fake"), (["thresholds_used", "escalate_gte"], 1.0)]:
            t = copy.deepcopy(r)
            t["verdict_signature"] = r["verdict_signature"]   # keep original sig
            reduce_set(t, path, val)
            assert verify_verdict(t, "+99999991001") is False, path


def reduce_set(d, path, val):
    for k in path[:-1]:
        d = d[k]
    d[path[-1]] = val


def test_latency_edits_do_not_break_signature():
    from app.main import app
    with TestClient(app) as c:
        r = _api_decide(c, "vs-3")
        t = copy.deepcopy(r)
        t["latency"]["end_to_end_ms"] = 999999
        t["reasons"] = [{"name": "FAKE", "latency_ms": 5}]
        assert verify_verdict(t, "+99999991001") is True   # timing is not identity


def test_wrong_msisdn_breaks_binding():
    from app.main import app
    with TestClient(app) as c:
        r = _api_decide(c, "vs-4")
        assert verify_verdict(r, "+99999999999") is False   # bound to the pseudonym


def test_idempotent_replay_same_signature():
    from app.main import app
    with TestClient(app) as c:
        a = _api_decide(c, "vs-5")
        b = _api_decide(c, "vs-5")
        assert b.get("idempotent_replay") is True
        assert a["verdict_signature"]["value"] == b["verdict_signature"]["value"]


def test_ledger_persists_signature():
    from app.main import app
    with TestClient(app) as c:
        r = _api_decide(c, "vs-6")
        recs = c.get("/v1/replay/vs-6").json()["intercept_records"]
        rec = recs[-1]   # append-only store: latest record for this txn
        vs = rec.get("verdict_signature")
        assert vs and vs["value"] == r["verdict_signature"]["value"]   # intact, identical


def test_swap_verdict_signature_survives_governor_and_hold_paths():
    from app.main import app
    with TestClient(app) as c:
        r = _api_decide(c, "vs-7", recent_sensitive_event="payee_added",
                        mode="sidecar", incumbent_score=55.0)
        assert verify_verdict(r, "+99999991001") is True
        r2 = _api_decide(c, "vs-8", call_in_progress=True)
        assert "hold" in r2 and verify_verdict(r2, "+99999991001") is True
