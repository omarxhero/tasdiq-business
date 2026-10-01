"""UNKNOWN request semantics — omitted context is screened, never clean.
Engine sentinels + API model_fields_set injection + verdict provenance."""
from fastapi.testclient import TestClient

from app.engine.decide import DecisionEngine
from tests.test_tiers import CountingNac, _req, bank, DEFAULT_BANK_A


def _decide(**kw):
    req = _req(txn_id=kw.pop("txn_id", "un-1"))
    for f in ("beneficiary_first_seen_minutes", "attempts_last_hour", "account_mean"):
        if f in kw and kw[f] is None:
            req.pop(f)
    req.update({k: v for k, v in kw.items() if v is not None})
    return DecisionEngine(CountingNac()).decide(req, bank(DEFAULT_BANK_A))


def test_missing_payee_age_screens_instead_of_clean():
    out = _decide(beneficiary_first_seen_minutes=None, txn_id="un-pa")
    assert out["cost"]["tier"] == 1                          # SIM bought — not tier 0
    assert out["cost"]["trigger"] == "unknown:payee_age"
    assert out["data_quality"]["unknown_fields"] == ["payee_age"]
    assert out["decision"] == "APPROVE" and out["band"] == "CLEAN"  # green = pass WITH evidence


def test_missing_attempts_flagged():
    out = _decide(attempts_last_hour=None, txn_id="un-at")
    assert "attempts" in out["data_quality"]["unknown_fields"]
    assert out["cost"]["tier"] >= 1


def test_missing_account_mean_no_fake_spike():
    # old bug: default 1.0 made amount/mean = amount -> phantom 5000x spike.
    # now: ratio UNKNOWN -> screening, no spike math, no false severe
    out = _decide(account_mean=None, amount=5000.0, txn_id="un-am")
    assert out["cost"]["tier"] == 1                          # screened, NOT tier-2 severe
    assert "account_mean" in out["data_quality"]["unknown_fields"]
    assert out["cost"]["signals_bought"] == ["SIM_SWAP"]


def test_all_unknowns_listed_and_screened():
    out = _decide(beneficiary_first_seen_minutes=None, attempts_last_hour=None,
                  account_mean=None, txn_id="un-all")
    assert set(out["data_quality"]["unknown_fields"]) == {"payee_age", "attempts", "account_mean"}
    assert out["cost"]["tier"] == 1


def test_complete_context_still_tier0():
    out = _decide(beneficiary_first_seen_minutes=9999, attempts_last_hour=0, txn_id="un-ok")
    assert out["cost"]["tier"] == 0
    assert "data_quality" not in out
    assert out["cost"]["trigger"] == "none"


def test_unknown_plus_real_spike_still_escalates():
    # unknown payee-age + a REAL 50x spike (amount & mean both sent): the spike
    # is genuine, green telecom fires rule 5 — unknown never weakens real signals
    out = _decide(beneficiary_first_seen_minutes=None, txn_id="un-sw",
                  **{"amount": 50000.0, "account_mean": 1000.0})
    assert out["decision"] == "ESCALATE" and out["band"] == "BEHAVIORAL_ANOMALY"
    assert out["cost"]["signals_bought"]            # screened AND swept (severe)


def test_api_omitted_fields_screened():
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/v1/decide", json={"txn_id": "un-api", "msisdn": "+99999991001",
                                       "amount": 120.0}).json()   # no account_mean etc
        assert r["cost"]["tier"] >= 1
        assert "account_mean" in r["data_quality"]["unknown_fields"]
        # explicitly-sent values are honored as KNOWN
        r2 = c.post("/v1/decide", json={"txn_id": "un-api2", "msisdn": "+99999991001",
                                        "amount": 120.0, "account_mean": 100.0,
                                        "beneficiary_first_seen_minutes": 9999,
                                        "attempts_last_hour": 0}).json()
        assert "data_quality" not in r2 and r2["cost"]["tier"] == 0


def test_replay_rows_flag_unknown_records():
    from app.replaylab import replay
    from app.policy import DEFAULT_BANK_A
    from tests.test_core import signed
    import copy
    recs = [{"txn_id": "un-r1", "msisdn": "+9", "amount": 1500.0,
             "confirmed_fraud": False}]          # bank log WITHOUT payee-age column
    rep = replay(recs, copy.deepcopy(signed(DEFAULT_BANK_A)))
    row = rep["rows"][0]
    assert row["tier"] >= 1 and row.get("data_quality", {}).get("unknown_fields")
