"""Posture cache tests — the three-state machine, the gates, the canary,
and the silence-is-never-clean contract."""
import time
import pytest

from app.posture import PostureStore


@pytest.fixture()
def store(tmp_path):
    s = PostureStore(tmp_path / "posture.json")
    yield s
    s.reset()


# ---- the state machine -------------------------------------------------------

def test_never_seen_is_unknown_never_clean(store):
    st = store.effective_state("+966500000001")
    assert st["state"] == "UNKNOWN" and st["reason"] == "never_seen"


def test_swap_event_makes_swapped_and_retains_long(store):
    store.apply_event({"event_id": "e1", "msisdn": "+966500000001",
                       "type": "sim_swap", "network_event_time": int(time.time())},
                      provider_ok=True)
    st = store.effective_state("+966500000001")
    assert st["state"] == "SWAPPED" and st["age_hours"] < 1


def test_stable_requires_trusted_snapshot_not_silence(store):
    # NO event at all -> UNKNOWN even after other numbers had events
    store.apply_event({"event_id": "e2", "msisdn": "+966500000002",
                       "type": "sim_swap"}, provider_ok=True)
    assert store.effective_state("+966500000003")["state"] == "UNKNOWN"
    # trusted snapshot -> STABLE
    store.apply_event({"event_id": "e3", "msisdn": "+966500000003",
                       "type": "stable_snapshot"}, provider_ok=True)
    assert store.effective_state("+966500000003")["state"] == "OBSERVED_STABLE"


def test_subscription_ended_reverts_to_unknown(store):
    store.apply_event({"event_id": "e4", "msisdn": "+966500000004",
                       "type": "stable_snapshot"}, provider_ok=True)
    store.mark_subscription_ended("+966500000004")
    st = store.effective_state("+966500000004")
    assert st["state"] == "UNKNOWN" and st["reason"] == "subscription_ended"


def test_stable_ttl_expiry_is_unknown_not_clean(store):
    old = int(time.time()) - 7200 - 10
    store.apply_event({"event_id": "e5", "msisdn": "+966500000005",
                       "type": "stable_snapshot", "network_event_time": old},
                      provider_ok=True)
    st = store.effective_state("+966500000005")
    assert st["state"] == "UNKNOWN" and st["reason"] == "ttl_expired"


def test_swap_aged_past_retention_is_unknown_not_stable(store):
    old = int(time.time()) - 240 * 3600 - 10
    store.apply_event({"event_id": "e6", "msisdn": "+966500000006",
                       "type": "sim_swap", "network_event_time": old},
                      provider_ok=True)
    st = store.effective_state("+966500000006")
    assert st["state"] == "UNKNOWN" and st["reason"] == "swap_aged_past_retention"


# ---- ingress hardening --------------------------------------------------------

def test_forged_event_rejected_without_provider_auth(store):
    r = store.apply_event({"event_id": "f1", "msisdn": "+966500000001",
                           "type": "sim_swap"}, provider_ok=False)
    assert r["applied"] is False and r["reason"] == "AUTH"
    assert store.effective_state("+966500000001")["state"] == "UNKNOWN"


def test_duplicate_event_id_applied_once(store):
    ev = {"event_id": "d1", "msisdn": "+966500000007", "type": "sim_swap"}
    assert store.apply_event(ev, True)["applied"] is True
    assert store.apply_event(ev, True)["reason"] == "DUPLICATE"


def test_out_of_order_event_ignored(store):
    now = int(time.time())
    store.apply_event({"event_id": "o1", "msisdn": "+966500000008",
                       "type": "sim_swap", "network_event_time": now}, True)
    r = store.apply_event({"event_id": "o2", "msisdn": "+966500000008",
                           "type": "stable_snapshot",
                           "network_event_time": now - 50}, True)
    assert r["reason"] == "STALE_ORDER"
    assert store.effective_state("+966500000008")["state"] == "SWAPPED"


def test_keys_are_hmac_not_plain_sha(store):
    import hashlib
    from app.config import cfg
    plain = hashlib.sha256("+966500000009".encode()).hexdigest()[:24]
    store.apply_event({"event_id": "k1", "msisdn": "+966500000009",
                       "type": "sim_swap"}, True)
    # stored key must NOT be the plain sha (enumerable)
    assert f"{plain}" not in " ".join(store._data.keys())
    from app.posture import _key
    assert _key("+966500000009").startswith("pm_")


# ---- substitution gate ---------------------------------------------------------

def test_substitution_gate_all_conditions(store):
    ms = "+966500000010"
    store.apply_event({"event_id": "g1", "msisdn": ms, "type": "stable_snapshot"}, True)
    ok, gate = store.may_substitute(ms, amount_vs_mean=2.0, payee_age_min=9999,
                                    sensitive_event=False)
    assert ok and all(gate.values())
    # high amount -> live query
    ok, gate = store.may_substitute(ms, amount_vs_mean=25.0, payee_age_min=9999,
                                    sensitive_event=False)
    assert not ok and not gate["amount_ok"]
    # fresh payee -> live
    ok, gate = store.may_substitute(ms, amount_vs_mean=2.0, payee_age_min=10,
                                    sensitive_event=False)
    assert not ok and not gate["payee_ok"]
    # sensitive event -> live (belt-and-braces)
    ok, gate = store.may_substitute(ms, 2.0, 9999, sensitive_event=True)
    assert not ok and not gate["no_event"]
    # SWAPPED state never substitutes
    ms2 = "+966500000011"
    store.apply_event({"event_id": "g2", "msisdn": ms2, "type": "sim_swap"}, True)
    ok, _ = store.may_substitute(ms2, 2.0, 9999, False)
    assert not ok
    # UNKNOWN never substitutes
    ok, _ = store.may_substitute("+999...", 2.0, 9999, False)
    assert not ok


# ---- canary audit ---------------------------------------------------------------

def test_canary_contradiction_trips_breaker(store):
    ms = "+966500000012"
    store.apply_event({"event_id": "c1", "msisdn": ms, "type": "stable_snapshot"}, True)
    # 3 checks, 2 contradictions -> >2% -> breaker
    store.canary(ms, live_swapped=False)   # agree
    store.canary(ms, live_swapped=True)    # contradiction 1
    store.canary(ms, live_swapped=True)    # contradiction 2 -> trips
    assert store.breaker_live_only is True
    ok, gate = store.may_substitute(ms, 2.0, 9999, False)
    assert not ok and not gate["breaker_ok"]


def test_canary_agreement_keeps_serving(store):
    ms = "+966500000013"
    store.apply_event({"event_id": "c2", "msisdn": ms, "type": "stable_snapshot"}, True)
    for _ in range(20):
        store.canary(ms, live_swapped=False)
    assert store.breaker_live_only is False and store.contradictions == 0
    ok, _ = store.may_substitute(ms, 2.0, 9999, False)
    assert ok


def test_persistence_roundtrip(tmp_path):
    p = tmp_path / "p2.json"
    s1 = PostureStore(p)
    s1.apply_event({"event_id": "p1", "msisdn": "+966500000014",
                    "type": "sim_swap"}, True)
    s2 = PostureStore(p)
    assert s2.effective_state("+966500000014")["state"] == "SWAPPED"
    s2.reset()


# ---- API ingress end-to-end ---------------------------------------------------

def _sig(event_id, msisdn, typ):
    import hashlib, hmac, os
    secret = os.getenv("TASDIQ_EVENT_SECRET", "demo-event-secret")
    return hmac.new(secret.encode(), f"{event_id}.{msisdn}.{typ}".encode(),
                    hashlib.sha256).hexdigest()


def test_api_ingress_full_loop(tmp_path):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.posture import POSTURE
    POSTURE.reset()
    with TestClient(app) as c:
        # forged -> rejected, posture stays UNKNOWN
        r = c.post("/v1/events", json={"event_id": "api-e1", "msisdn": "+966500000020",
                                       "type": "sim_swap", "provider_signature": "bad"})
        assert r.json()["applied"] is False
        assert POSTURE.effective_state("+966500000020")["state"] == "UNKNOWN"
        # authenticated swap event -> SWAPPED
        r = c.post("/v1/events", json={"event_id": "api-e2", "msisdn": "+966500000020",
                                       "type": "sim_swap",
                                       "provider_signature": _sig("api-e2", "+966500000020", "sim_swap")})
        assert r.json()["state"] == "SWAPPED"
        # THE demo: decide on that number now catches the swap WITHOUT a live query
        d = c.post("/v1/decide", json={"txn_id": "post-1", "msisdn": "+966500000020",
                                       "amount": 120.0, "account_mean": 100.0,
                                       "beneficiary_first_seen_minutes": 9999,
                                       "attempts_last_hour": 0}).json()
        assert d["decision"] == "ESCALATE" and "SMS" in d["step_up"]["prohibited"]
        # duplicate rejected
        r = c.post("/v1/events", json={"event_id": "api-e2", "msisdn": "+966500000020",
                                       "type": "sim_swap",
                                       "provider_signature": _sig("api-e2", "+966500000020", "sim_swap")})
        assert r.json()["reason"] == "DUPLICATE"
    POSTURE.reset()


def test_posture_stable_substitutes_and_saves_query():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.posture import POSTURE
    POSTURE.reset()
    with TestClient(app) as c:
        c.post("/v1/events", json={"event_id": "st-1", "msisdn": "+966500000021",
                                   "type": "stable_snapshot",
                                   "provider_signature": _sig("st-1", "+966500000021", "stable_snapshot")})
        # radar-flagged txn (fresh payee) on a STABLE number: tier-1 served from
        # cache — signals_bought shows the cache source, cost still $0.07 ceiling
        d = c.post("/v1/decide", json={"txn_id": "post-2", "msisdn": "+966500000021",
                                       "amount": 150.0, "account_mean": 100.0,
                                       "beneficiary_first_seen_minutes": 3,
                                       "attempts_last_hour": 0}).json()
        assert d["cost"]["tier"] == 1
        assert d["cost"]["signals_bought"] == ["SIM_SWAP"]
        # high amount must NOT substitute (gate) -> tier 2 sweep
        d2 = c.post("/v1/decide", json={"txn_id": "post-3", "msisdn": "+966500000021",
                                        "amount": 5000.0, "account_mean": 100.0,
                                        "beneficiary_first_seen_minutes": 9999,
                                        "attempts_last_hour": 0}).json()
        assert d2["cost"]["tier"] == 2
    POSTURE.reset()


def test_subscription_ended_asymmetry_is_design():
    """STABLE+ended -> UNKNOWN (silence never clean); SWAPPED+ended -> SWAPPED
    (a positive historical fact survives until retention — dropping it would
    be fail-open). Both directions are the fail-strict choice."""
    store = PostureStore(__import__("pathlib").Path(
        __import__("tempfile").mkdtemp()) / "p.json")
    store.apply_event({"event_id": "a1", "msisdn": "+966500000030",
                       "type": "stable_snapshot"}, True)
    store.apply_event({"event_id": "a2", "msisdn": "+966500000031",
                       "type": "sim_swap"}, True)
    store.mark_subscription_ended("+966500000030")
    store.mark_subscription_ended("+966500000031")
    assert store.effective_state("+966500000030")["state"] == "UNKNOWN"
    assert store.effective_state("+966500000031")["state"] == "SWAPPED"
    store.reset()
