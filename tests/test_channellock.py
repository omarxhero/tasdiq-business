"""ChannelLock — the 12 enforcement tests (spec from the review panel).

Covers: swap-band never grants SMS · tamper/expiry/replay/audience/
policy-hash rejection · WebAuthn survives SMS block · clean traffic gets
no OTP path · refusal audit trail · local-verify latency · verifier
isolation from the engine · shadow/enforce parity.
Offline stubs only — no network, no model. Gateway HMAC is not
configured in tests (prototype mode: TASDIQ_GATEWAY_SECRET unset)."""
import copy
import time
from fastapi.testclient import TestClient

from app import channellock
from app.engine.decide import DecisionEngine
from tests.test_tiers import CountingNac, _req, bank, DEFAULT_BANK_A


def _verdict(sim_swapped=False, clean=False, txn_id="cl-txn"):
    nac = CountingNac(sim_swapped=sim_swapped)
    req = _req(txn_id=txn_id,
               amount=120.0 if clean else 3000.0,
               beneficiary_first_seen_minutes=9999 if clean else 3)
    return DecisionEngine(nac).decide(req, bank(DEFAULT_BANK_A))


def _grant(verdict, msisdn="+99999991001", bank_id="A", ttl=channellock.DEFAULT_TTL):
    return channellock.issue_grant(verdict, msisdn, bank_id, ttl=ttl)


# 1. SIM-swap transaction never receives an SMS grant.
def test_swap_band_never_grants_sms():
    v = _verdict(sim_swapped=True, txn_id="cl-swap")
    assert "SMS" in v["step_up"]["prohibited"]
    res = channellock.verify_grant(_grant(v), "SMS", "a-otp-gateway")
    assert res["authorized"] is False
    assert res["reason"] in ("CHANNEL_PROHIBITED", "CHANNEL_NOT_ALLOWED")

# 2. Tampered token is rejected.
def test_tampered_token_rejected():
    g = _grant(_verdict(clean=True, txn_id="cl-clean"))
    g["allowed"] = ["SMS"]          # attacker edits the allowed list in place
    res = channellock.verify_grant(g, "SMS", "a-otp-gateway")
    assert res["authorized"] is False and res["reason"] == "TAMPERED"

# 3. Expired token is rejected.
def test_expired_token_rejected():
    g = _grant(_verdict(clean=True, txn_id="cl-exp"), ttl=1)
    time.sleep(1.2)
    res = channellock.verify_grant(g, "WEBAUTHN", "a-otp-gateway")
    assert res["authorized"] is False and res["reason"] == "EXPIRED"

# 4. Reused nonce is rejected.
def test_reused_nonce_rejected():
    g = _grant(_verdict(sim_swapped=True, txn_id="cl-nonce"))
    first = channellock.verify_grant(g, "WEBAUTHN", "a-otp-gateway")
    assert first["authorized"] is True
    second = channellock.verify_grant(copy.deepcopy(g), "WEBAUTHN", "a-otp-gateway")
    assert second["authorized"] is False and second["reason"] == "REPLAYED"

# 5. Wrong bank audience is rejected.
def test_wrong_audience_rejected():
    g = _grant(_verdict(sim_swapped=True, txn_id="cl-aud"))
    res = channellock.verify_grant(g, "WEBAUTHN", "b-otp-gateway")
    assert res["authorized"] is False and res["reason"] == "WRONG_AUDIENCE"

# 6. The policy hash is bound into the signature (policy swap => tamper).
def test_policy_hash_bound_into_signature():
    g = _grant(_verdict(sim_swapped=True, txn_id="cl-pol"))
    assert g["policy_version_hash"].startswith("sha256:")
    g["policy_version_hash"] = "sha256:fakepolicy"
    res = channellock.verify_grant(g, "WEBAUTHN", "a-otp-gateway")
    assert res["authorized"] is False and res["reason"] == "TAMPERED"

# 7. WebAuthn remains available after SMS is blocked.
def test_webauthn_survives_sms_block():
    g = _grant(_verdict(sim_swapped=True, txn_id="cl-wa"))
    wa = channellock.verify_grant(g, "WEBAUTHN", "a-otp-gateway")
    sms = channellock.verify_grant(g, "SMS", "a-otp-gateway")
    assert wa["authorized"] is True and sms["authorized"] is False

# 8. Clean transaction: no OTP channel is grantable (OTP-free path).
def test_clean_traffic_gets_no_otp_path():
    v = _verdict(clean=True, txn_id="cl-clean2")
    assert v["decision"] == "APPROVE" and v["step_up"]["allowed"] == []
    g = _grant(v)
    for ch in ("SMS", "VOICE", "WEBAUTHN"):
        assert channellock.verify_grant(g, ch, "a-otp-gateway")["authorized"] is False

# 9. Gateway audit records every rejected channel attempt (through the API).
def test_gateway_refusal_audited():
    with TestClient(__import__("app.main", fromlist=["app"]).app) as c:
        r = c.post("/v1/decide", json={"txn_id": "cl-aud-t", "msisdn": "+99999991001",
                                       "amount": 120.0, "account_mean": 100.0})
        tok = r.json()["step_up_grant"]["token"]
        d = c.post("/v1/stepup/dispatch", json={"token": tok, "channel": "SMS"}).json()
        assert d["dispatched"] is False and d["audit"]["action"] == "REFUSED"
        a = c.get("/v1/stepup/audit").json()
        assert a["count"] >= 1 and a["records"][-1]["reason"] == "CHANNEL_NOT_ALLOWED"

# 10. Local verification latency below 5 ms.
def test_verify_latency_under_5ms():
    g = _grant(_verdict(sim_swapped=True, txn_id="cl-lat"))
    t0 = time.perf_counter()
    for _ in range(50):
        channellock.verify_grant(g, "WEBAUTHN", "a-otp-gateway")
    per_ms = (time.perf_counter() - t0) / 50 * 1000
    assert per_ms < 5.0, f"verify took {per_ms:.2f} ms"

# 11. Verifier isolated from the engine (Tasdiq outage never re-enables SMS).
def test_verifier_isolated_from_engine():
    g = _grant(_verdict(sim_swapped=True, txn_id="cl-iso"))
    src = open(channellock.__file__, encoding="utf-8").read()
    assert "NacClient" not in src and "requests" not in src and "httpx" not in src
    assert channellock.verify_grant(g, "SMS", "a-otp-gateway")["authorized"] is False

# 12. Shadow mode = same authorization verdict, no dispatch block.
def test_shadow_matches_enforce_without_blocking():
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/v1/decide", json={"txn_id": "cl-shd-t", "msisdn": "+99999991001",
                                       "amount": 120.0, "account_mean": 100.0})
        tok = r.json()["step_up_grant"]["token"]
        sh = c.post("/v1/stepup/dispatch",
                    json={"token": tok, "channel": "SMS", "mode": "shadow"}).json()
        en = c.post("/v1/stepup/dispatch",
                    json={"token": tok, "channel": "SMS", "mode": "enforce"}).json()
        assert sh["dispatched"] is True and sh["would_have_refused"] is True
        assert en["dispatched"] is False
        assert sh["audit"]["reason"] == en["audit"]["reason"]
