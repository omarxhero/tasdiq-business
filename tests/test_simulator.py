"""Policy Simulator — contract tests: the page's fixtures MUST match the
engine. Both consume the same JSON files; a drift here means the demo
would lie. Also proves demo-tenant isolation properties."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

FIX = Path(__file__).resolve().parent.parent / "demo" / "simulator_fixtures"


def _fixtures():
    return [json.loads(f.read_text(encoding="utf-8")) for f in sorted(FIX.glob("*.json"))]


@pytest.fixture(scope="module")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


def test_fixtures_exist_and_wellformed():
    fx = _fixtures()
    assert len(fx) >= 8
    for f in fx:
        for k in ("scenario_id", "title_en", "title_ar", "input", "expected", "teaches_en", "teaches_ar"):
            assert k in f, (f["scenario_id"], k)
        assert f["input"].get("msisdn") in ("+99999991000", "+99999991001"), \
            f"{f['scenario_id']}: sandbox numbers ONLY in demo fixtures"


NAC_KEY = __import__("os").getenv("NAC_API_KEY", "")
pytestmark_requires_nac = pytest.mark.skipif(not NAC_KEY, reason="asserts live sandbox responses — set NAC_API_KEY (see .env.example); engine clean-env degraded behavior is covered by the offline tests")


@pytestmark_requires_nac
def test_every_preset_matches_the_engine(client):
    """THE contract: run each fixture's input through the real engine and
    assert every pinned expectation. The demo cannot drift from the code."""
    from app.policy import DEFAULT_BANK_A
    from tests.test_core import signed
    import copy
    for f in _fixtures():
        r = client.post("/v1/decide", json={**f["input"],
                                            "txn_id": f"sim-{f['scenario_id']}"}).json()
        exp = f["expected"]
        ctx = f["scenario_id"]
        assert r["decision"] == exp["decision"], (ctx, r["band"])
        assert r["band"] == exp["band"], (ctx, r["band"])
        if "tier" in exp:
            assert r["cost"]["tier"] == exp["tier"], (ctx, r["cost"]["tier"])
        if "cost_usd" in exp:
            assert abs(r["cost"]["cost_estimate_usd"] - exp["cost_usd"]) < 0.001, ctx
        if exp.get("sms_prohibited"):
            assert "SMS" in r["step_up"]["prohibited"], ctx
        if exp.get("biometric_allowed"):
            assert "IN_APP_BIOMETRIC" in r["step_up"]["allowed"], ctx
        if exp.get("sms_grantable") is False:
            d = client.post("/v1/stepup/dispatch",
                            json={"token": r["step_up_grant"]["token"], "channel": "SMS"}).json()
            assert d["dispatched"] is False, ctx
        if exp.get("no_channel_grantable"):
            for ch in ("SMS", "VOICE", "WEBAUTHN", "IN_APP_BIOMETRIC"):
                d = client.post("/v1/stepup/dispatch",
                                json={"token": r["step_up_grant"]["token"], "channel": ch}).json()
                assert d["dispatched"] is False, (ctx, ch)
        if exp.get("hold_release_minutes"):
            assert r["hold"]["release_after_minutes"] == exp["hold_release_minutes"], ctx
        if "weighted_risk_min" in exp:
            # sandbox conf can be 1.0 (live) or 0.9 (cached fallback) — the FLOOR
            # property must hold under both: weighted >= 0.9 x 40 = 36
            assert r["weighted_risk"] >= exp["weighted_risk_min"], (ctx, r["weighted_risk"])
        if exp.get("governor_final"):
            assert r["governor"]["final"] == exp["governor_final"], ctx
            assert r["governor"]["counterfactual"] is not None, ctx
        if "trigger_prefix" in exp:
            assert r["cost"]["trigger"].startswith(exp["trigger_prefix"]), (ctx, r["cost"]["trigger"])
        if "unknown_fields" in exp:
            assert set(exp["unknown_fields"]) <= set(r["data_quality"]["unknown_fields"]), ctx


def test_fixtures_endpoint_serves_them_all(client):
    r = client.get("/v1/simulator/fixtures").json()
    assert r["count"] == len(_fixtures())
    ids = {f["scenario_id"] for f in r["fixtures"]}
    assert "sim_swap_attack_v1" in ids and "coached_call_v1" in ids
    # demo contract: no raw thresholds in the payload
    blob = json.dumps(r)
    for secret in ("decline_gte", "escalate_gte", "instant_multiplier", "API_KEY", "SECRET"):
        assert secret not in blob, secret


def test_demo_isolation_sandbox_numbers_only(client):
    """A real-looking number must not appear in any fixture; the page never
    learns anything about production tenants."""
    for f in _fixtures():
        assert f["input"]["msisdn"].startswith("+9999999"), f["scenario_id"]


def test_fixture_source_regenerates_identically():
    """The src generator and the on-disk fixtures are in sync (no stale JSON)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "fixsrc", Path(__file__).resolve().parent.parent / "demo" / "simulator_fixtures_src.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    disk = {f["scenario_id"]: f for f in _fixtures()}
    for p in mod.PRESETS:
        assert p == disk[p["scenario_id"]], p["scenario_id"]


def test_simulator_page_contract():
    """The page references only existing endpoints and carries no secrets."""
    import re
    from pathlib import Path
    page = (Path(__file__).resolve().parent.parent / "demo" / "policy_simulator.html")         .read_text(encoding="utf-8")
    endpoints = set(re.findall(r"fetch\('(/v1/[a-z/]+)'", page))
    assert endpoints <= {"/v1/simulator/fixtures", "/v1/decide", "/v1/stepup/dispatch"}
    for bad in ("API_KEY", "SECRET", "GEMINI", "NAC_", "VAULT", "Bearer "):
        assert bad not in page, bad
    # bilingual present (Arabic checked via unicode escapes for console safety)
    assert "Policy Simulator" in page
    assert "العربية" in page


def test_single_use_grant_semantics_on_authorized_dispatch(client):
    """One grant, two allowed channels: the FIRST authorized dispatch burns the
    nonce; the second is REPLAYED (single-use by design — a bank gateway
    dispatches one step-up per transaction). Locks the semantics the recheck
    probe surfaced as INTENDED behavior, not a bug."""
    r = client.post("/v1/decide", json={"txn_id": "sim-single-use", "msisdn": "+99999991000",
                                        "amount": 3000.0, "account_mean": 100.0,
                                        "beneficiary_first_seen_minutes": 3,
                                        "attempts_last_hour": 0}).json()
    assert set(r["step_up"]["allowed"]) >= {"WEBAUTHN", "IN_APP_BIOMETRIC"}
    first = client.post("/v1/stepup/dispatch", json={"token": r["step_up_grant"]["token"],
                                                     "channel": "WEBAUTHN"}).json()
    second = client.post("/v1/stepup/dispatch", json={"token": r["step_up_grant"]["token"],
                                                      "channel": "IN_APP_BIOMETRIC"}).json()
    assert first["dispatched"] is True
    assert second["dispatched"] is False and second["audit"]["reason"] == "REPLAYED"
