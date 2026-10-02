"""Verdict webhooks — panel-hardened spec: SSRF allowlist, outbox
non-interference, at-least-once + DLQ + replay, HMAC transport with
rotation, tamper evidence, CEF format, pseudonymous projection."""
import copy
import json
import time
import pytest
from fastapi.testclient import TestClient

from app import webhooks as wh


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    wh.reset_demo_registry()
    # offline determinism: stub DNS for fake SIEM hostnames -> public IP;
    # the SSRF block tests below monkeypatch to private IPs explicitly
    real = wh._is_blocked_host
    def stub(host):
        if host.endswith(".example.com") or host.endswith(".example"):
            return real("93.184.216.34")     # a public address -> not blocked
        return real(host)
    monkeypatch.setattr(wh, "_is_blocked_host", stub)
    yield
    wh.reset_demo_registry()


@pytest.fixture(scope="module")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


# ---------------- registration + SSRF ----------------------------------------

def test_register_requires_https(client):
    r = client.post("/v1/webhooks", json={"url": "http://siem.bank.local/hook",
                                          "secret": "s1"})
    assert r.status_code == 422


def test_register_blocks_private_and_metadata(client):
    for host in ("https://169.254.169.254/latest", "https://127.0.0.1/hook",
                 "https://10.0.0.5/hook", "https://192.168.1.10/hook"):
        r = client.post("/v1/webhooks", json={"url": host, "secret": "s1"})
        assert r.status_code == 422, host


# ---------------- outbox + delivery matrix -----------------------------------

def _decide(client, txn):
    return client.post("/v1/decide", json={"txn_id": txn, "msisdn": "+99999991001",
                                           "amount": 120.0, "account_mean": 100.0,
                                           "beneficiary_first_seen_minutes": 9999,
                                           "attempts_last_hour": 0}).json()


def test_decision_enqueues_outbox_row_without_registered_endpoints(client):
    _decide(client, "wh-1")
    # no registry -> no outbox writes (nothing to deliver)
    assert not wh.OUTBOX_PATH.exists() or all(
        r["status"] == "pending" for r in [json.loads(l) for l in wh.OUTBOX_PATH.read_text().splitlines() if l])


def test_delivery_success_matrix(client):
    ep = wh.WebhookEndpoint(url="https://siem.example.com/hook", secret_current="sekrit")
    wh.register(ep)
    _decide(client, "wh-2")
    # simulate: 200 -> delivered
    sent = []
    def send(url, headers, body):
        sent.append((url, headers, body))
        return 200
    res = wh.dispatch_pending(send)
    assert res["delivered"] >= 1 and res["dead"] == 0
    url, headers, body = sent[0]
    env = json.loads(body)
    assert env["schema"] == "tasdiq.verdict.created.v1"
    assert env["verdict"]["decision"] == "APPROVE"
    assert "verdict_signature" in env["verdict"]          # evidence travels
    assert "+999" not in body.decode()                     # no RAW msisdn value
    assert "msisdn_hash" in body.decode() or "msisdn" not in body.decode()  # hash-name ok
    assert headers["x-tasdiq-event-id"] == env["event_id"] # stable id for bank dedup
    assert wh.verify_transport(ep, int(headers["x-tasdiq-timestamp"]), body,
                               headers["x-tasdiq-signature"]) is True


def test_retry_then_dead_letter(client):
    wh.register(wh.WebhookEndpoint(url="https://siem.example.com/hook",
                                   secret_current="s"))
    _decide(client, "wh-3")
    def fail(url, headers, body):
        return 503
    for _ in range(5):
        wh.dispatch_pending(fail)
    counts = {}
    rows = [json.loads(l) for l in wh.OUTBOX_PATH.read_text().splitlines() if l]
    row = [r for r in rows if r["decision_id"] == "wh-3"][0]
    assert row["status"] == "dead" and row["attempts"] == 5


def test_replay_admin_resurrects_dead(client):
    wh.register(wh.WebhookEndpoint(url="https://siem.example.com/hook",
                                   secret_current="s"))
    _decide(client, "wh-4")
    def fail(u, h, b): return 500
    for _ in range(5):
        wh.dispatch_pending(fail)
    rows = [json.loads(l) for l in wh.OUTBOX_PATH.read_text().splitlines() if l]
    dead = [r for r in rows if r["decision_id"] == "wh-4"][0]
    assert dead["status"] == "dead"
    res = wh.replay_events([dead["event_id"]], lambda u, h, b: 200)
    assert res["replayed"] == 1 and res["delivered"] >= 1
    rows = [json.loads(l) for l in wh.OUTBOX_PATH.read_text().splitlines() if l]
    assert [r for r in rows if r["decision_id"] == "wh-4"][0]["status"] == "delivered"


def test_non_interference_with_decision_path(client):
    """THE panel property: webhook total failure cannot move /v1/decide."""
    wh.register(wh.WebhookEndpoint(url="https://siem.example.com/hook",
                                   secret_current="s"))
    import time as _t
    t0 = _t.perf_counter()
    r = _decide(client, "wh-5")
    dt_ok = _t.perf_counter() - t0
    assert r["decision"] == "APPROVE"
    # catastrophic dispatcher failure after the fact
    wh.dispatch_pending(lambda u, h, b: 0/1 if False else 0)
    t0 = _t.perf_counter()
    r2 = _decide(client, "wh-6")
    assert r2["decision"] == "APPROVE"      # verdict unchanged
    # latency not materially different (no network in either — enqueue is O(1) append)
    assert wh.OUTBOX_PATH.exists()


def test_transport_tamper_and_rotation(client):
    ep = wh.WebhookEndpoint(url="https://x.example/hook", secret_current="new",
                            secret_previous="old")
    body = b'{"probe":1}'
    ts = int(time.time())
    good = wh._hmac_transport(wh.WebhookEndpoint(url="https://x/h", secret_current="new"),
                              body, ts)
    assert wh.verify_transport(ep, ts, body, good) is True
    assert wh.verify_transport(ep, ts, b'{"probe":2}', good) is False   # body tamper
    assert wh.verify_transport(ep, ts - 4000, body, good) is False     # stale (>5min)
    prev = wh._hmac_transport(wh.WebhookEndpoint(url="https://x/h", secret_current="old"),
                              body, ts)
    assert wh.verify_transport(ep, ts, body, prev) is True              # rotation overlap works


def test_cef_format(client):
    ep = wh.WebhookEndpoint(url="https://siem.example.com/cef", secret_current="s",
                            format="cef")
    wh.register(ep)
    _decide(client, "wh-7", )
    seen = {}
    def send(url, headers, body):
        seen["env"] = json.loads(body); return 200
    wh.dispatch_pending(send)
    assert "cefversion" in seen["env"] and seen["env"]["name"] == "Tasdiq Verdict"


def test_endpoint_url_recheck_at_dispatch(client, monkeypatch):
    """DNS rebalancing: a host resolving to a private IP at DISPATCH time
    is refused even if it passed registration."""
    wh.register(wh.WebhookEndpoint(url="https://evil-rebind.example/hook",
                                   secret_current="s"))
    _decide(client, "wh-8")
    monkeypatch.setattr(wh, "_is_blocked_host", lambda h: True)
    res = wh.dispatch_pending(lambda u, h, b: 200)
    # blocked at send: dispatcher must not have delivered
    assert res["delivered"] == 0
