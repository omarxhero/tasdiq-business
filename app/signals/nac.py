"""Nokia Network-as-Code CAMARA client with per-operator circuit breakers.

Verified live contracts (evidence/live_calls/camara_first_live_evidence.json):
  SIM Swap     POST passthrough/camara/v1/sim-swap/sim-swap/v0/check {phoneNumber,maxAge} -> {swapped}
  Roaming      POST device-status/v0/roaming {device:{phoneNumber}} -> {roaming,countryCode,countryName}
  Connectivity POST device-status/v0/connectivity {device:{phoneNumber}} -> {connectivityStatus}
Number Verification needs a 3-legged OAuth device consent flow -> degraded mode
in the headless prototype (confidence 0.30, honestly labeled AUTH_PENDING).
"""
from __future__ import annotations
import json, time, threading, urllib.request, urllib.error
from dataclasses import dataclass, field
from typing import Optional
from app.config import cfg, operator_for


@dataclass
class Signal:
    name: str
    value: object
    confidence: float
    risk: float
    fetched_at: str = ""
    source: str = "nokia_nac"
    operator: str = ""
    degradation: Optional[str] = None   # e.g. WIFI_RESTRICTED / AUTH_PENDING / BREAKER_OPEN
    latency_ms: int = 0

    def as_dict(self):
        return self.__dict__.copy()


class _Breaker:
    """Per-operator circuit breaker (bulkhead isolation)."""
    def __init__(self, fail_threshold=5, open_seconds=30):
        self.fail_threshold, self.open_seconds = fail_threshold, open_seconds
        self._state: dict[str, dict] = {}
        self._lock = threading.Lock()

    def is_open(self, operator: str) -> bool:
        with self._lock:
            st = self._state.get(operator)
            return bool(st and st["open_until"] > time.time())

    def record(self, operator: str, ok: bool):
        with self._lock:
            st = self._state.setdefault(operator, {"fails": 0, "open_until": 0})
            if ok:
                st["fails"], st["open_until"] = 0, 0
            else:
                st["fails"] += 1
                if st["fails"] >= self.fail_threshold:
                    st["open_until"] = time.time() + self.open_seconds


class NacClient:
    def __init__(self, recordings_path=None):
        self.breaker = _Breaker()
        self._nv_client = None       # lazy Number-Verification OAuth client
        self.recordings = {}
        if recordings_path:
            from pathlib import Path
            p = Path(recordings_path)
            if p.exists():
                self.recordings = json.loads(p.read_text())

    def _post(self, path: str, body: dict, timeout: float):
        req = urllib.request.Request(
            cfg.NAC_BASE_URL + "/" + path, data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     "x-rapidapi-host": cfg.NAC_RAPIDAPI_HOST,
                     "x-rapidapi-key": cfg.NAC_API_KEY})
        t0 = time.perf_counter()
        try:
            raw = urllib.request.urlopen(req, timeout=timeout).read()
            return json.loads(raw), int((time.perf_counter() - t0) * 1000), None
        except urllib.error.HTTPError as e:
            return None, int((time.perf_counter() - t0) * 1000), f"HTTP{e.code}"
        except Exception as e:
            return None, int((time.perf_counter() - t0) * 1000), repr(e)[:60]

    def _guard(self, signal_name: str, msisdn: str, deadline_remaining: float,
               fetch) -> Signal:
        """Fetch with per-operator breaker + deadline; degrade, never fail the rail."""
        operator = operator_for(msisdn)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if self.breaker.is_open(operator):
            rec = (self.recordings.get(msisdn) or {}).get(self._recording_key(signal_name))
            if isinstance(rec, dict) and "_err" not in rec:
                val = {k: v for k, v in rec.items() if not k.startswith("_")}
                return Signal(signal_name, val, 0.9, 0.0, now, operator=operator,
                              degradation="BREAKER_OPEN_CACHED")
            return Signal(signal_name, None, 0.0, 0.0, now, operator=operator,
                          degradation="BREAKER_OPEN")
        timeout = max(0.05, min(deadline_remaining - 0.15, 2.0))  # reserve 150ms
        if timeout <= 0.05:
            return Signal(signal_name, None, 0.0, 0.0, now, operator=operator,
                          degradation="BUDGET_MISS")
        data, ms, err = fetch(timeout)
        self.breaker.record(operator, err is None)
        if err:
            rec = (self.recordings.get(msisdn) or {}).get(self._recording_key(signal_name))
            if isinstance(rec, dict) and "_err" not in rec:
                # labeled fallback (official guide tip: cache demo data)
                val = {k: v for k, v in rec.items() if not k.startswith("_")}
                return Signal(signal_name, val, 0.9, 0.0, now, operator=operator,
                              degradation="CACHED_FALLBACK", latency_ms=ms)
            return Signal(signal_name, None, 0.0, 0.0, now, operator=operator,
                          degradation=f"UNAVAILABLE({err})", latency_ms=ms)
        # opportunistically refresh the recording
        if msisdn in self.recordings:
            self.recordings[msisdn][self._recording_key(signal_name)] = data
        return Signal(signal_name, data, 1.0, 0.0, now, operator=operator, latency_ms=ms)

    @staticmethod
    def _recording_key(signal_name: str) -> str:
        return {"SIM_SWAP": "sim_swap", "DEVICE_STATUS": "roaming",
                "DEVICE_SWAP": "device_swap"}.get(signal_name, "connectivity")

    # --- the three CAMARA calls -------------------------------------------
    def sim_swap(self, msisdn: str, max_age_hours: int, deadline_remaining: float) -> Signal:
        sig = self._guard("SIM_SWAP", msisdn, deadline_remaining,
                          lambda t: self._post("passthrough/camara/v1/sim-swap/sim-swap/v0/check",
                                               {"phoneNumber": msisdn, "maxAge": max_age_hours}, t))
        if sig.value is not None:
            sig.risk = 40.0 if sig.value.get("swapped") else 0.0
        return sig

    def roaming(self, msisdn: str, deadline_remaining: float) -> Signal:
        sig = self._guard("DEVICE_STATUS", msisdn, deadline_remaining,
                          lambda t: self._post("device-status/v0/roaming",
                                               {"device": {"phoneNumber": msisdn}}, t))
        if sig.value is not None:
            # roaming alone is not fraud (expat reality) — small contribution
            sig.risk = 8.0 if sig.value.get("roaming") else 0.0
        return sig

    def device_swap(self, msisdn: str, deadline_remaining: float) -> Signal:
        """CAMARA Device Swap: did the number move to a DIFFERENT device (IMEI-level)?
        Complements SIM Swap — catches number re-registration without a SIM change."""
        sig = self._guard("DEVICE_SWAP", msisdn, deadline_remaining,
                          lambda t: self._post("passthrough/camara/v1/device-swap/device-swap/v1/check",
                                               {"phoneNumber": msisdn}, t))
        if sig.value is not None:
            sig.risk = 20.0 if sig.value.get("swapped") else 0.0
        return sig

    def number_recycling(self, msisdn: str, before: str = "2026-06-16T00:00:00Z") -> Signal:
        """CAMARA Number Recycling (bonus tool-belt signal): was this number
        recycled to a new owner after `before`? Recycled number + bank account
        still bound to the previous owner = account-takeover vector."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        data, ms, err = self._post(
            "passthrough/camara/v1/number-recycling/number-recycling/v0.2/check",
            {"phoneNumber": msisdn, "specifiedDate": before}, 3.0)
        if err:
            return Signal("NUMBER_RECYCLING", None, 0.0, 0.0, now, degradation=f"UNAVAILABLE({err})", latency_ms=ms)
        return Signal("NUMBER_RECYCLING", data, 1.0, 20.0 if data.get("phoneNumberRecycled") else 0.0, now, latency_ms=ms)

    def number_verify(self, msisdn: str, declared_multi_sim: bool, deadline_remaining: float) -> Signal:
        """3-legged OAuth consent flow: the device-side authorization-code step
        is device-bound (HANDOFF §7.5). NUMVERIFY_MODE:
          degraded (default) — labeled degraded signal, confidence 0.30
          oauth              — full client (app/signals/nv_oauth.py) attempts the
                               live verify; any failure degrades with the real
                               error label — a verification is NEVER fabricated
        """
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if cfg.NUMVERIFY_MODE == "oauth":
            if self._nv_client is None:          # build once, keep the token cache
                from app.signals.nv_oauth import client_from_env
                self._nv_client = client_from_env()
            cli = self._nv_client
            if cli is None:
                return Signal("NUMBER_VERIFY", None, 0.0, 0.0, now,
                              operator=operator_for(msisdn),
                              degradation="UNAVAILABLE(oauth not configured)")
            res = cli.verify(msisdn)
            if res["ok"]:
                return Signal("NUMBER_VERIFY", "MATCH" if res["match"] else "MISMATCH",
                              1.0, 0.0 if res["match"] else 25.0, now,
                              operator=operator_for(msisdn))
            return Signal("NUMBER_VERIFY", "MATCH_ASSUMED", 0.30, 0.0, now,
                          operator=operator_for(msisdn),
                          degradation=f"DEGRADED({res['error']})")
        # client-attested multi-SIM only reduces false positives; never adds security
        conf = 0.30
        degr = "DUAL_SIM_DECLARED" if declared_multi_sim else "AUTH_PENDING"
        return Signal("NUMBER_VERIFY", "MATCH_ASSUMED", conf, 0.0, now,
                      operator=operator_for(msisdn), degradation=degr)
