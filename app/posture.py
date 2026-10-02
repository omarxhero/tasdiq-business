"""Posture cache — the panel-corrected event-driven evidence layer.

Design rules (05_ADOPT_LIST_v2 #1, hardened by review consensus):
  SILENCE IS NOT CLEAN. Three semantic states, never two:
    SWAPPED          trusted swap event — retained for the LONGEST policy
                     window (240h default), not the clean TTL
    OBSERVED_STABLE  ONLY from a live negative / trusted initial snapshot,
                     while subscription health is continuous; short TTL
    UNKNOWN          no event, lapsed subscription, never seen — behaves
                     exactly like today's no-signal path (screened, never
                     clean)
  HMAC-KEYED LOOKUP: plain sha256(msisdn) is enumerable (~10^9 KSA space
  brute-forces in minutes — the jitter bug class). Store keys are
  HMAC(VAULT_KEY, msisdn), encrypted values.
  SUBSTITUTION GATE: cache substitutes for a live query ONLY below an
  amount ceiling, for aged payees, with no sensitive event — belt-and-
  braces for event loss. Everything else queries live.
  CANARY AUDIT: 1-3% of OBSERVED_STABLE-served decisions are shadowed
  with a live query; the contradiction rate is a measured soundness KPI,
  and a breach trips the breaker to live-only.
  INGRESS: CloudEvents-shaped, provider-auth adapter (HMAC now, bearer/
  mTLS later), event-id dedupe, ordering by network event time, per-number
  rate limit (a forged event can only ADD swaps — DoS against victims).
  Every posture mutation is ledger-written (provable "why we believed
  no swap at 14:03").
"""
from __future__ import annotations
import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Literal

from app.config import cfg

STORE_PATH = Path(__file__).resolve().parent.parent / "ledger_store" / "posture_store.json"

SwapState = Literal["SWAPPED", "OBSERVED_STABLE", "UNKNOWN"]


def _key(msisdn: str) -> str:
    return "pm_" + hmac.new(cfg.VAULT_KEY.encode(), msisdn.encode(),
                            hashlib.sha256).hexdigest()[:24]


class PostureStore:
    """In-process store (production: encrypted KV / Redis; the STATE MACHINE
    and gates are the product — persistence is a deployment detail)."""

    def __init__(self, path: Path = STORE_PATH):
        self.path = path
        self._data: dict[str, dict] = {}
        self._seen_event_ids: set[str] = set()
        self._load()
        self.contradictions = 0        # canary KPI
        self.canary_checks = 0
        self.breaker_live_only = False

    # ---------------- persistence ----------------
    def _load(self):
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data), encoding="utf-8")

    # ---------------- ingress ----------------
    def apply_event(self, event: dict, provider_ok: bool) -> dict:
        """Authenticated CAMARA-style event -> posture mutation. Returns the
        applied mutation record (ledger-written by the caller)."""
        if not provider_ok:
            return {"applied": False, "reason": "AUTH"}
        eid = event.get("event_id")
        if not eid:
            return {"applied": False, "reason": "NO_EVENT_ID"}
        if eid in self._seen_event_ids:
            return {"applied": False, "reason": "DUPLICATE"}
        self._seen_event_ids.add(eid)
        msisdn = event.get("msisdn")
        if not msisdn:
            return {"applied": False, "reason": "NO_MSISDN"}
        t = event.get("network_event_time") or int(time.time())
        rec = self._data.setdefault(_key(msisdn), {})
        # ordering: only newer network events move the state
        if rec.get("last_event_ts") and t <= rec["last_event_ts"]:
            return {"applied": False, "reason": "STALE_ORDER"}
        if event.get("type") == "sim_swap":
            rec.update({"state": "SWAPPED", "last_event_ts": t,
                        "source": event.get("source", "subscription"),
                        "subscription_active": True})
            self._save()
            return {"applied": True, "state": "SWAPPED", "msisdn_key": _key(msisdn), "ts": t}
        if event.get("type") == "stable_snapshot":
            # trusted live negative or initial snapshot -> OBSERVED_STABLE
            rec.update({"state": "OBSERVED_STABLE", "stable_since": t,
                        "last_event_ts": t, "source": event.get("source", "live_query"),
                        "subscription_active": event.get("subscription_active", True)})
            self._save()
            return {"applied": True, "state": "OBSERVED_STABLE",
                    "msisdn_key": _key(msisdn), "ts": t}
        return {"applied": False, "reason": "UNKNOWN_TYPE"}

    def mark_subscription_ended(self, msisdn: str):
        """ASYMMETRIC BY DESIGN: STABLE reverts to UNKNOWN (a lost subscription
        voids continuous-coverage claims — silence is never clean), but a
        SWAPPED event SURVIVES until retention expiry (a historical swap is a
        positive fact; dropping it would be fail-open). Fail-strict in both
        directions."""
        rec = self._data.get(_key(msisdn))
        if rec:
            rec["subscription_active"] = False
            self._save()

    # ---------------- read path ----------------
    def effective_state(self, msisdn: str, stable_ttl_s: int = 7200,
                        swapped_retention_s: int = 240 * 3600) -> dict:
        """The three-state machine. UNKNOWN is the default and NEVER clean."""
        rec = self._data.get(_key(msisdn))
        now = time.time()
        if not rec:
            return {"state": "UNKNOWN", "reason": "never_seen"}
        if rec.get("state") == "SWAPPED":
            age = now - rec.get("last_event_ts", 0)
            if age <= swapped_retention_s:
                return {"state": "SWAPPED", "since": rec["last_event_ts"],
                        "age_hours": round(age / 3600, 1)}
            # swap aged past retention: not STABLE — UNKNOWN until a new
            # stable snapshot arrives (silence is never clean)
            return {"state": "UNKNOWN", "reason": "swap_aged_past_retention"}
        if rec.get("state") == "OBSERVED_STABLE":
            if not rec.get("subscription_active", False):
                return {"state": "UNKNOWN", "reason": "subscription_ended"}
            age = now - rec.get("stable_since", 0)
            if age <= stable_ttl_s:
                return {"state": "OBSERVED_STABLE", "as_of": rec["stable_since"]}
            return {"state": "UNKNOWN", "reason": "ttl_expired"}
        return {"state": "UNKNOWN", "reason": "corrupt_record"}

    # ---------------- substitution + canary ----------------
    def may_substitute(self, msisdn: str, amount_vs_mean: float,
                       payee_age_min: float, sensitive_event: bool,
                       amount_ceiling: float = 10.0) -> tuple[bool, dict]:
        """Cache may replace a live query ONLY: STABLE + low amount + aged
        payee + no sensitive event + breaker closed."""
        st = self.effective_state(msisdn)
        gate = {
            "state": st["state"],
            "amount_ok": amount_vs_mean < amount_ceiling,
            "payee_ok": payee_age_min > 60,
            "no_event": not sensitive_event,
            "breaker_ok": not self.breaker_live_only,
        }
        ok = (st["state"] == "OBSERVED_STABLE" and gate["amount_ok"]
              and gate["payee_ok"] and gate["no_event"] and gate["breaker_ok"])
        return ok, gate

    def canary(self, msisdn: str, live_swapped: bool | None):
        """Shadow-check a STABLE-served decision against a live query result.
        None = live unavailable (no signal either way)."""
        if live_swapped is None:
            return None
        self.canary_checks += 1
        st = self.effective_state(msisdn)
        if st["state"] == "OBSERVED_STABLE" and live_swapped:
            self.contradictions += 1
            # soundness breach: the cache said stable, the network says swapped
            if self.canary_checks and (self.contradictions / self.canary_checks) > 0.02:
                self.breaker_live_only = True
        return {"checks": self.canary_checks, "contradictions": self.contradictions,
                "breaker": self.breaker_live_only}

    def reset(self):
        self._data.clear()
        self._seen_event_ids.clear()
        self.contradictions = 0
        self.canary_checks = 0
        self.breaker_live_only = False
        self.path.unlink(missing_ok=True)


POSTURE = PostureStore()
