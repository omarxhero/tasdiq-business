"""L2 progressive decision engine — deadline-driven, early-exit, cost-tiered.

Behavioral radar runs FIRST and free on every payment. Signal purchases are
gated by the radar (cost curve convex in risk):
  Tier 0 (radar quiet, progressive_tiers on): NO telecom signal bought.
        Verdict APPROVE-CLEAN, decision_basis BEHAVIORAL_ONLY, cost $0.
  Tier 1 (mild flag — fresh payee / declared multi-SIM): SIM Swap only
        (+ free local Number Verification).
  Tier 2 (severe flag — amount spike / velocity / payee-velocity trap, or
        policy tier_mode=full): full sweep — SIM Swap + Device Status +
        Device Swap in parallel, plus the AGED-window SIM query when the
        recent window is clean (aged-swap corroboration, rule 6).
Phase-1 early DECLINE (fresh swap × amount multiplier) preserved on every
tier that buys SIM Swap.
Threshold jitter: per-txn deterministic (sha256(txn_id)-seeded), exact
values recorded in thresholds_used for exact replay.
Dual latency reporting: end_to_end_ms (incl. sandbox RTT) and internal_ms
(external network excluded). Sandbox overhead shown, never hidden.
"""
from __future__ import annotations
import time
from app.config import cfg
from app.signals.nac import NacClient, Signal
from app.engine.weighting import Behavioral, evaluate, jitter_thresholds
from app.policy import verify_bundle

# events that force the FULL sweep (takeover-shaped), vs SIM-only screening
_EVENT_FULL = {"credential_reset", "device_registration", "login_anomaly"}


def _sampled(txn_id: str, rate: float) -> bool:
    """Keyed deterministic Tier-0 sampling: same txn_id + deployment pepper ->
    same answer (idempotent replays and Replay Lab agree); an attacker cannot
    grind txn_ids to escape sampling without knowing the pepper."""
    import hashlib
    from app.config import cfg
    if rate <= 0 or not txn_id:
        return False
    h = hashlib.sha256((cfg.VAULT_KEY + ":" + txn_id).encode()).digest()
    return int.from_bytes(h[:8], "big") / 2**64 < rate


# per-signal ceiling prices (USD) for cost_estimate_usd; policy can override
DEFAULT_SIGNAL_COST = {"SIM_SWAP": 0.07, "DEVICE_STATUS": 0.07,
                       "DEVICE_SWAP": 0.07, "SIM_SWAP_AGED": 0.07}


class DecisionEngine:
    def __init__(self, nac: NacClient):
        self.nac = nac

    def decide(self, req: dict, bundle: dict) -> dict:
        t0 = time.perf_counter()
        deadline = cfg.DECISION_BUDGET_MS / 1000.0

        policy = verify_bundle(bundle)["rules"]   # tampered config -> exception -> REJECT
        mult = policy.get("instant_multiplier", 50)
        # pydantic guarantees amount/account_mean > 0 and finite on the API path;
        # direct callers (tests, demo scripts) get the same guard here.
        import math
        for k in ("amount",):
            v = req.get(k, 0)
            if not (isinstance(v, (int, float)) and math.isfinite(v) and v > 0):
                raise ValueError(f"{k} must be a positive finite number")
        # account_mean may be legitimately absent = UNKNOWN ratio (screened, not spiked)
        mean = req.get("account_mean")
        ratio_known = isinstance(mean, (int, float)) and mean > 0
        amount_vs_mean = (req["amount"] / mean) if ratio_known else 1.0

        # deterministic per-transaction threshold jitter; exact values recorded
        pol, thresholds_used = jitter_thresholds(policy, req.get("txn_id", ""))

        raw_payee = req.get("beneficiary_first_seen_minutes", -1)   # -1 = NOT SENT
        raw_att = req.get("attempts_last_hour", -1)                 # -1 = NOT SENT
        b = Behavioral(
            beneficiary_first_seen_minutes=raw_payee if raw_payee is not None and raw_payee >= 0 else 9999,
            attempts_last_hour=max(raw_att, 0),
            amount_vs_mean=amount_vs_mean,
            declared_multi_sim=req.get("declared_multi_sim", False),
            new_payee_repeats=req.get("new_payee_repeats", 1),
            call_in_progress=req.get("call_in_progress", False),
            call_direction=req.get("call_direction", "none"),
            call_duration_minutes=req.get("call_duration_minutes", 0.0),
            call_forwarding_state=req.get("call_forwarding_state") or "unknown",
            unknown_payee_age=raw_payee is None or raw_payee < 0,
            unknown_attempts=raw_att is None or raw_att < 0,
            unknown_ratio=not ratio_known,
        )
        costs = dict(DEFAULT_SIGNAL_COST)
        costs.update(policy.get("signal_cost_usd", {}))

        # ---- Tier 0: radar quiet AND no sensitive event AND not sampled -----
        progressive = bool(policy.get("progressive_tiers", True))
        # posture lookup hoisted: push evidence (SWAPPED) outranks radar quiet
        from app.posture import POSTURE as _posture
        posture_state = _posture.effective_state(req["msisdn"])
        ev = req.get("recent_sensitive_event") or "none"   # None-safe for direct dict callers
        ev_age = req.get("sensitive_event_minutes_ago")
        event_recent = (ev != "none"
                        and (ev_age is None
                             or ev_age <= policy.get("event_window_minutes", 60)))
        event_full = event_recent and ev in _EVENT_FULL
        rate = float(policy.get("tier0_sample_rate", 0.02))
        sampled = _sampled(req.get("txn_id", ""), rate)
        unk_fields = ([f for f, u in (("payee_age", b.unknown_payee_age),
                                       ("attempts", b.unknown_attempts),
                                       ("account_mean", b.unknown_ratio)) if u])
        trigger = ("event:" + ev if event_recent
                   else "unknown:" + "+".join(unk_fields) if unk_fields
                   else "sample" if sampled
                   else "severe" if b.severe
                   else "radar" if b.radar_flagged else "none")
        posture_swapped = posture_state["state"] == "SWAPPED"
        if progressive and not b.radar_flagged and not event_recent and not sampled                 and not posture_swapped:
            out = self._finish(req, t0, "APPROVE", "CLEAN", [], 0.0, pol, bundle,
                                [], [], total_risk=behavioral_risk_of(b),
                                tier=0, signals_bought=[], costs=costs, trigger="none",
                                unknown_fields=unk_fields if unk_fields else None,
                                basis="BEHAVIORAL_ONLY", thresholds_used=thresholds_used)
            from app.engine.weighting import _apply_forwarding as _fwd
            return self._govern(req, _fwd(out, b), b, pol)

        bought: list[str] = []

        # ---- Phase 1: SIM Swap — posture cache FIRST, live query only when
        # the cache cannot substitute (three-state machine; silence never clean)
        posture_used = False
        _subst_ok, _subst_gate = _posture.may_substitute(
            req["msisdn"], amount_vs_mean, req.get("beneficiary_first_seen_minutes", 9999),
            bool(event_recent))
        if posture_state["state"] == "SWAPPED":
            # trusted push event — the swap fact arrives without a query
            sim = Signal("SIM_SWAP", {"swapped": True}, 1.0, 40.0)
            posture_used = True
        elif _subst_ok:
            sim = Signal("SIM_SWAP", {"swapped": False}, 1.0, 0.0,
                         degradation=None)
            sim.__dict__["source"] = "posture_cache"
            posture_used = True
        else:
            sim = self.nac.sim_swap(req["msisdn"], policy.get("swap_window_hours", 24),
                                    deadline_remaining=deadline - (time.perf_counter() - t0))
        bought.append("SIM_SWAP")
        swapped_recent = bool(sim.value and sim.value.get("swapped"))
        if swapped_recent and amount_vs_mean > mult:
            return self._govern(req, self._finish(req, t0, "DECLINE", "SIM_SWAP_INSTANT_PATTERN",
                                [sim.as_dict()], 0.0, pol, bundle,
                                ["WEBAUTHN", "IN_APP_BIOMETRIC"], ["SMS", "VOICE"],
                                tier=1 if not b.severe else 2, signals_bought=bought,
                                costs=costs, basis="TELECOM_FUSED", trigger=trigger,
                                unknown_fields=unk_fields if unk_fields else None,
                                thresholds_used=thresholds_used,
                                forwarding_note=("unconditional call forwarding active — voice OTP and "
                                                 "callbacks prohibited (reach the redirect target)")
                                if b.call_forwarding_state == "unconditional" else None), b, pol)

        # ---- Tier 1 (mild flag): SIM Swap + free local NV ------------------
        full_sweep = (not progressive) or b.severe or event_full or policy.get("tier_mode") == "full"
        remaining = deadline - (time.perf_counter() - t0)
        nv = self.nac.number_verify(req["msisdn"], req.get("declared_multi_sim", False), remaining)
        if not full_sweep:
            result = evaluate([sim, nv], b, pol)
            return self._govern(req, self._finish(req, t0, result["decision"], result["band"], result["reasons"],
                                result["weighted_risk"], pol, bundle,
                                result["step_up"]["allowed"], result["step_up"]["prohibited"],
                                total_risk=result["total_risk"], tier=1,
                                signals_bought=bought, costs=costs,
                                basis="TELECOM_FUSED", thresholds_used=thresholds_used,
                                hold=result.get("hold"), trigger=trigger,
                                unknown_fields=unk_fields if unk_fields else None,
                                forwarding_note=result.get("forwarding_note")), b, pol)

        # ---- Phase 2 (tier 2): parallel + behavioral + aged window ---------
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_roam = pool.submit(self.nac.roaming, req["msisdn"], remaining)
            f_dswap = pool.submit(self.nac.device_swap, req["msisdn"], remaining)
            roam = f_roam.result()
            dswap = f_dswap.result()
        bought += ["DEVICE_STATUS", "DEVICE_SWAP"]
        aged = None
        aged_window = int(policy.get("aged_window_hours", 240))
        if aged_window > 0 and not swapped_recent:
            # aged-swap corroboration: long-window SIM query only when the
            # recent window is clean (no extra cost on live-swap traffic)
            aged = self.nac.sim_swap(req["msisdn"], aged_window, remaining)
            aged.name = "SIM_SWAP_AGED"
            if aged.value is not None:
                aged.risk = 20.0 if aged.value.get("swapped") else 0.0
            bought.append("SIM_SWAP_AGED")
        result = evaluate([sim, nv, roam, dswap], b, pol, aged=aged)
        return self._govern(req, self._finish(req, t0, result["decision"], result["band"], result["reasons"],
                            result["weighted_risk"], pol, bundle,
                            result["step_up"]["allowed"], result["step_up"]["prohibited"],
                            total_risk=result["total_risk"], tier=2,
                            signals_bought=bought, costs=costs,
                            basis="TELECOM_FUSED", thresholds_used=thresholds_used,
                            hold=result.get("hold"), trigger=trigger,
                            unknown_fields=unk_fields if unk_fields else None,
                            forwarding_note=result.get("forwarding_note")), b, pol)

    def _finish(self, req, t0, decision, band, reasons, wr, policy, bundle,
                allowed, prohibited, total_risk=None, tier=None, signals_bought=None,
                costs=None, basis="TELECOM_FUSED", thresholds_used=None, hold=None,
                trigger=None, unknown_fields=None, forwarding_note=None):
        from app.policy import verify_bundle
        from app.engine.weighting import behavioral_risk as _br
        end_to_end = int((time.perf_counter() - t0) * 1000)
        # parallel fan-out: wall-clock external time = slowest single call, not the sum
        external = max((r.get("latency_ms", 0) for r in reasons), default=0)
        cost = round(sum(costs.get(n, 0.0) for n in (signals_bought or [])), 4)
        return {
            "txn_id": req.get("txn_id"), "decision": decision, "band": band,
            "weighted_risk": wr, "total_risk": total_risk if total_risk is not None else wr,
            "reasons": reasons,
            "step_up": {"allowed": allowed, "prohibited": prohibited},
            "cost": {"tier": tier, "signals_bought": signals_bought or [],
                     "cost_estimate_usd": cost, "decision_basis": basis,
                     "trigger": trigger or ("severe" if tier == 2 else
                                            "radar" if tier == 1 else "none")},
            "thresholds_used": thresholds_used,
            **({"hold": hold} if hold is not None else {}),
            **({"data_quality": {"unknown_fields": unknown_fields}} if unknown_fields else {}),
            **({"forwarding_note": forwarding_note} if forwarding_note else {}),
            "policy_id": bundle.get("policy_id"),
            "policy_version_hash": verify_bundle(bundle)["policy_version_hash"],
            "latency": {"end_to_end_ms": end_to_end,
                        "internal_ms": max(0, end_to_end - external),
                        "external_network_ms": external,
                        "budget_ms": cfg.DECISION_BUDGET_MS},
        }



    def _govern(self, req, out, behavioral, pol):
        """Sidecar post-processing — only when mode == 'sidecar'."""
        if req.get("mode") != "sidecar":
            return out
        from app.governor import apply_governor
        return apply_governor(out, req, pol, behavioral, evaluate)

def behavioral_risk_of(b: Behavioral) -> float:
    from app.engine.weighting import behavioral_risk
    return behavioral_risk(b)
