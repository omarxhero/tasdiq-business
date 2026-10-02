"""L2.5 confidence weighting + behavioral features + HARD RULES.

Weighted risk = Σ(risk_i × confidence_i) / Σ(confidence_i)
Hard rules (regulator-correct, always win over the weighted score):
  1. SIM swap < 1h AND amount > instant_multiplier × mean  -> DECLINE (early exit, L2 Phase 1)
  2. degraded signal + amount/velocity deviation           -> ESCALATE (never approve at 0.30)
  3. primary-signal (SIM Swap) loss + any anomaly           -> ESCALATE (timeout-approve path closed)
  4. coverage below bank minimum                            -> ESCALATE
  5. snatch-&-run pattern (telecom green + behavioral)      -> ESCALATE, biometric-only step-up
  6. AGED SIM swap corroboration (swap inside aged window, outside recent) + behavioral
     anomaly -> ESCALATE, biometric-preferred, SMS allowed (reduced-weight corroboration;
     can never DECLINE alone).
  7. PAYEE-VELOCITY TRAP — fresh payee + repeat attempts -> ESCALATE, biometric-only.
     Hard rule (threshold-independent): the Z3 prover caught bank-b-v1's escalate bar
     (62) sitting above the trap's 60 score — a signed policy could silently disable
     the trap. Now structurally guaranteed for every policy.
"""
from __future__ import annotations
from dataclasses import dataclass
from app.signals.nac import Signal


@dataclass
class Behavioral:
    beneficiary_first_seen_minutes: float
    attempts_last_hour: int
    amount_vs_mean: float          # amount / account_mean
    declared_multi_sim: bool
    # payee-velocity trap input: how many txns to THIS new payee recently
    # (bank-computed; engine stays stateless). >=2 springs the trap.
    new_payee_repeats: int = 1
    # coached-payment inputs (bank app reports live call state — platform
    # capability; telecom Scam Signal is the later upgrade path)
    call_in_progress: bool = False
    call_direction: str = "none"        # none | inbound | outbound
    call_duration_minutes: float = 0.0
    # call-forwarding state (CAMARA CFS semantics: forwarding redirects INCOMING
    # VOICE calls, not SMS). Enum — never a bool; conditional forwarding to
    # voicemail is normal life, only UNCONDITIONAL is threat-relevant.
    call_forwarding_state: str = "unknown"   # inactive|unconditional|conditional_busy|
                                             # conditional_unreachable|conditional_no_answer|
                                             # unknown|unavailable
    # UNKNOWN context flags: the bank did NOT send the field — unknown must
    # never read as clean (panel catch). Unknown forces screening (a signal
    # purchase), never silent approval without evidence.
    unknown_payee_age: bool = False
    unknown_attempts: bool = False
    unknown_ratio: bool = False

    @property
    def any_unknown(self) -> bool:
        return self.unknown_payee_age or self.unknown_attempts or self.unknown_ratio

    @property
    def coached(self) -> bool:
        return self.call_in_progress

    @property
    def anomaly(self) -> bool:
        return (self.beneficiary_first_seen_minutes <= 5
                or self.amount_vs_mean >= 20
                or self.attempts_last_hour >= 5)

    @property
    def radar_flagged(self) -> bool:
        """Any reason to spend money on telecom signals at all."""
        return (self.anomaly
                or self.declared_multi_sim
                or self.new_payee_repeats >= 2
                or self.call_in_progress
                or self.any_unknown)

    @property
    def severe(self) -> bool:
        """Flags that justify the full 4-signal sweep."""
        return (self.amount_vs_mean >= 20
                or self.attempts_last_hour >= 5
                or self.new_payee_repeats >= 2
                or self.call_in_progress)


def weighted_risk(signals: list[Signal]) -> float:
    num = sum(s.risk * s.confidence for s in signals)
    den = sum(s.confidence for s in signals)
    return round(num / den, 2) if den > 0 else 0.0


def coverage(signals: list[Signal]) -> float:
    """Effective coverage: signals still contributing (confidence > 0) count —
    a 0.30-confidence signal informs the decision; a 0.0 signal does not."""
    contributing = [s for s in signals if s.confidence > 0]
    return round(len(contributing) / len(signals), 2) if signals else 0.0


def behavioral_risk(b: Behavioral) -> float:
    risk = 0.0
    if b.beneficiary_first_seen_minutes <= 5:  risk += 30.0   # payee added moments ago
    if b.amount_vs_mean >= 20:                  risk += 25.0
    if b.attempts_last_hour >= 5:               risk += 15.0
    if b.new_payee_repeats >= 2:                risk += 30.0  # mule-distribution tell
    return risk


def jitter_thresholds(policy: dict, txn_id: str) -> tuple[dict, dict]:
    """Deterministic per-transaction threshold jitter (anti-probing).

    Same txn_id -> same offset (exact replay preserved via thresholds_used);
    different txn_id -> offset within ±jitter_pct, so an attacker binary-
    searching the exact cutoff hears noise, not the boundary.
    Returns (jittered policy copy, thresholds_used record).
    """
    import hashlib, hmac as _hmac
    from app.config import cfg
    pct = float(policy.get("threshold_jitter_pct", 0.0))   # default OFF (panel verdict)
    base_decline = float(policy.get("decline_gte", 80))
    base_escalate = float(policy.get("escalate_gte", 55))
    if pct <= 0 or not txn_id:
        pol = dict(policy)
        used = {"decline_gte": base_decline, "escalate_gte": base_escalate,
                "jitter_pct": 0.0}
        return pol, used
    # keyed with the deployment pepper: txn_id grinding cannot predict the offset
    seed = _hmac.new(cfg.VAULT_KEY.encode(), txn_id.encode(), hashlib.sha256).digest()
    u1 = int.from_bytes(seed[:8], "big") / 2**64     # [0,1)
    u2 = int.from_bytes(seed[8:16], "big") / 2**64
    off1 = (u1 * 2 - 1) * pct / 100.0
    off2 = (u2 * 2 - 1) * pct / 100.0
    pol = dict(policy)
    pol["decline_gte"] = round(base_decline * (1 + off1), 2)
    pol["escalate_gte"] = round(base_escalate * (1 + off2), 2)
    used = {"decline_gte": pol["decline_gte"], "escalate_gte": pol["escalate_gte"],
            "jitter_pct": pct}
    return pol, used


def _evaluate_inner(signals: list[Signal], b: Behavioral, policy: dict,
             aged: Signal | None = None) -> dict:
    """Returns {decision, band, weighted_risk, total_risk, reasons, step_up}.

    `aged`: SIM-swap result queried at the LONG window (aged_window_hours).
    Corroboration-only: +20 to total when swapped, plus hard rule 6 when the
    behavioral radar also flags. Never declines on its own.
    """
    wr_avg = weighted_risk(signals)
    # SEVERE-SIGNAL FLOOR: a green signal must never dilute a red one — the
    # weighted average alone lets three clean signals wash a 40-risk swap down
    # to 10. The floor keeps the strongest single contribution.
    wr = max(wr_avg, max((s.risk * s.confidence for s in signals), default=0.0))
    aged_swap = (aged is not None and isinstance(aged.value, dict)
                 and bool(aged.value.get("swapped")))
    total = min(100.0, wr + behavioral_risk(b) + (20.0 if aged_swap else 0.0))
    cov = coverage(signals)
    reasons = [s.as_dict() for s in signals]
    if aged is not None:
        reasons.append(aged.as_dict())

    sim = next((s for s in signals if s.name == "SIM_SWAP"), None)

    # Rule 0: live SIM swap is never a clean approve (band SIM_SWAP_RECENT)
    if telecom_swap_live := (sim is not None and isinstance(sim.value, dict)
                             and sim.value.get("swapped") and sim.confidence >= 0.9):
        if total >= policy.get("decline_gte", 80):
            # mirror the early-exit: SMS/voice prohibited, biometric recovery kept
            return _out("DECLINE", "SIM_SWAP_HIGH_RISK", wr, total, reasons,
                        ["WEBAUTHN", "IN_APP_BIOMETRIC"], ["SMS", "VOICE"])
        return _out("ESCALATE", "SIM_SWAP_RECENT", wr, total, reasons,
                    ["WEBAUTHN", "IN_APP_BIOMETRIC"], ["SMS", "VOICE"])
    # Rule 6: AGED swap corroboration — swap inside aged window, behavioral anomaly.
    # SMS allowed (unlike rule 0): the recent-swap attacker-owned-SIM window has
    # passed; biometric still preferred. Cannot decline on its own.
    if aged_swap and b.anomaly:
        return _out("ESCALATE", "SIM_SWAP_AGED_CORROBORATION", wr, total, reasons,
                    ["IN_APP_BIOMETRIC", "WEBAUTHN", "SMS"], [])
    # Rule 7: PAYEE-VELOCITY TRAP — fresh payee + repeat attempts = mule-distribution
    # tell. Fires regardless of bank thresholds (proof gate: with escalate_gte=62 the
    # 30+30=60 score never reached the bar — Z3 prover caught this on bank-b-v1).
    if b.beneficiary_first_seen_minutes <= 5 and b.new_payee_repeats >= 2:
        return _out("ESCALATE", "PAYEE_VELOCITY_TRAP", wr, total, reasons,
                    ["IN_APP_BIOMETRIC", "WEBAUTHN"], ["SMS"])
    # Rule 8: COACHED PAYMENT — a live call is active during the payment.
    # Nothing completes while the customer may be coached on the line: every
    # OTP/voice channel is prohibited, no step-up completes now; the payment
    # goes to a cooling-off hold with a callback to the bank-held number.
    # (Bank-app call-state input today; telecom Scam Signal = upgrade path.)
    if b.coached:
        fwd = b.call_forwarding_state == "unconditional"
        return _apply_forwarding(_out("ESCALATE", "COOLING_OFF_HOLD", wr, total, reasons,
                    [], ["SMS", "VOICE"],
                    hold={"release_after_minutes": policy.get("call_cooldown_minutes", 30),
                          "callback": "bank-held number",
                          "call_direction": b.call_direction,
                          "call_duration_minutes": b.call_duration_minutes,
                          "callback_allowed": not fwd,
                          **({"callback_block_reason": "unconditional_call_forwarding"} if fwd else {})}), b)
    # Rule 3 (checked before generic rule 2): primary signal lost + anomaly
    if sim is not None and sim.confidence == 0.0 and b.anomaly:
        return _out("ESCALATE", "PRIMARY_SIGNAL_LOSS", wr, total, reasons,
                    ["IN_APP_BIOMETRIC", "WEBAUTHN"], ["SMS", "VOICE"])
    # Rule 5 (before generic rule 2): snatch-&-run — telecom green + behavioral anomaly
    telecom_green = (sim is not None and isinstance(sim.value, dict)
                     and not sim.value.get("swapped"))
    if telecom_green and b.anomaly and b.amount_vs_mean >= 20:
        return _out("ESCALATE", "BEHAVIORAL_ANOMALY", wr, total, reasons,
                    ["IN_APP_BIOMETRIC"], ["SMS"])   # stolen unlocked device receives SMS too
    # Rule 2: degraded signal + anomaly -> escalate (never approve at 0.30)
    degraded = [s for s in signals if s.degradation and s.confidence < 1.0]
    if degraded and b.anomaly:
        return _out("ESCALATE", "DEGRADED_SIGNAL_ANOMALY", wr, total, reasons,
                    ["IN_APP_BIOMETRIC", "WEBAUTHN"], ["SMS", "VOICE"])
    # Rule 4: coverage
    if cov < policy.get("min_signal_coverage", 0.5):
        return _out("ESCALATE", "COVERAGE_LOW", wr, total, reasons,
                    ["IN_APP_BIOMETRIC", "WEBAUTHN"], [])
    # thresholds (jittered copy of policy passed by the engine; exact values
    # recorded per decision in thresholds_used for replay)
    if total >= policy.get("decline_gte", 80):
        return _out("DECLINE", "WEIGHTED_RISK_HIGH", wr, total, reasons, [], [])
    if total >= policy.get("escalate_gte", 55):
        return _out("ESCALATE", "WEIGHTED_RISK_BAND", wr, total, reasons,
                    ["SMS"], [])
    return _out("APPROVE", "CLEAN", wr, total, reasons, [], [])



def evaluate(signals: list[Signal], b: Behavioral, policy: dict,
             aged: Signal | None = None) -> dict:
    """Public evaluate: inner rules + R9 forwarding post-pass on every path."""
    return _apply_forwarding(_evaluate_inner(signals, b, policy, aged), b)


def _apply_forwarding(out: dict, b: Behavioral) -> dict:
    """R9 post-pass: UNCONDITIONAL call forwarding strips VOICE and CALLBACK
    channels from any verdict's allowed list (they reach the attacker's
    redirect). SMS is never touched by CFS alone — voice is the mechanism.
    Corroboration-only: does not change the decision itself."""
    if b.call_forwarding_state != "unconditional":
        return out
    step = out.get("step_up", {})
    allowed = [c for c in step.get("allowed", [])
               if c not in ("VOICE", "VOICE_OTP", "CALLBACK")]
    prohibited = list(step.get("prohibited", []))
    for c in ("VOICE", "CALLBACK"):
        if c not in prohibited:
            prohibited.append(c)
    out["step_up"] = {"allowed": allowed, "prohibited": prohibited}
    out["forwarding_note"] = ("unconditional call forwarding active — voice OTP and "
                              "callbacks prohibited (reach the redirect target)")
    if out.get("hold"):
        # R8 interaction: the cooling-off callback itself must not go to a
        # forwarded line — the callback gate consumes swap + forwarding state
        out["hold"]["callback_allowed"] = False
        out["hold"]["callback_block_reason"] = "unconditional_call_forwarding"
    return out


def _out(decision, band, wr, total, reasons, allowed, prohibited, hold=None):
    out = {"decision": decision, "band": band, "weighted_risk": wr,
           "total_risk": total, "reasons": reasons,
           "step_up": {"allowed": allowed, "prohibited": prohibited}}
    if hold is not None:
        out["hold"] = hold
    return out
