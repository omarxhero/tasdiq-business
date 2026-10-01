# Tasdiq — Architecture (deep dive)

Three views: the layers, the decision pipeline (time), and ChannelLock
enforcement (trust). Companion to the [README](../README.md); honest limits
in [PRODUCTION_DELTA](PRODUCTION_DELTA.md).

## 1 · The six layers

```mermaid
flowchart TD
    REQ["Bank request → /v1/decide<br/>msisdn · amount · account mean · payee age · velocity<br/>events · call state · incumbent score (sidecar)"]

    subgraph INLINE["INLINE RAIL — 450 ms budget — decides"]
        direction TB
        L1["L1 · Signal Collection<br/>CAMARA via Nokia NaC · behavior-gated purchasing<br/>per-operator circuit breakers · labeled cached fallback<br/>UNAVAILABLE never fabricates green"]
        P1{"L2 · Phase 1 (0–200 ms)<br/>SIM Swap alone"}
        EARLY["DECLINE — early exit<br/>answered swap × amount > multiplier<br/>SMS/VOICE prohibited · biometric recovery kept"]
        P2["L2 · Phase 2 (200–400 ms)<br/>Device Status ∥ Device Swap in parallel<br/>+ aged-window SIM query when recent is clean<br/>+ behavioral radar (free, every payment)"]
        L25["L2.5 · Confidence weighting<br/>weighted = Σ(risk×conf) ÷ Σ(conf)<br/>FLOORED at the strongest single contribution<br/>total = min(100, floored + behavioral)"]
        RULES["Hard rules R0–R8 (order below)<br/>band isolation: after any swap signal<br/>SMS and voice are PROHIBITED in the verdict"]
        L3["L3 · Signed policy<br/>Ed25519 maker-checker · tampered = rejected<br/>Z3-verified: I1–I6 must PROVE before signing<br/>thresholds recorded per decision (exact replay)"]
        DEC{"Verdict +<br/>ChannelLock grant +<br/>verdict signature"}
        L0["L0 · Silent authentication<br/>clean ⇒ no OTP at all<br/>(the OTP-cost wedge)"]
    end

    subgraph ASYNC["ASYNC LANE — seconds later — documents"]
        direction TB
        L4["L4 · AI compliance agent<br/>bilingual explanations · regulator-report drafts (DRAFT, human signs)<br/>sealed tool belt: opaque IDs only<br/>proportionality: skips only when mathematically redundant"]
        L5["L5 · Dual audit ledgers<br/>intercept (inline) + agent (async) · hash-chained<br/>verifier RECOMPUTES content · RFC 3161 anchoring<br/>HMAC-pseudonymized MSISDNs"]
    end

    RESP["Answer to the bank ≤ 450 ms<br/>+ grant + signature + cost provenance"]

    REQ --> L1 --> P1
    P1 -- "swap × spike" --> EARLY
    P1 -- "else" --> P2 --> L25 --> RULES --> L3 --> DEC
    DEC -- "clean" --> L0 --> RESP
    DEC --> RESP
    EARLY --> L5
    RESP -. "txn_id links everything" .-> L4 --> L5
    L5 -. "NO WRITE PATH to the rail — ever.<br/>Policy changes only via human governance" .-> L3
```

**How to read it:** the top block races the 450 ms clock (evidence → timing
→ weighting → judgment → answer). L0 is the reward for a clean pass: no OTP
at all. The bottom block runs after the bank already has its answer. The
red dashed path is the constitutional rule: **the agent can never write
back into the payment rail.**

## 2 · Decision pipeline

```mermaid
flowchart LR
    subgraph CLOCK["the 450 ms clock"]
        direction LR
        A["Phase 1<br/>0–200 ms<br/>SIM Swap only"] --> G{"answered swap<br/>AND amount > multiplier?"}
        G -- "yes" --> D1["DECLINE<br/>early exit<br/>~1 signal bought"]
        G -- "no" --> B["Phase 2<br/>200–400 ms<br/>parallel fan-out<br/>+ aged window if clean"]
        B --> C["weight + floor<br/>hard rules R0–R8<br/>jittered-or-raw thresholds<br/>50 ms margin"]
    end
    D1 --> V["verdict + grant + signature"]
    C --> V
```

**One transaction's life** (the 52,000 attack):

```mermaid
sequenceDiagram
    participant B as Bank
    participant E as Tasdiq engine
    participant N as Nokia NaC (CAMARA)
    participant L as Intercept ledger
    participant G as Bank OTP gateway
    B->>E: POST /v1/decide — 52,000 (52× mean), swapped MSISDN
    E->>N: Phase 1 · SIM Swap check
    N-->>E: swapped = true (confidence 1.0)
    E->>E: 52× > 40× multiplier → EARLY EXIT
    E-->>B: DECLINE · band SIM_SWAP_INSTANT_PATTERN<br/>step_up: allowed [WEBAUTHN, IN_APP_BIOMETRIC]<br/>prohibited [SMS, VOICE] · verdict signature
    E->>L: append (hash-chained, signature persisted)
    B->>G: dispatch attempt: SMS
    G->>G: verify ChannelLock grant locally (~1 ms)
    G-->>B: REFUSED — CHANNEL_PROHIBITED<br/>(no SMS was ever sendable)
    Note over G: Tasdiq could be offline —<br/>the grant verifies locally; SMS stays refused
```

## 3 · Hard rules — evaluation order (first match wins)

```mermaid
flowchart TD
    S["signal set from L2.5"] --> R0{"R0 · live swap<br/>(conf ≥ 0.9)"}
    R0 -- "total ≥ decline" --> D["DECLINE · SIM_SWAP_HIGH_RISK<br/>SMS/VOICE prohibited · biometric kept"]
    R0 -- "else" --> E0["ESCALATE · SIM_SWAP_RECENT<br/>SMS/VOICE PROHIBITED"]
    R0 -- "no" --> R6{"R6 · aged-window swap<br/>+ behavioral anomaly?"}
    R6 -- "yes" --> E6["ESCALATE · SIM_SWAP_AGED_CORROBORATION<br/>SMS allowed (window passed) · +20, never declines alone"]
    R6 -- "no" --> R7{"R7 · fresh payee + repeats ≥ 2?"}
    R7 -- "yes" --> E7["ESCALATE · PAYEE_VELOCITY_TRAP<br/>biometric-only · threshold-independent"]
    R7 -- "no" --> R8{"R8 · live call during payment?"}
    R8 -- "yes" --> E8["ESCALATE · COOLING_OFF_HOLD<br/>NOTHING dispatchable · hold + bank-held callback"]
    R8 -- "no" --> R3{"R3 · primary signal lost<br/>+ anomaly?"}
    R3 -- "yes" --> E3["ESCALATE · PRIMARY_SIGNAL_LOSS<br/>biometric-only"]
    R3 -- "no" --> R5{"R5 · telecom green + anomaly + ≥20×?"}
    R5 -- "yes" --> E5["ESCALATE · BEHAVIORAL_ANOMALY<br/>biometric only, SMS prohibited"]
    R5 -- "no" --> R2{"R2 · degraded signal + anomaly?"}
    R2 -- "yes" --> E2["ESCALATE · DEGRADED_SIGNAL_ANOMALY"]
    R2 -- "no" --> R4{"R4 · coverage < minimum?"}
    R4 -- "yes" --> E4["ESCALATE · COVERAGE_LOW"]
    R4 -- "no" --> T{"thresholds (recorded)"}
    T -- "≥ decline" --> D2["DECLINE · WEIGHTED_RISK_HIGH"]
    T -- "≥ escalate" --> E9["ESCALATE · WEIGHTED_RISK_BAND (SMS allowed)"]
    T -- "else" --> A["APPROVE · CLEAN — no step-up at all"]
```

## 4 · ChannelLock — how enforcement works

```mermaid
sequenceDiagram
    participant B as Bank orchestrator
    participant T as Tasdiq /v1/decide
    participant G as OTP gateway (bank side)
    Note over T: verdict computed; includes<br/>Ed25519-signed grant:<br/>allowed[] · prohibited[] · policy hash<br/>nonce · audience · 60–120 s TTL
    B->>T: decide(payment)
    T-->>B: verdict + grant (compact token)
    B->>G: send channel X + token
    G->>G: verify signature · expiry · nonce<br/>audience · policy hash · channel ∈ allowed
    alt channel prohibited or anything invalid
        G-->>B: REFUSED (reason code) — logged to audit
    else channel allowed, token valid
        G-->>B: dispatched (nonce burns — single use)
    end
    Note over G: verification is LOCAL — no call to Tasdiq.<br/>A Tasdiq outage never re-enables SMS.
```

**Deployment ladder:** `shadow` (log would-have-refused) → `alert`
(dispatch + alert) → `enforce` (refuse). The mock gateway at
`/v1/stepup/dispatch` implements all three.

## 5 · Fail-safe direction

Missing / degraded / timed-out signals carry confidence 0 with a label, and
the rules **tighten** — an attacker who forces a blind state forces a
stricter bank, never a blinder one. Risk-sensitive degraded modes (per
operator outage × transaction size × device trust) are the bank's policy to
own; Tier-0 quiet traffic survives outages by construction (it buys no
signals).
