"""ChannelLock — signed step-up enforcement grants (L3.5).

The verdict's step_up lists are ADVICE until the bank's OTP gateway can
refuse prohibited channels. ChannelLock turns advice into a control:
every decision carries a short-lived Ed25519-signed grant; the bank's
gateway verifies it LOCALLY (this module is the reference verifier —
ships as the SDK/sidecar) and dispatches a channel only if that channel
is in the grant's `allowed` list. Default deny.

Semantics:
  - allowed  : the ONLY channels the gateway may dispatch for this txn.
  - prohibited: channels the verdict explicitly bans (redundant with
    default-deny, kept for audit clarity — e.g. "SMS" after a swap).
  - Clean APPROVE (no step-up needed) issues allowed=[] — the gateway
    refuses EVERY OTP for that transaction, which is the designed
    OTP-free path.
  - Token lifetime 60–120 s (default 90), one-time nonce, tenant-bound
    issuer/audience, policy_version_hash bound.
  - Failure behavior: no valid grant for the channel => refuse. An
    expired/absent token NEVER re-enables a channel (fail closed).
    Gateway behaviour on total absence of a token (Tasdiq down before
    decision) is bank-configurable — the verifier just reports why.

Prototype limits (documented): nonce store is in-process (production:
bank-side SDK local store); signing key is a file persona like
maker/checker (production: KMS/HSM); grant rides inside the verdict so
idempotent replay returns the ORIGINAL token (a re-decide after expiry
would mint a fresh one — the gateway treats expired as refuse).
"""
from __future__ import annotations
import hashlib, json, os, secrets, time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.config import cfg
from app.policy import canon, gen_keypair, load_key

KEYS = Path(__file__).resolve().parent.parent / "keys"
PERSONA = "channellock"          # dedicated key persona, independent of maker/checker
DEFAULT_TTL = int(os.getenv("CHANNELLOCK_TTL", "90"))
MAX_TTL = 120


def ensure_key() -> str:
    if not (KEYS / f"{PERSONA}.key").exists():
        gen_keypair(PERSONA, KEYS)
    return PERSONA


# --- one-time nonce store (prototype: in-process; production: bank-side) ----
_used_nonces: dict[str, float] = {}


def _sweep(now: float):
    for n, exp in list(_used_nonces.items()):
        if exp < now:
            del _used_nonces[n]


def _msisdn_hash(msisdn: str) -> str:
    return "msisdn_" + hashlib.sha256((msisdn + cfg.VAULT_KEY).encode()).hexdigest()[:16]


# --- issuance (server side, once per decision) -------------------------------
def issue_grant(verdict: dict, msisdn: str, bank: str, ttl: int = DEFAULT_TTL) -> dict:
    """Build + sign the step-up grant for a decided verdict."""
    ensure_key()
    ttl = max(1, min(ttl, MAX_TTL))
    now = int(time.time())
    payload = {
        "v": 1,
        "txn_id_hash": "sha256:" + hashlib.sha256(verdict.get("txn_id", "").encode()).hexdigest(),
        "msisdn_hash": _msisdn_hash(msisdn),
        "allowed": [_canon_channel(ch) for ch in verdict.get("step_up", {}).get("allowed", [])],
        "prohibited": [_canon_channel(ch) for ch in verdict.get("step_up", {}).get("prohibited", [])],
        "policy_version_hash": verdict.get("policy_version_hash"),
        "band": verdict.get("band"),
        "issuer": f"tasdiq-{bank.lower()}",
        "audience": f"{bank.lower()}-otp-gateway",
        "iat": now,
        "exp": now + ttl,
        "nonce": secrets.token_hex(16),
    }
    sig = load_key(PERSONA, KEYS).sign(canon(payload))
    token = dict(payload)
    token["signing_key_id"] = f"{PERSONA}@1"
    token["signature_algorithm"] = "Ed25519"
    token["signature"] = sig.hex()
    return token


def compact(token: dict) -> str:
    """Wire form: base64url(canonical payload).base64url(signature)."""
    import base64
    payload_b = canon({k: token[k] for k in token if k not in ("signature",
                                                               "signature_algorithm",
                                                               "signing_key_id")})
    return (base64.urlsafe_b64encode(payload_b).decode().rstrip("=")
            + "." + base64.urlsafe_b64encode(bytes.fromhex(token["signature"])).decode().rstrip("="))


# --- verification (bank side — LOCAL, no network, no Tasdiq call) -------------
REFUSAL_REASONS = {
    "MALFORMED", "TAMPERED", "EXPIRED", "REPLAYED", "WRONG_AUDIENCE",
    "WRONG_ISSUER", "NO_GRANT", "CHANNEL_NOT_ALLOWED", "CHANNEL_PROHIBITED",
}


_CHANNEL_ALIAS = {"SMS_OTP": "SMS"}   # legacy naming — one channel, one canonical name


def _canon_channel(ch: str) -> str:
    return _CHANNEL_ALIAS.get(ch, ch)


def verify_grant(token: dict | None, channel: str, expected_audience: str,
                 expected_issuer: str | None = None) -> dict:
    """Reference verifier (the SDK that ships to the bank).

    Pure local computation: signature, expiry, nonce, audience/issuer,
    policy-hash presence, channel membership. Returns
    {authorized: bool, reason: None|str, payload: token|None}.
    A channel is authorized ONLY if it appears in `allowed` of a fully
    valid, unexpired, unused token. Default deny; never a silent allow.
    """
    channel = _canon_channel(channel)
    if not isinstance(token, dict):
        return {"authorized": False, "reason": "NO_GRANT", "payload": None}
    sig = token.get("signature")
    if not sig or "txn_id_hash" not in token:
        return {"authorized": False, "reason": "MALFORMED", "payload": None}
    payload = {k: token[k] for k in token if k not in ("signature",
                                                       "signature_algorithm",
                                                       "signing_key_id")}
    pub: Ed25519PublicKey = load_key(PERSONA, KEYS, private=False)
    try:
        pub.verify(bytes.fromhex(sig), canon(payload))
    except Exception:
        return {"authorized": False, "reason": "TAMPERED", "payload": None}
    now = time.time()
    if now > token.get("exp", 0):
        return {"authorized": False, "reason": "EXPIRED", "payload": token}
    _sweep(now)
    nonce = token.get("nonce", "")
    if nonce in _used_nonces:
        return {"authorized": False, "reason": "REPLAYED", "payload": token}
    if token.get("audience") != expected_audience:
        return {"authorized": False, "reason": "WRONG_AUDIENCE", "payload": token}
    if expected_issuer and token.get("issuer") != expected_issuer:
        return {"authorized": False, "reason": "WRONG_ISSUER", "payload": token}
    if channel in token.get("prohibited", []):
        return {"authorized": False, "reason": "CHANNEL_PROHIBITED", "payload": token}
    if channel not in token.get("allowed", []):
        return {"authorized": False, "reason": "CHANNEL_NOT_ALLOWED", "payload": token}
    # single-use: the nonce burns only on an AUTHORIZED dispatch — refusal
    # checks (probing a channel, shadow-mode audits) must not consume the
    # grant, or a gateway could not test-then-dispatch the same verdict
    _used_nonces[nonce] = token["exp"]
    return {"authorized": True, "reason": None, "payload": token}


def decode_compact(token_str: str) -> dict | None:
    import base64
    try:
        payload_b64, sig_b64 = token_str.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)
        payload = json.loads(base64.urlsafe_b64decode(pad(payload_b64)))
        payload["signature"] = base64.urlsafe_b64decode(pad(sig_b64)).hex()
        return payload
    except Exception:
        return None
