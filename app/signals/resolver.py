"""Operator resolution — pluggable MNP-aware routing (friend-review F4).

Production ports numbers between operators (stc -> Mobily etc.); a static
prefix map silently mis-attributes the breaker, the operator label, and any
operator-scoped risk. This module makes the resolution step an interface:

  StaticResolver      — prefix map (sandbox / prototype default)
  CachedMNPResolver   — TTL cache in front of ANY pluggable lookup provider
                        (production: MNP feed / HLR dip / aggregator API)

The production provider is a Phase-1 workstream (named in README honest
scope); the seam exists today so the answer to "what happens when a number
ports?" is a design, not a flinch.
"""
from __future__ import annotations
import threading, time
from abc import ABC, abstractmethod


class OperatorResolver(ABC):
    @abstractmethod
    def resolve(self, msisdn: str) -> str: ...


class StaticResolver(OperatorResolver):
    """Prefix-table resolution (current prototype behavior, unchanged)."""

    def __init__(self, prefix_map: dict[str, str], default: str):
        self.map = dict(prefix_map)
        self.default = default

    def resolve(self, msisdn: str) -> str:
        for prefix, op in self.map.items():
            if msisdn.startswith(prefix):
                return op
        return self.default


class CachedMNPResolver(OperatorResolver):
    """TTL cache wrapping a slower lookup (MNP feed, HLR dip, aggregator).

    Cache hit = one dict read (sub-microsecond). Miss/ttl-expiry delegates to
    the wrapped provider. Porting events are rare; a modest TTL keeps both the
    latency budget and operator attribution honest.
    """

    def __init__(self, inner: OperatorResolver, ttl_seconds: float = 300.0):
        self.inner = inner
        self.ttl = ttl_seconds
        self._cache: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def resolve(self, msisdn: str) -> str:
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(msisdn)
        if hit and now - hit[1] < self.ttl:
            return hit[0]
        op = self.inner.resolve(msisdn)
        with self._lock:
            self._cache[msisdn] = (op, now)
        return op
