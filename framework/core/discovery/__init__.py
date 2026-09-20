"""Falcon MAG - Smart Discovery Engine (public API)."""
from .engine import discover, DiscoveryEngine, DiscoveryConfig, DiscoveryResult
from .intelligence import URLNormalizer, ScoreRanker, CatchAllDetector, Deduplicator

__all__ = [
    "discover",
    "DiscoveryEngine",
    "DiscoveryConfig",
    "DiscoveryResult",
    "URLNormalizer",
    "ScoreRanker",
    "CatchAllDetector",
    "Deduplicator",
]
