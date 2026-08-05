"""
Chain freeze logic — locks the winning WAF bypass chain and shares it
across all detection engines for the rest of the campaign.

Once a chain is frozen:
1. New payloads are automatically encoded through the frozen chain
2. The chain is persisted to the campaign database
3. All engines receive the frozen chain via the orchestrator context
"""
from __future__ import annotations

import json
from typing import Optional

import structlog

from nightfall.bypass.encoders import apply_chain

logger = structlog.get_logger(__name__)


class ChainFreezer:
    """Manages frozen WAF bypass chains for the campaign.

    Stores the winning encoder chain and provides methods to:
    - Freeze a chain after successful bypass
    - Apply the frozen chain to new payloads
    - Serialize/deserialize for database persistence
    """

    def __init__(self):
        self._frozen: dict[str, list[str]] = {}  # vuln_class -> chain_names
        self._history: list[dict] = []  # audit trail of freeze events

    def freeze(self, vuln_class: str, chain_name: str) -> None:
        """Freeze a winning bypass chain for a vulnerability class.

        Args:
            vuln_class: The vulnerability class (sqli, xss, etc.)
            chain_name: The encoder chain name (e.g. "enc_url+enc_mixed_case")
        """
        chain_names = chain_name.split("+")
        self._frozen[vuln_class] = chain_names
        self._history.append({
            "vuln_class": vuln_class,
            "chain_name": chain_name,
            "chain_parts": chain_names,
        })
        logger.info(
            "chain_frozen",
            vuln_class=vuln_class,
            chain=chain_name,
        )

    def is_frozen(self, vuln_class: str) -> bool:
        """Check if a bypass chain is frozen for this vulnerability class."""
        return vuln_class in self._frozen

    def get_chain(self, vuln_class: str) -> Optional[list[str]]:
        """Get the frozen chain names for a vulnerability class."""
        return self._frozen.get(vuln_class)

    def encode(self, payload: str, vuln_class: str) -> str:
        """Apply the frozen chain to a payload.

        If no chain is frozen for this class, returns the payload unchanged.

        Args:
            payload: Raw payload to encode.
            vuln_class: Vulnerability class to look up the frozen chain.

        Returns:
            Encoded payload (or original if no frozen chain).
        """
        chain = self._frozen.get(vuln_class)
        if not chain:
            return payload
        return apply_chain(payload, chain)

    def to_json(self) -> str:
        """Serialize frozen chains for database persistence."""
        return json.dumps({
            "frozen": self._frozen,
            "history": self._history,
        })

    @classmethod
    def from_json(cls, data: str) -> "ChainFreezer":
        """Deserialize frozen chains from database."""
        freezer = cls()
        try:
            parsed = json.loads(data)
            freezer._frozen = parsed.get("frozen", {})
            freezer._history = parsed.get("history", [])
        except (json.JSONDecodeError, KeyError):
            pass
        return freezer

    @property
    def frozen_chains(self) -> dict[str, list[str]]:
        return dict(self._frozen)

    @property
    def stats(self) -> dict:
        return {
            "num_frozen": len(self._frozen),
            "classes": list(self._frozen.keys()),
            "history_len": len(self._history),
        }
