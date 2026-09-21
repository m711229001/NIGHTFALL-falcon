"""Pytest suite for nightfall_core."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
import nightfall_core as nc


class TestSignatures:
    def test_waf_signatures_count(self):
        assert len(nc.WAF_SIGNATURES) >= 30

    def test_waf_signatures_extended(self):
        assert len(nc.WAF_SIGNATURES_EXTENDED) >= 60

    def test_waf_body_patterns(self):
        assert len(nc.WAF_BODY_PATTERNS) >= 15


class TestClassesExist:
    def test_circuit_breaker(self):
        assert hasattr(nc, "CircuitBreaker")

    def test_adaptive_rate_limiter(self):
        assert hasattr(nc, "AdaptiveRateLimiter")

    def test_structured_logger(self):
        assert hasattr(nc, "StructuredScanLogger")

    def test_metrics_collector(self):
        assert hasattr(nc, "MetricsCollector")


class TestCoreFunctions:
    def test_test_xss(self):
        assert callable(getattr(nc, "test_xss", None))

    def test_test_xss_post(self):
        assert callable(getattr(nc, "test_xss_post", None))

    def test_test_sqli(self):
        assert callable(getattr(nc, "test_sqli", None))

    def test_test_sqli_union(self):
        assert callable(getattr(nc, "test_sqli_union", None))

    def test_test_sqli_boolean(self):
        assert callable(getattr(nc, "test_sqli_boolean", None))

    def test_test_sqli_stacked(self):
        assert callable(getattr(nc, "test_sqli_stacked", None))

    def test_test_sqli_time_advanced(self):
        assert callable(getattr(nc, "test_sqli_time_advanced", None))

    def test_test_sqli_oast(self):
        assert callable(getattr(nc, "test_sqli_oast", None))

    def test_test_sqlmap_bridge(self):
        assert callable(getattr(nc, "test_sqlmap_bridge", None))

    def test_test_ssrf(self):
        assert callable(getattr(nc, "test_ssrf", None))

    def test_test_ssrf_advanced(self):
        assert callable(getattr(nc, "test_ssrf_advanced", None))

    def test_test_ssrf_oast_advanced(self):
        assert callable(getattr(nc, "test_ssrf_oast_advanced", None))

    def test_test_nosql_advanced(self):
        assert callable(getattr(nc, "test_nosql_advanced", None))

    def test_test_graphql_advanced(self):
        assert callable(getattr(nc, "test_graphql_advanced", None))

    def test_test_ldap_advanced(self):
        assert callable(getattr(nc, "test_ldap_advanced", None))

    def test_test_csrf_advanced(self):
        assert callable(getattr(nc, "test_csrf_advanced", None))

    def test_test_jwt_advanced(self):
        assert callable(getattr(nc, "test_jwt_advanced", None))

    def test_test_jwt_multi(self):
        assert callable(getattr(nc, "test_jwt_multi", None))

    def test_test_xxe_advanced(self):
        assert callable(getattr(nc, "test_xxe_advanced", None))

    def test_test_ssti_advanced(self):
        assert callable(getattr(nc, "test_ssti_advanced", None))

    def test_test_waf_advanced(self):
        assert callable(getattr(nc, "test_waf_advanced", None))

    def test_test_waf_body_detection(self):
        assert callable(getattr(nc, "test_waf_body_detection", None))

    def test_test_db_fingerprint(self):
        assert callable(getattr(nc, "test_db_fingerprint", None))

    def test_test_fingerprint_advanced(self):
        assert callable(getattr(nc, "test_fingerprint_advanced", None))

    def test_test_security_headers(self):
        assert callable(getattr(nc, "test_security_headers", None))

    def test_test_cookies_advanced(self):
        assert callable(getattr(nc, "test_cookies_advanced", None))

    def test_test_nmap_scan(self):
        assert callable(getattr(nc, "test_nmap_scan", None))

    def test_test_open_redirect_post(self):
        assert callable(getattr(nc, "test_open_redirect_post", None))

    def test_test_sqli_post(self):
        assert callable(getattr(nc, "test_sqli_post", None))

    def test_test_ssrf_post(self):
        assert callable(getattr(nc, "test_ssrf_post", None))


class TestOrchestrators:
    def test_run_scan(self):
        assert callable(getattr(nc, "run_scan", None))

    def test_run_scan_v4(self):
        assert callable(getattr(nc, "run_scan_v4", None))

    def test_run_scan_v5(self):
        assert callable(getattr(nc, "run_scan_v5", None))

    def test_run_vulnerability_tests_v2(self):
        assert callable(getattr(nc, "run_vulnerability_tests_v2", None))

    def test_run_sqli_advanced(self):
        assert callable(getattr(nc, "run_sqli_advanced", None))


class TestCircuitBreaker:
    def test_trips_after_threshold(self):
        cb = nc.CircuitBreaker(threshold=3, cooldown_sec=1.0)
        assert not cb.is_open("test.local")
        cb.record_failure("test.local")
        cb.record_failure("test.local")
        assert not cb.is_open("test.local")
        cb.record_failure("test.local")
        assert cb.is_open("test.local")


class TestAdaptiveRateLimiter:
    def test_halves_on_block(self):
        arl = nc.AdaptiveRateLimiter(rate_per_sec=30.0, burst=5)
        assert arl.get_rate("test.local") == 30.0
        arl.on_block("test.local")
        assert arl.get_rate("test.local") == 15.0
        arl.on_block("test.local")
        assert arl.get_rate("test.local") == 7.5
