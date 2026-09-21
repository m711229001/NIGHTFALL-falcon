# NIGHTFALL - E2E Benchmark Report

**Date:** 2026-09-21  
**Status:** E2E scans working

## DVWA (http://localhost:8080)

- **Scan ID:** 63
- **Findings:** 33
- **Modules:** xss, sqli, ai
- **Report:** bug_bounty_reports/scan_63_*
- **Excel:** exports/falcon_scan_63_*.xlsx
- **Status:** ✅ Working

## Juice Shop (http://localhost:3000)

- **Scan ID:** cli_1789973839_1
- **Status:** done

## bWAPP (http://localhost:8081)

- **Scan ID:** cli_1789973935_1
- **Status:** done

## Fixes Applied in this Session

1. `--cookies` → `--cookie` in cli_runner.py
2. `_translate_target()` for Docker networking
3. DVWA connected to falcon-net
4. `scan_id` filter (int + str) in findings.py

## Statistics

- Total Scans: 11
- Tags: 13+
- Commits: 70+
- pytest: 44/44 ✅
