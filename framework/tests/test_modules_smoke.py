"""Smoke tests for Phase 4 modules (ADDED 2026-09-19).

Tests all new modules to ensure they:
  1. Import without errors
  2. Have a callable run() function
  3. Accept the standard signature (config, client)
  4. Don't crash on a safe target
"""
import sys
from pathlib import Path

# Add framework to path
FRAMEWORK_DIR = Path(__file__).resolve().parent.parent
if str(FRAMEWORK_DIR) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_DIR))

import traceback
from core.config import load_config, apply_target
from core.http_client import HTTPClient


# Modules to test
NEW_MODULES = [
    "tech_fingerprint",
    "nextjs_middleware_bypass",
    "rsc_data_leakage",
    "graphql_relay_idor",
    "react2shell_rce",
    "ssr_proto_pollution",
]

# Import paths (from cli.py MODULE_REGISTRY)
MODULE_PATHS = {
    "tech_fingerprint": "modules.tech_fingerprint",
    "nextjs_middleware_bypass": "modules.nextjs_middleware_bypass",
    "rsc_data_leakage": "modules.rsc_data_leakage",
    "graphql_relay_idor": "modules.graphql_relay_idor",
    "react2shell_rce": "modules.react2shell_rce",
    "ssr_proto_pollution": "modules.ssr_proto_pollution",
}

TARGET = "https://httpbin.org"


def test_import(name: str) -> tuple:
    """Test 1: can we import the module and get run()?"""
    try:
        import_path = MODULE_PATHS[name]
        mod = __import__(import_path, fromlist=["run"])
        fn = getattr(mod, "run", None)
        if not callable(fn):
            return False, "run() not callable or missing"
        return True, "OK"
    except Exception as e:
        return False, f"Import failed: {type(e).__name__}: {e}"


def test_run(name: str, config: dict, client) -> tuple:
    """Test 2: can we actually run the module?"""
    try:
        import_path = MODULE_PATHS[name]
        mod = __import__(import_path, fromlist=["run"])
        fn = mod.run
        result = fn(config=config, client=client)
        if not isinstance(result, dict):
            return False, f"run() returned {type(result).__name__}, expected dict"
        return True, f"OK ({len(result)} keys)"
    except Exception as e:
        tb = traceback.format_exc()
        return False, f"Run failed: {type(e).__name__}: {e}\n{tb[:500]}"


def main():
    print("=" * 70)
    print("Falcon MAG - Phase 4 Modules Smoke Test")
    print("=" * 70)
    print(f"Target: {TARGET}")
    print()

    # Setup config + client
    try:
        config = load_config()
        apply_target(config, TARGET)
        client = HTTPClient(config=config)
        print("[SETUP] Config + client OK")
        print()
    except Exception as e:
        print(f"[FATAL] Setup failed: {e}")
        traceback.print_exc()
        return 1

    passed = 0
    failed = 0
    results = []

    for name in NEW_MODULES:
        print(f"--- {name} ---")

        # Test 1: Import
        ok1, msg1 = test_import(name)
        if ok1:
            print(f"  [PASS] Import: {msg1}")
        else:
            print(f"  [FAIL] Import: {msg1}")
            failed += 1
            results.append((name, "import", msg1))
            print()
            continue

        # Test 2: Run
        ok2, msg2 = test_run(name, config, client)
        if ok2:
            print(f"  [PASS] Run:    {msg2}")
            passed += 1
        else:
            print(f"  [FAIL] Run:    {msg2}")
            failed += 1
            results.append((name, "run", msg2))

        print()

    print("=" * 70)
    print(f"SUMMARY: {passed} passed, {failed} failed (out of {len(NEW_MODULES)})")
    print("=" * 70)

    if results:
        print()
        print("FAILURES:")
        for name, phase, msg in results:
            print(f"  - {name} [{phase}]: {msg[:200]}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())