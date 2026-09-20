"""Falcon MAG Framework - Unified CLI Entry Point

Falcon MAG v2 — Security Assessment CLI
Features:
  - scan / list / test / version
  - login / profiles / totp (Playwright + TOTP)
  - Crawler → Scanner bridge (feeders run first)
  - Parallel module execution
  - Authenticated scans (cookies, bearer, profile)
"""
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import typer
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# Add framework dir to path so `import core` works
FRAMEWORK_DIR = Path(__file__).resolve().parent
if str(FRAMEWORK_DIR) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_DIR))

from core.config import (  # noqa: E402
    load_config, apply_target, apply_modules,
    enable_all_modules, get_enabled_modules,
)
from core.http_client import HTTPClient, preflight_check  # noqa: E402
from core.report import generate_reports  # noqa: E402
from core.logger import get_logger  # noqa: E402

log = get_logger("cli")
console = Console()

# ============================================================
# Auth extensions (Playwright + TOTP) — optional
# ============================================================
try:
    from core.auth.profiles import load_profile, list_profiles
    HAS_AUTH_EXTENSIONS = True
except ImportError as e:
    log.warning(f"Profile extensions not available: {e}")
    HAS_AUTH_EXTENSIONS = False

# TOTP support
try:
    import pyotp
    HAS_TOTP = True
except ImportError:
    HAS_TOTP = False


# Generic auth (basic/oauth/saml/nafath)
try:
    from core.auth import login as generic_login, available as auth_available
    HAS_GENERIC_AUTH = True
except ImportError as e:
    HAS_GENERIC_AUTH = False
    log.warning(f'Generic auth not available: {e}')

# ============================================================
# Typer App
# ============================================================
# ============================================================
# TOTP helpers
# ============================================================
def generate_totp(secret: str) -> str:
    """Generate a TOTP code from a base32 secret."""
    if not HAS_TOTP:
        return ""
    try:
        return pyotp.TOTP(secret).now()
    except Exception:
        return ""


def verify_secret(secret: str) -> bool:
    """Verify a TOTP secret is valid base32."""
    if not secret:
        return False
    try:
        import base64
        base64.b32decode(secret.upper(), casefold=True)
        return True
    except Exception:
        return False



app = typer.Typer(
    name="falcon",
    help="🦅 Falcon MAG Framework — Security Assessment CLI",
    add_completion=False,
    rich_markup_mode="rich",
)

# ============================================================
# Module registry (name -> import path)
# ============================================================
MODULE_REGISTRY = {
    # Phase 4 — Modern Vulnerabilities (ADDED 2026-09-19)
    "rsc_data_leakage":         "modules.rsc_data_leakage",
    "graphql_relay_idor":       "modules.graphql_relay_idor",
    "react2shell_rce":          "modules.react2shell_rce",
    "ssr_proto_pollution":      "modules.ssr_proto_pollution",
    "nextjs_middleware_bypass": "modules.nextjs_middleware_bypass",
    "tech_fingerprint":     "modules.tech_fingerprint",
    # Phase 1 — Reconnaissance
    "fingerprint":          "modules.fingerprint",
    "headers_check":        "modules.headers_check",
    "param_discovery":      "modules.param_discovery",
    "crawler":              "modules.crawler",
    "js_analyzer":          "modules.js_analyzer",
    "path_discovery":       "modules.path_discovery",
    "catch_all_detector":   "modules.catch_all_detector",
    "js_endpoints":         "modules.js_endpoints",
    "endpoint_catalog":     "modules.endpoint_catalog",
    "js_secrets":           "modules.js_secrets",
    "dom_xss_scanner":      "modules.dom_xss_scanner",
    "external_nmap":        "modules.external_nmap",
    "external_testssl":     "modules.external_testssl",
    "external_subfinder":   "modules.external_subfinder",
    "external_searchsploit":"modules.external_searchsploit",
    "playwright_crawler":   "modules.playwright_crawler",
    # Phase 2 — Vulnerabilities
    "xss_scanner":          "modules.xss_scanner",
    "sqli_scanner":         "modules.sqli_scanner",
    "nosql_scanner":        "modules.nosql_scanner",
    "csrf_checker":         "modules.csrf_checker",
    "clickjacking":         "modules.clickjacking",
    "path_traversal":       "modules.path_traversal",
    "ssrf_scanner":         "modules.ssrf_scanner",
    "idor_scanner":         "modules.idor_scanner",
    "open_redirect":        "modules.open_redirect",
    "prototype_pollution":  "modules.prototype_pollution",
    # Phase 3 — Infrastructure
    "tls_checker":          "modules.tls_checker",
    "port_scanner":         "modules.port_scanner",
    "cors_checker":         "modules.cors_checker",
    "http_methods":         "modules.http_methods",
    "cookies_checker":      "modules.cookies_checker",
    "rate_limit_test":      "modules.rate_limit_test",
    "subdomain_enum":       "modules.subdomain_enum",
    "cve_lookup":           "modules.cve_lookup",
}

# ============================================================
# Bridge: feeders run first, sequentially, before scanners
# ============================================================
FEEDER_MODULES = ["crawler", "playwright_crawler", "js_analyzer", "js_endpoints", "param_discovery", "endpoint_catalog"]

FEEDER_KEYS = {
    "crawler":            "_crawl_result",
    "playwright_crawler": "_crawl_result",
    "js_analyzer":        "_js_analyzer",
    "js_endpoints":       "_js_endpoints",
    "param_discovery":    "_param_discovery",
    "endpoint_catalog":   "_endpoint_catalog",
}

# Modules that accept a crawl_result kwarg
MODULES_ACCEPTING_CRAWL = {"xss_scanner", "js_endpoints"}


# ============================================================
# SCAN MODES (ADDED 2026-09-20)
# ============================================================
MODE_PRESETS = {
    "fast": {
        "label": "Fast (30-60s)",
        "description": "Quick recon + visible params only",
        "modules": [
            "fingerprint", "headers_check", "clickjacking",
            "cors_checker", "cookies_checker", "endpoint_catalog",
        ],
        "max_pages": 10,
        "crawl_depth": 1,
        "param_discovery_max": 50,
        "xss_max_params": 3,
        "sqli_max_params": 2,
        "max_findings_ai": 5,
        "path_wordlist": "small",
        "enable_ai": True,
    },
    "normal": {
        "label": "Normal (3-5 min)",
        "description": "Balanced — crawl + common params + AI",
        "modules": [
            "fingerprint", "headers_check", "clickjacking",
            "cors_checker", "cookies_checker", "csrf_checker",
            "crawler", "param_discovery",
            "xss_scanner", "sqli_scanner",
            "http_methods", "open_redirect", "endpoint_catalog",
        ],
        "max_pages": 30,
        "crawl_depth": 2,
        "param_discovery_max": 150,
        "xss_max_params": 15,
        "sqli_max_params": 8,
        "max_findings_ai": 15,
        "path_wordlist": "small",
        "enable_ai": True,
    },
    "deep": {
        "label": "Deep (15-30 min)",
        "description": "Full crawl + JS + DOM + SSRF/IDOR",
        "modules": [
            "fingerprint", "headers_check", "clickjacking",
            "cors_checker", "cookies_checker", "csrf_checker",
            "crawler", "playwright_crawler", "param_discovery",
            "js_analyzer", "js_secrets", "js_endpoints",
            "dom_xss_scanner", "xss_scanner", "sqli_scanner",
            "nosql_scanner", "ssrf_scanner", "idor_scanner",
            "open_redirect", "path_traversal", "prototype_pollution",
            "path_discovery", "http_methods",
            "tls_checker", "subdomain_enum", "cve_lookup", "endpoint_catalog",
        ],
        "max_pages": 100,
        "crawl_depth": 3,
        "param_discovery_max": 300,
        "xss_max_params": 40,
        "sqli_max_params": 20,
        "max_findings_ai": 30,
        "path_wordlist": "medium",
        "enable_ai": True,
    },
    "ultra": {
        "label": "Ultra (1-3 hours)",
        "description": "Everything + external tools + full wordlists",
        "modules": "ALL",
        "param_discovery_max": 9999,
        "xss_max_params": 200,
        "sqli_max_params": 100,
        "max_findings_ai": 50,
        "path_wordlist": "full",
        "enable_ai": True,
    },
    "custom": {
        "label": "Custom",
        "description": "User-selected vulnerability focus",
        "modules": [],  # resolved from --focus
        "param_discovery_max": 150,
        "xss_max_params": 20,
        "sqli_max_params": 10,
        "max_findings_ai": 20,
        "path_wordlist": "small",
        "enable_ai": True,
    },
}


# Focus → modules mapping (for custom mode)
FOCUS_MAP = {
    "xss":      ["xss_scanner", "dom_xss_scanner"],
    "sqli":     ["sqli_scanner", "nosql_scanner"],
    "ssrf":     ["ssrf_scanner"],
    "idor":     ["idor_scanner"],
    "csrf":     ["csrf_checker"],
    "redirect": ["open_redirect"],
    "lfi":      ["path_traversal"],
    "rce":      ["prototype_pollution"],
    "cors":     ["cors_checker"],
    "headers":  ["headers_check"],
    "cookies":  ["cookies_checker"],
    "tls":      ["tls_checker"],
    "ports":    ["port_scanner"],
    "js":       ["js_analyzer", "js_secrets", "js_endpoints"],
    "dom":      ["dom_xss_scanner"],
    "recon":    ["crawler", "fingerprint", "path_discovery", "subdomain_enum"],
    "params":   ["param_discovery"],
    "all":      "ALL",
}


def _resolve_modules_from_mode(mode: str, focus: list, explicit: list):
    """Resolve module list from scan mode."""
    if explicit:
        return explicit

    if mode == "custom":
        if not focus:
            log.warning("  --mode custom requires --focus or --modules")
            # Fallback to normal
            return MODE_PRESETS["normal"]["modules"]
        resolved = set()
        for f in focus:
            f = f.lower().strip()
            mapped = FOCUS_MAP.get(f)
            if mapped == "ALL":
                return None  # means all modules
            if mapped:
                resolved.update(mapped)
        # Always add recon in custom mode
        resolved.update(["fingerprint", "headers_check", "crawler", "param_discovery"])
        return sorted(resolved)

    preset = MODE_PRESETS.get(mode, MODE_PRESETS["normal"])
    mods = preset.get("modules")
    if mods == "ALL":
        return None  # all modules
    return list(mods)


def _print_mode_banner(mode: str, focus: list, module_count: int):
    """Print mode info."""
    preset = MODE_PRESETS.get(mode, {})
    label = preset.get("label", mode)
    desc = preset.get("description", "")
    console.print(f"[bold cyan]Mode:[/bold cyan] [yellow]{label}[/yellow]  [dim]({desc})[/dim]")
    if focus:
        console.print(f"[bold cyan]Focus:[/bold cyan] [magenta]{', '.join(focus)}[/magenta]")
    console.print(f"[bold cyan]Modules:[/bold cyan] [green]{module_count}[/green]")

# ============================================================
# Helpers
# ============================================================
def _load_module_fn(name: str):
    """Dynamically import a module and return its run() function."""
    if name not in MODULE_REGISTRY:
        raise ValueError(f"Unknown module: {name}")
    import_path = MODULE_REGISTRY[name]
    try:
        mod = __import__(import_path, fromlist=["run"])
    except ImportError as e:
        raise ImportError(f"Cannot import {import_path}: {e}")
    fn = getattr(mod, "run", None)
    if not callable(fn):
        raise AttributeError(f"{import_path} has no callable 'run'")
    return fn


def _print_banner(target: str, modules: list):
    console.print()
    console.print(Panel.fit(
        f"[bold red]🦅 Falcon MAG Framework[/bold red]\n"
        f"[white]Target:[/white] [cyan]{target}[/cyan]\n"
        f"[white]Modules:[/white] [yellow]{len(modules)}[/yellow] "
        f"({', '.join(modules) if len(modules) <= 8 else ', '.join(modules[:8]) + ', ...'})",
        border_style="red",
        box=box.DOUBLE,
    ))
    console.print()


def _count_findings(data: dict) -> int:
    """Count findings in a module result (list-style + bool-style)."""
    if not isinstance(data, dict):
        return 0
    count = 0
    # NOTE: js_files, endpoints are informational (not findings)
    for key in ("vulnerable", "real_paths", "open_ports", "secrets",
                "vulnerable_forms", "weak_protocols",
                "found", "cves", "dangerous", "insecure",
                # ADDED 2026-09-20: more finding keys
                "findings", "issues", "alerts", "leaks", "hits",
                "suspicious", "exposed", "misconfigurations",
                "vulnerabilities", "warnings"):
        val = data.get(key)
        if isinstance(val, list):
            count += len(val)
    for key in ("vulnerable",):
        val = data.get(key)
        if isinstance(val, bool) and val:
            count += 1
    return count


def _print_summary_table(results: dict, elapsed: float):
    table = Table(title="Scan Summary", box=box.ROUNDED, title_style="bold red")
    table.add_column("Module", style="cyan", no_wrap=True)
    table.add_column("Status", style="green")
    table.add_column("Findings", style="yellow", justify="right")
    table.add_column("Time (s)", style="magenta", justify="right")

    for name, data in results.get("module_results", {}).items():
        if isinstance(data, dict):
            if data.get("error"):
                status = "[red]ERROR[/red]"
            elif data.get("skipped"):
                status = "[dim]SKIPPED[/dim]"
            else:
                status = "[green]OK[/green]"
            n = _count_findings(data)
            t = data.get("_elapsed", 0)
            table.add_row(name, status, str(n), f"{t:.2f}")
        else:
            table.add_row(name, "[dim]?[/dim]", "-", "-")

    console.print(table)
    console.print(f"\n[bold green]✓ Total time:[/bold green] {elapsed:.2f}s")
    console.print(f"[bold green]✓ Total findings:[/bold green] {len(results.get('findings', []))}")


def _execute_module(mod_name: str, config: dict, client, auth_kwargs: dict):
    """Run a single module, handling signature variations."""
    mod_start = time.time()
    try:
        mod_fn = _load_module_fn(mod_name)

        # Build kwargs dynamically based on what the module accepts
        kwargs = {"config": config, "client": client}

        # Some modules accept crawl_result
        if mod_name in MODULES_ACCEPTING_CRAWL:
            kwargs["crawl_result"] = config.get("_crawl_result")

        # Try with auth_context first, fallback without
        if auth_kwargs:
            try:
                mod_res = mod_fn(auth_context=auth_kwargs, **kwargs)
            except TypeError as te:
                if "auth_context" in str(te):
                    mod_res = mod_fn(**kwargs)
                else:
                    raise
        else:
            mod_res = mod_fn(**kwargs)

        if not isinstance(mod_res, dict):
            mod_res = {"result": mod_res}

        mod_res["_elapsed"] = time.time() - mod_start
        return mod_name, mod_res

    except Exception as err:
        log.exception(f"Exception running module {mod_name}")
        return mod_name, {"error": str(err), "_elapsed": time.time() - mod_start}

# ============================================================
# Tech-Aware Routing (ADDED 2026-09-19)
# Auto-enable modules based on tech_fingerprint result
# ============================================================
TECH_MODULE_MAP = {
    "Next.js": [
        "nextjs_middleware_bypass",
        "rsc_data_leakage",
    ],
    "React RSC": [
        "react2shell_rce",
    ],
    "GraphQL": [
        "graphql_mass_assign",
        "graphql_relay_idor",
    ],
    "Express/Node": [
        "nosql_scanner",
        "ssr_proto_pollution",
    ],
    "Vercel": [
        "http_methods",
        "cors_checker",
    ],
    "Cloudflare": [
        "cors_checker",
        "cookies_checker",
    ],
    "WordPress": [
        "xss_scanner",
        "sqli_scanner",
    ],
    "Django": [
        "ssrf_scanner",
        "csrf_checker",
    ],
    "Laravel": [
        "idor_scanner",
        "csrf_checker",
    ],
}


def _route_modules_by_tech(detected_techs: list, currently_selected: list) -> list:
    """Return modules relevant to detected technologies.

    Keeps currently_selected modules, and ADDS tech-specific ones.
    """
    routed = set(currently_selected or [])
    added = []

    for tech in (detected_techs or []):
        extra = TECH_MODULE_MAP.get(tech, [])
        for m in extra:
            if m not in routed:
                routed.add(m)
                added.append(m)

    return sorted(routed), added

def _run_scan(target: str, module_names: list, config_path: str = None,
              output_override: str = None, quiet: bool = False,
              auth_kwargs: dict = None, http_kwargs: dict = None,
              parallel: int = 1,
              enable_ai: bool = True, ai_max_findings: int = 20,
              scan_mode: str = "normal",
              max_pages: int = 30, crawl_depth: int = 2):
    """Core scan engine: feeders first (sequential), then parallel batch."""
    start_time = time.time()

    # ---- Load config ----
    config = load_config(config_path)

    # --insecure flag
    if http_kwargs and http_kwargs.pop("_insecure", False):
        config.setdefault("scan", {})["verify_ssl"] = False

    apply_target(config, target)

    # === Store scan mode (ADDED 2026-09-20) ===
    config["_scan_mode"] = scan_mode
    _mode_preset = MODE_PRESETS.get(scan_mode, {})
    config["_mode_preset"] = _mode_preset

    # === Crawl limits (ADDED 2026-09-20) ===
    config["_max_pages"] = max_pages
    config["_crawl_depth"] = crawl_depth
    scan_cfg = config.setdefault("scan", {})
    scan_cfg["max_pages"] = max_pages
    scan_cfg["crawl_depth"] = crawl_depth
    # === END ===

    # === Preflight: fast-fail on unreachable targets ===
    if not quiet:
        log.info("[preflight] Checking connectivity...")
    ok, reason = preflight_check(target, timeout=6)
    if not ok:
        log.error(f"[preflight] Target unreachable: {reason}")
        if not quiet:
            console.print(f"[red]✗ Target unreachable: {reason}[/red]")
            console.print(f"[yellow]  Aborting scan to save time.[/yellow]")
        return {
            "target": target,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "module_results": {},
            "findings": [],
            "error": f"preflight_failed: {reason}",
        }
    if not quiet:
        log.info(f"[preflight] OK ({reason})")
    # === End preflight ===

    if module_names:
        apply_modules(config, module_names)
    else:
        enable_all_modules(config)
        module_names = get_enabled_modules(config)

    if not quiet:
        _print_banner(target, module_names)

    # ---- Apply auth config (ADDED 2026-09-20) ----
    if auth_kwargs:
        if auth_kwargs.get("manual_cookie"):
            config["_manual_cookie"] = auth_kwargs["manual_cookie"]
        if auth_kwargs.get("bearer_token"):
            config["_bearer_token"] = auth_kwargs["bearer_token"]
        if auth_kwargs.get("username") and auth_kwargs.get("password"):
            config["_auth_username"] = auth_kwargs["username"]
            config["_auth_password"] = auth_kwargs["password"]
        if auth_kwargs.get("login_url"):
            config["_login_url"] = auth_kwargs["login_url"]

    # Extra headers from scan
    if http_kwargs and http_kwargs.get("extra_headers"):
        config["_auth_headers"] = http_kwargs["extra_headers"]

    # === ADDED: convert --post-data into a POST form (2026-09-20) ===
    if http_kwargs:
        post_data = http_kwargs.get("post_data")
        if post_data and "=" in post_data:
            fields = []
            for pair in post_data.split("&"):
                if "=" in pair:
                    k = pair.split("=", 1)[0]
                    fields.append(k)
            if fields:
                existing = config.get("_crawl_forms_post", []) or []
                existing.append({
                    "action": target,
                    "body": post_data,
                    "fields": fields,
                    "source": "cli_post_data",
                })
                config["_crawl_forms_post"] = existing
                if not quiet:
                    log.info(f"  [post-data] Converted to POST form ({len(fields)} fields)")

    # ---- HTTP client ----
    client = HTTPClient(config=config, **(http_kwargs or {}))

    # ---- Verify auth (ADDED) ----
    has_auth = bool(config.get("_manual_cookie") or config.get("_bearer_token"))
    if has_auth and not quiet:
        log.info("[auth] Verifying authenticated session...")
    if has_auth:
        ok, reason = client.verify_auth(target)
        config["_auth_verified"] = ok
        config["_auth_reason"] = reason
        if not quiet:
            if ok:
                log.info(f"[auth] ✓ Session active ({reason})")
            else:
                log.warning(f"[auth] ✗ Session may be invalid: {reason}")

    results = {
        "target": target,
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "module_results": {},
        "findings": [],
    }

    # ==========================================================
    # Step 1: Feeders first (sequential)
    # ==========================================================
    feeders_present = [m for m in FEEDER_MODULES if m in module_names]
    remaining = [m for m in module_names if m not in feeders_present]

    for m_name in feeders_present:
        _, m_data = _execute_module(m_name, config, client, auth_kwargs)
        results["module_results"][m_name] = m_data

        key = FEEDER_KEYS.get(m_name)
        if key and isinstance(m_data, dict) and not m_data.get("error"):
            # === Extract forms → POST test cases (ADDED 2026-09-20) ===
            if m_name == "crawler" and key == "_crawl_result":
                forms = m_data.get("forms", []) or []
                if forms:
                    posts = []
                    get_urls = []
                    for form in forms[:10]:
                        if not isinstance(form, dict):
                            continue
                        action = form.get("action") or config.get("target", "")
                        if not action:
                            continue
                        method = (form.get("method") or "GET").upper()
                        inputs = form.get("inputs", []) or []
                        fields = []
                        for inp in inputs:
                            if not isinstance(inp, dict):
                                continue
                            name = inp.get("name")
                            if not name:
                                continue
                            val = inp.get("value") or "test"
                            fields.append((name, val))

                        if not fields:
                            continue

                        if method == "POST":
                            posts.append({
                                "action": action,
                                "body": "&".join([f"{k}={v}" for k, v in fields]),
                                "fields": [k for k, _ in fields],
                            })
                        else:
                            # GET form → URL with params
                            from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
                            try:
                                p = urlparse(action)
                                existing = parse_qs(p.query, keep_blank_values=True)
                                for k, v in fields:
                                    if k not in existing:
                                        existing[k] = [v]
                                new_q = urlencode({k: v[0] for k, v in existing.items()})
                                url_with_params = urlunparse(p._replace(query=new_q))
                                get_urls.append({
                                    "url": url_with_params,
                                    "fields": [k for k, _ in fields],
                                })
                            except Exception:
                                pass

                    if posts:
                        config["_crawl_forms_post"] = posts
                        log.info(f"  [forms] Extracted {len(posts)} POST form(s)")
                    if get_urls:
                        config["_crawl_forms_get"] = get_urls
                        log.info(f"  [forms] Extracted {len(get_urls)} GET form(s) as URLs")

            # Merge if key already exists
            if key in config and isinstance(config[key], dict):
                merged = config[key]
                for k, v in m_data.items():
                    if k.startswith("_"):
                        continue
                    if k in merged and isinstance(merged[k], list) and isinstance(v, list):
                        merged[k] = merged[k] + v
                    else:
                        merged[k] = v
            else:
                config[key] = m_data
            log.info(f"  [bridge] config['{key}'] <- {m_name} result")

    # ==========================================================
    # Tech-Aware Routing (ADDED 2026-09-19)
    # After tech_fingerprint runs, add relevant modules
    # ==========================================================
    tech_data = results["module_results"].get("tech_fingerprint", {})
    detected_techs = tech_data.get("technologies") or []

    if detected_techs:
        already_run = set(results["module_results"].keys())
        already_run.add("tech_fingerprint")

        # Compute additional modules
        additional, added = _route_modules_by_tech(detected_techs, list(already_run))
        additional = [m for m in additional if m not in already_run]

        if additional and not quiet:
            log.info(f"  [routing] Detected: {', '.join(detected_techs)}")
            log.info(f"  [routing] Auto-adding: {', '.join(additional)}")

        # Run additional modules now
        for m_name in additional:
            _, m_data = _execute_module(m_name, config, client, auth_kwargs)
            results["module_results"][m_name] = m_data

    # ==========================================================
    # Step 2: Remaining modules (parallel or sequential)
    # ==========================================================
    if parallel > 1 and len(remaining) > 1:
        with ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = {executor.submit(_execute_module, m, config, client, auth_kwargs): m
                       for m in remaining}
            for future in as_completed(futures):
                m_name, m_data = future.result()
                results["module_results"][m_name] = m_data
    else:
        for m_name in remaining:
            _, m_data = _execute_module(m_name, config, client, auth_kwargs)
            results["module_results"][m_name] = m_data

    # ==========================================================
    # AI Enrichment (ADDED 2026-09-19)
    # ==========================================================
    if enable_ai:
        try:
            from core.report import extract_findings
            from core.ai_analyzer import (
                _is_available as _ai_available,
                analyze_all_findings,
                generate_executive_summary,
            )

            if _ai_available():
                if not quiet:
                    log.info("[AI] Extracting findings for analysis...")

                findings_for_ai = extract_findings(results)

                if findings_for_ai:
                    if not quiet:
                        log.info(f"[AI] Analyzing up to {ai_max_findings} findings...")

                    enriched = analyze_all_findings(
                        findings_for_ai,
                        max_findings=ai_max_findings,
                        skip_info=True,
                    )

                    results["_ai_enriched"] = enriched

                    try:
                        summary = generate_executive_summary(results, enriched)
                        if summary:
                            results["_ai_summary"] = summary
                            results["ai_summary"] = summary
                            if not quiet:
                                log.info("[AI] Executive summary generated")
                        else:
                            if not quiet:
                                log.warning("[AI] Summary is empty")
                    except Exception as e:
                        log.warning(f"[AI] Executive summary failed: {e}")

                    analyzed = sum(1 for f in enriched if f.get("ai_analyzed"))
                    if not quiet:
                        log.info(f"[AI] Done: {analyzed} findings enriched")
                else:
                    if not quiet:
                        log.info("[AI] No findings to analyze")
            else:
                if not quiet:
                    log.warning("[AI] Not available (no API key configured)")
        except Exception as e:
            log.exception(f"[AI] Enrichment failed: {e}")

    # ==========================================================
    # Persist feeders to results (ADDED 2026-09-20)
    # ==========================================================
    try:
        if "_endpoint_catalog" in config:
            ec = config["_endpoint_catalog"]
            # If dict, store just the endpoints list
            if isinstance(ec, dict):
                results["_endpoint_catalog"] = ec.get("endpoints", [])
            else:
                results["_endpoint_catalog"] = ec
        if "_discovered_params" in config:
            results["_discovered_params"] = config["_discovered_params"]
        if "_discovered_endpoints" in config:
            results["_discovered_endpoints"] = config["_discovered_endpoints"]
        if "_crawl_result" in config and isinstance(config["_crawl_result"], dict):
            crawl = config["_crawl_result"]
            results["_crawl_summary"] = {
                "pages": len(crawl.get("pages", []) or []),
                "forms": len(crawl.get("forms", []) or []),
                "js_files": len(crawl.get("js_files", []) or []),
                "xhr": len(crawl.get("xhr_requests", []) or []),
            }
        if not quiet:
            ec = results.get("_endpoint_catalog", [])
            log.info(f"  [persist] Saved {len(ec)} endpoints to results")
    except Exception as _e:
        log.debug(f"  [persist] failed: {_e}")
    # ==========================================================

    # ==========================================================
    # Reports
    # ==========================================================
    total_elapsed = time.time() - start_time

    # ==========================================================
    # Fill report metadata (ADDED 2026-09-19)
    # ==========================================================
    results["timestamp"] = results.get("scan_date", datetime.now(timezone.utc).isoformat())
    results["duration"] = round(total_elapsed, 2)
    results["modules_run"] = list(results.get("module_results", {}).keys())
    try:
        results["http_requests_count"] = len(client.history)
    except Exception:
        results["http_requests_count"] = 0

    report_config = config
    if output_override:
        if not isinstance(report_config, dict):
            report_config = {}
        report_config.setdefault("output", {})["directory"] = output_override

    try:
        generate_reports(results, report_config)
    except Exception as e:
        log.exception(f"Report generation failed: {e}")

    if not quiet:
        _print_summary_table(results, total_elapsed)

    return results


# ============================================================
# Commands
# ============================================================
@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL (e.g. https://example.com)"),
    modules: str = typer.Option(None, "--modules", "-m", help="Comma-separated module names."),
    all_modules: bool = typer.Option(False, "--all", "-a", help="Enable ALL modules."),
    config: str = typer.Option(None, "--config", "-c", help="Path to config.yaml."),
    output: str = typer.Option(None, "--output", "-o", help="Output directory override."),
    json_out: bool = typer.Option(False, "--json", help="Print final JSON to stdout."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
    login_url: str = typer.Option(None, "--login-url", help="Login URL for authenticated scans."),
    username: str = typer.Option(None, "--username", "-u", help="Username for login."),
    password: str = typer.Option(None, "--password", "-p", help="Password for login."),
    bearer_token: str = typer.Option(None, "--bearer-token", help="Bearer token for API auth."),
    cookie: str = typer.Option(None, "--cookie", help="Manual cookie string."),
    cookie_file: str = typer.Option(None, "--cookie-file", help="JSON file with cookies."),
    cookies: str = typer.Option(None, "--cookies", help="Netscape-format cookie file."),
    method: str = typer.Option("GET", "--method", "-X", help="HTTP method."),
    post_data: str = typer.Option(None, "--post-data", help="POST body (form-encoded)."),
    post_json: str = typer.Option(None, "--post-json", help="POST body as JSON."),
    header: str = typer.Option(None, "--header", "-H", help="Extra headers, separated by ';'."),
    parallel: int = typer.Option(1, "--parallel", "-j", help="Number of parallel workers."),
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Skip SSL verification."),
    profile: str = typer.Option(None, "--profile", "-P", help="Use saved login profile."),
    totp_secret: str = typer.Option(None, "--totp-secret", help="TOTP secret (base32) for 2FA."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI analysis after scan."),
    ai_max: int = typer.Option(20, "--ai-max", help="Max findings to analyze with AI (default: 20)."),
    mode: str = typer.Option(
        "normal", "--mode",
        help="Scan mode: fast | normal | deep | ultra | custom",
    ),
    focus: str = typer.Option(
        None, "--focus",
        help="Vuln focus for custom mode (e.g. xss,sqli,ssrf,idor). Use with --mode custom.",
    ),
    max_pages: int = typer.Option(
        30, "--max-pages",
        help="Max pages for crawler (default: 30).",
    ),
    crawl_depth: int = typer.Option(
        2, "--crawl-depth",
        help="Max crawl depth (default: 2).",
    ),
):
    """Run a security scan against TARGET."""
    # === MODE RESOLUTION (ADDED 2026-09-20) ===
    focus_list = []
    if focus:
        focus_list = [f.strip().lower() for f in focus.split(",") if f.strip()]

    # Check if mode is valid
    if mode not in MODE_PRESETS:
        console.print(f"[yellow]Unknown mode '{mode}' — using 'normal'[/yellow]")
        mode = "normal"

    explicit_modules = None
    if modules:
        explicit_modules = [m.strip() for m in modules.split(",") if m.strip()]

    # Resolve module list
    module_list = _resolve_modules_from_mode(mode, focus_list, explicit_modules)

    # Show mode banner
    if not quiet:
        count = len(module_list) if module_list else 39
        _print_mode_banner(mode, focus_list, count)

    # If module_list is None (ultra/all), set all_modules=True
    if module_list is None:
        all_modules = True
        module_list = None
    # === END MODE RESOLUTION ===

    # ---- Auth kwargs ----
    auth_kwargs = {}
    if login_url:
        auth_kwargs["login_url"] = login_url
    if username:
        auth_kwargs["username"] = username
    if password:
        auth_kwargs["password"] = password
    if bearer_token:
        auth_kwargs["bearer_token"] = bearer_token
    if cookie:
        auth_kwargs["manual_cookie"] = cookie

    # JSON cookie file
    if cookie_file:
        from core.cookie_loader import load_cookie_json
        cookies_str = load_cookie_json(cookie_file)
        if cookies_str:
            auth_kwargs["manual_cookie"] = cookies_str
            log.info(f"Loaded cookies from JSON: {cookie_file}")
        else:
            console.print(f"[red]Failed to load cookie file: {cookie_file}[/red]")
            raise typer.Exit(1)

    # Netscape cookie file
    if cookies:
        from core.cookie_loader import load_cookie_netscape
        cookies_str = load_cookie_netscape(cookies)
        if cookies_str:
            auth_kwargs["manual_cookie"] = cookies_str
            log.info(f"Loaded cookies from Netscape: {cookies}")
        else:
            console.print(f"[red]Failed to load Netscape cookie file: {cookies}[/red]")
            raise typer.Exit(1)

    # Playwright profile
    if profile and HAS_AUTH_EXTENSIONS:
        profile_data = load_profile(profile)
        if not profile_data:
            console.print(f"[red]Profile '{profile}' not found. Run: python cli.py login URL -u USER -p PASS -P {profile}[/red]")
            raise typer.Exit(1)
        p_cookies = profile_data.get("cookies", [])
        cookie_str = "; ".join(
            f"{c['name']}={c['value']}"
            for c in p_cookies
            if c.get("name") and c.get("value")
        )
        if cookie_str:
            auth_kwargs["manual_cookie"] = cookie_str
            log.info(f"Loaded profile '{profile}' ({len(p_cookies)} cookies)")

    # TOTP
    if totp_secret and HAS_AUTH_EXTENSIONS:
        otp_code = generate_totp(totp_secret)
        if otp_code:
            auth_kwargs["totp_code"] = otp_code
            log.info(f"Generated TOTP: {otp_code}")

    # ---- HTTP kwargs ----
    http_kwargs = {}
    if insecure:
        http_kwargs["_insecure"] = True
        log.info("SSL verification DISABLED (--insecure)")
    if method and method != "GET":
        http_kwargs["method"] = method
    if post_data:
        http_kwargs["post_data"] = post_data
    if post_json:
        http_kwargs["post_json"] = post_json
    if header:
        headers = {}
        for h in header.split(";"):
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        if headers:
            http_kwargs["extra_headers"] = headers

    # Compute mode-specific AI max
    try:
        _preset = MODE_PRESETS.get(mode, {})
        _mode_ai_max = _preset.get("max_findings_ai", ai_max)
        if ai_max == 20:  # user did not override
            ai_max = _mode_ai_max
        if mode == "fast" and not no_ai:
            # In fast mode, keep AI for top findings only
            ai_max = min(ai_max, 5)
    except Exception:
        pass

    results = _run_scan(
        target=target,
        module_names=module_list,
        config_path=config,
        output_override=output,
        quiet=quiet,
        auth_kwargs=auth_kwargs if auth_kwargs else None,
        http_kwargs=http_kwargs if http_kwargs else None,
        parallel=parallel,
        enable_ai=not no_ai,
        ai_max_findings=ai_max,
        scan_mode=mode,
        max_pages=max_pages,
        crawl_depth=crawl_depth,
    )

    if json_out:
        console.print_json(data=results)


@app.command(name="list")
def list_modules():
    """List all available modules."""
    table = Table(title="Available Modules", box=box.ROUNDED, title_style="bold red")
    table.add_column("#", style="dim", width=4)
    table.add_column("Module", style="cyan")
    table.add_column("Status", style="green")

    for i, name in enumerate(MODULE_REGISTRY.keys(), 1):
        try:
            _load_module_fn(name)
            status = "[green]ready[/green]"
        except Exception:
            status = "[red]missing[/red]"
        table.add_row(str(i), name, status)

    console.print(table)
    console.print(f"\n[bold]Total:[/bold] {len(MODULE_REGISTRY)} modules")


@app.command()
def test(
    target: str = typer.Option("https://httpbin.org", "--target", "-t", help="Safe test target."),
):
    """Quick smoke test on a known-safe target."""
    console.print(f"[yellow]Smoke test on {target}[/yellow]")
    _run_scan(
        target=target,
        module_names=["fingerprint", "headers_check", "path_discovery"],
        quiet=False,
    )


@app.command()
def version():
    """Print version."""
    console.print("[bold red]Falcon MAG Framework[/bold red] v2.0-snapshot")
    console.print("Security Assessment CLI")


@app.command()
def login(
    url: str = typer.Argument(..., help="Login page URL"),
    auth_type: str = typer.Option(
        "auto", "--auth-type", "-A",
        help="auto | basic | oauth | saml | nafath",
    ),
    username: str = typer.Option(None, "--username", "-u", help="Username/email (basic)."),
    password: str = typer.Option(None, "--password", "-p", help="Password (basic)."),
    totp_secret: str = typer.Option(None, "--totp-secret", help="TOTP base32 secret."),
    button_selector: str = typer.Option(
        None, "--button-selector", "--nafath-selector",
        help="CSS selector for the SSO / Nafath button.",
    ),
    otp_selector: str = typer.Option(None, "--otp-selector", help="OTP input selector (basic)."),
    profile: str = typer.Option("default", "--profile", "-P", help="Profile name."),
    wait: int = typer.Option(240, "--wait", "-w", help="Seconds to wait for manual approval. Use 0 for open-ended interactive (press ENTER to save)."),
    headless: bool = typer.Option(False, "--headless", help="Hide browser (not recommended)."),
    success_url: str = typer.Option(
        None, "--success-url",
        help="Substring expected in the URL after successful login.",
    ),
):
    """Login to any site: basic / oauth / saml / nafath (auto-detected)."""
    if not HAS_GENERIC_AUTH:
        console.print("[red]Generic auth not available. Check core/auth/[/red]")
        raise typer.Exit(1)

    console.print(Panel.fit(
        f"[bold cyan]Login[/bold cyan]\n"
        f"  URL:       [yellow]{url}[/yellow]\n"
        f"  Type:      [magenta]{auth_type}[/magenta]\n"
        f"  Profile:   [green]{profile}[/green]\n"
        f"  Wait:      {wait}s",
        border_style="cyan",
    ))

    kwargs = {}
    if username:
        kwargs["username"] = username
    if password:
        kwargs["password"] = password
    if totp_secret:
        kwargs["totp_secret"] = totp_secret
    if button_selector:
        kwargs["nafath_selector"] = button_selector
        kwargs["button_selector"] = button_selector
    if otp_selector:
        kwargs["otp_selector"] = otp_selector
    if success_url:
        kwargs["success_url_contains"] = success_url

    try:
        profile_file = generic_login(
            auth_type=auth_type,
            url=url,
            profile=profile,
            headless=headless,
            wait_seconds=wait,
            **kwargs,
        )
        console.print()
        console.print(Panel.fit(
            f"[bold green]Session saved![/bold green]\n\n"
            f"  Profile: [cyan]{profile}[/cyan]\n"
            f"  File:    [dim]{profile_file}[/dim]\n\n"
            f"[bold]Next:[/bold]\n"
            f"  python cli.py scan {url} --profile {profile} --all",
            border_style="green",
        ))
    except Exception as e:
        console.print(f"[red]Login failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def profiles():
    """List all saved login profiles."""
    if not HAS_AUTH_EXTENSIONS:
        console.print("[red]Auth extensions not available.[/red]")
        raise typer.Exit(1)

    names = list_profiles()
    if not names:
        console.print("[yellow]No profiles yet.[/yellow]")
        return

    table = Table(title="Saved Login Profiles", box=box.ROUNDED)
    table.add_column("#", style="dim", width=4)
    table.add_column("Profile", style="cyan")
    table.add_column("File", style="dim")
    for i, name in enumerate(names, 1):
        table.add_row(str(i), name, f"profiles/{name}.json")
    console.print(table)


@app.command()
def totp(
    secret: str = typer.Argument(..., help="TOTP secret (base32)"),
):
    """Generate a TOTP code from a secret."""
    if not HAS_AUTH_EXTENSIONS:
        console.print("[red]Auth extensions not available.[/red]")
        raise typer.Exit(1)

    if not verify_secret(secret):
        console.print(f"[red]Invalid TOTP secret: {secret}[/red]")
        raise typer.Exit(1)

    code = generate_totp(secret)
    console.print(Panel.fit(
        f"[bold green]TOTP Code: [yellow]{code}[/yellow][/bold green]\n"
        f"[dim]Valid for 30 seconds[/dim]",
        border_style="green",
    ))


@app.command(name="auth-types")
def list_auth_types():
    """List available authentication handlers."""
    if not HAS_GENERIC_AUTH:
        console.print("[red]Generic auth not available.[/red]")
        return
    table = Table(title="Available Auth Handlers", box=box.ROUNDED)
    table.add_column("#", style="dim", width=4)
    table.add_column("Type", style="cyan")
    table.add_column("Description", style="white")
    desc = {
        "basic":  "username + password (+ OTP/TOTP)",
        "oauth":  "OAuth2 / OIDC / 'Sign in with X'",
        "saml":   "SAML 2.0 SSO",
        "nafath": "Saudi National SSO (Nafath)",
    }
    for i, name in enumerate(auth_available(), 1):
        table.add_row(str(i), name, desc.get(name, ""))
    console.print(table)


@app.command()
def triage(
    scan_file: str = typer.Argument(..., help="Path to scan JSON file (or 'latest')."),
    max_findings: int = typer.Option(30, "--max", help="Max findings to triage."),
):
    """AI-triage findings from a previous scan."""
    import json as _json
    from pathlib import Path as _Path

    # Resolve file
    if scan_file == "latest":
        out_dir = FRAMEWORK_DIR / "output"
        jsons = sorted(out_dir.glob("scan_*.json"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        if not jsons:
            console.print("[red]No scan files found[/red]")
            raise typer.Exit(1)
        scan_file = str(jsons[0])

    path = _Path(scan_file)
    if not path.exists():
        console.print(f"[red]File not found: {scan_file}[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Loading {path.name}...[/cyan]")
    data = _json.loads(path.read_text(encoding="utf-8"))
    findings = data.get("_ai_enriched") or data.get("findings") or []
    console.print(f"[cyan]Findings: {len(findings)}[/cyan]")

    from modules.ai_triage import run as triage_run
    result = triage_run(None, {}, findings=findings, max_findings=max_findings)

    # Save
    out_path = path.with_name(path.stem + "_triage.json")
    out_path.write_text(_json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    console.print(f"[green]Saved: {out_path}[/green]")

    # Print top 10
    console.print()
    console.print("[bold]Top findings by exploitability:[/bold]")
    for i, f in enumerate(result["items"][:10], 1):
        t = f.get("_triage", {})
        worthy = "[green]★[/green]" if t.get("bugbounty_worthy") else " "
        console.print(
            f"  {i:2d}. {worthy} "
            f"[yellow]{t.get('exploitability_score',0):3d}[/yellow] | "
            f"[magenta]{t.get('real_cvss',0):.1f}[/magenta] | "
            f"{f.get('title','')[:70]}"
        )


def main():
    app()


if __name__ == "__main__":
    main()
