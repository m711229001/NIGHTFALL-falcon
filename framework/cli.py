"""Falcon MAG Framework - Unified CLI Entry Point"""
import sys
import time
import json
from datetime import datetime
from pathlib import Path

import typer
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

# Add framework dir to path so `import core` works
FRAMEWORK_DIR = Path(__file__).resolve().parent
if str(FRAMEWORK_DIR) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_DIR))

from core.config import (  # noqa: E402
    load_config, apply_target, apply_modules,
    enable_all_modules, get_enabled_modules,
)
from core.http_client import HTTPClient  # noqa: E402
from core.report import generate_reports  # noqa: E402
from core.logger import get_logger  # noqa: E402

log = get_logger("cli")
console = Console()


# ============================================================
# Module registry (name -> (import_path, run_func_name))
# ============================================================
MODULE_REGISTRY = {
    # Phase 1
    "fingerprint":       ("modules.fingerprint", "run"),
    "headers_check":     ("modules.headers_check", "run"),
    "crawler":           ("modules.crawler", "run"),
    "js_analyzer":       ("modules.js_analyzer", "run"),
    "path_discovery":    ("modules.path_discovery", "run"),
    "catch_all_detector": ("modules.catch_all_detector", "run"),
    "js_endpoints":        ("modules.js_endpoints", "run"),
    "js_secrets":          ("modules.js_secrets", "run"),
    "dom_xss_scanner":     ("modules.dom_xss_scanner", "run"),
    "external_nmap":       ("modules.external_nmap", "run"),
    "external_testssl":    ("modules.external_testssl", "run"),
    "external_subfinder":  ("modules.external_subfinder", "run"),
    "external_searchsploit":("modules.external_searchsploit", "run"),
    "playwright_crawler":  ("modules.playwright_crawler", "run"),
    # Phase 2
    "xss_scanner":       ("modules.xss_scanner", "run"),
    "sqli_scanner":      ("modules.sqli_scanner", "run"),
    "nosql_scanner":     ("modules.nosql_scanner", "run"),
    "csrf_checker":      ("modules.csrf_checker", "run"),
    "clickjacking":      ("modules.clickjacking", "run"),
    "path_traversal":    ("modules.path_traversal", "run"),
    "ssrf_scanner":      ("modules.ssrf_scanner", "run"),
    "idor_scanner":      ("modules.idor_scanner", "run"),
    "open_redirect":     ("modules.open_redirect", "run"),
    "prototype_pollution": ("modules.prototype_pollution", "run"),
    # Phase 3
    "tls_checker":       ("modules.tls_checker", "run"),
    "port_scanner":      ("modules.port_scanner", "run"),
    "cors_checker":      ("modules.cors_checker", "run"),
    "http_methods":      ("modules.http_methods", "run"),
    "cookies_checker":   ("modules.cookies_checker", "run"),
    "rate_limit_test":   ("modules.rate_limit_test", "run"),
    "subdomain_enum":    ("modules.subdomain_enum", "run"),
    "cve_lookup":        ("modules.cve_lookup", "run"),
}


app = typer.Typer(
    name="falcon",
    help="🦅 Falcon MAG Framework — Security Assessment CLI",
    add_completion=False,
    rich_markup_mode="rich",
)


# ============================================================
# Helpers
# ============================================================
def _load_module(name: str):
    """Dynamically import a module and return its run() function."""
    if name not in MODULE_REGISTRY:
        raise ValueError(f"Unknown module: {name}")
    import_path, func_name = MODULE_REGISTRY[name]
    try:
        mod = __import__(import_path, fromlist=[func_name])
    except ImportError as e:
        raise ImportError(f"Cannot import {import_path}: {e}")
    fn = getattr(mod, func_name, None)
    if not callable(fn):
        raise AttributeError(f"{import_path} has no callable '{func_name}'")
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
    """Count findings in a module's result — handles list and bool schemas."""
    if not isinstance(data, dict):
        return 0

    count = 0

    # List-style keys
    for key in ("vulnerable", "real_paths", "open_ports", "secrets",
                "vulnerable_forms", "weak_protocols",
                "found", "cves", "dangerous", "insecure"):
        val = data.get(key)
        if isinstance(val, list):
            count += len(val)

    # Boolean-style keys
    for key in ("vulnerable",):
        val = data.get(key)
        if isinstance(val, bool) and val:
            count += 1

    return count


def _count_findings(data: dict) -> int:
    """Count findings in a module's result — handles list and bool schemas."""
    if not isinstance(data, dict):
        return 0

    count = 0

    # List-style keys
    for key in ("vulnerable", "real_paths", "open_ports", "secrets",
                "vulnerable_forms", "weak_protocols",
                "found", "cves", "dangerous", "insecure"):
        val = data.get(key)
        if isinstance(val, list):
            count += len(val)

    # Boolean-style keys
    for key in ("vulnerable",):
        val = data.get(key)
        if isinstance(val, bool) and val:
            count += 1

    return count


def _count_findings(data: dict) -> int:
    """Count findings in a module's result — handles list and bool schemas."""
    if not isinstance(data, dict):
        return 0

    count = 0

    # List-style keys
    for key in ("vulnerable", "real_paths", "open_ports", "secrets",
                "vulnerable_forms", "weak_protocols",
                "found", "cves", "dangerous", "insecure"):
        val = data.get(key)
        if isinstance(val, list):
            count += len(val)

    # Boolean-style keys
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


def _run_scan(target: str, module_names: list, config_path: str = None,
              output_override: str = None, quiet: bool = False,
              auth_kwargs: dict = None, http_kwargs: dict = None,
              parallel: int = 1):
    """Core scan runner."""
    # 1. Load config
    cfg = load_config(config_path) if config_path else load_config()
    cfg = apply_target(cfg, target)
    cfg = apply_modules(cfg, ",".join(module_names))

    # sanity
    if "scan" not in cfg:
        cfg["scan"] = {}
    cfg["scan"].setdefault("verify_ssl", False)
    cfg["scan"].setdefault("timeout", 10)
    cfg["exclude"] = []  # don't skip anything for now

    if output_override:
        cfg.setdefault("output", {})["directory"] = output_override

    # 2. Banner
    if not quiet:
        _print_banner(target, module_names)

    # 3. HTTP client
    client = HTTPClient(cfg)

    # 3.5 Authentication (if requested)
    if auth_kwargs and any(auth_kwargs.values()):
        try:
            from core.auth import AuthSession
            auth = AuthSession(**auth_kwargs)
            if not quiet:
                console.print("[bold yellow]\U0001f510 Authenticating...[/bold yellow]")
            if auth.login(client):
                if not quiet:
                    console.print("[bold green]   \u2713 Logged in[/bold green]")
            else:
                if not quiet:
                    console.print("[bold yellow]   \u26a0 Login failed, continuing unauthenticated[/bold yellow]")
        except Exception as e:
            log.warning("Auth error: " + str(e))

    # 3.6 HTTP method / body overrides
    if http_kwargs:
        cfg["_http_method"] = http_kwargs.get("method", "GET")
        cfg["_post_data"] = http_kwargs.get("post_data", "")
        cfg["_post_json"] = http_kwargs.get("post_json", "")
        extra_header = http_kwargs.get("extra_header", "")
        if extra_header:
            # Parse "X-A: 1; X-B: 2" format
            for hdr in extra_header.split(";"):
                hdr = hdr.strip()
                if not hdr or ":" not in hdr:
                    continue
                k, v = hdr.split(":", 1)
                client.session.headers[k.strip()] = v.strip()
                if not quiet:
                    console.print("[dim]   + Header: " + k.strip() + "[/dim]")
        if cfg.get("_http_method") != "GET":
            if not quiet:
                console.print("[dim]   + Method: " + cfg["_http_method"] + "[/dim]")
        if cfg.get("_post_data"):
            if not quiet:
                console.print("[dim]   + POST data: " + cfg["_post_data"][:60] + "[/dim]")
        if cfg.get("_post_json"):
            if not quiet:
                console.print("[dim]   + POST JSON: " + cfg["_post_json"][:60] + "[/dim]")

    # 4. Run modules
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "modules_run": module_names,
        "module_results": {},
    }

    enabled = get_enabled_modules(cfg)
    start = time.time()

    fingerprint_data = {}
    crawl_data = {}

    # Split modules: some must run first (dependencies)
    FIRST_WAVE = {"fingerprint", "headers_check", "crawler", "catch_all_detector"}

    first_wave_modules = [m for m in module_names if m in FIRST_WAVE]
    second_wave_modules = [m for m in module_names if m not in FIRST_WAVE]

    def run_one(name, client, cfg, crawl_data, quiet):
        """Run a single module and return (name, data, elapsed)."""
        t0 = time.time()
        try:
            fn = _load_module(name)
            if name in ("xss_scanner", "csrf_checker", "idor_scanner",
                        "js_analyzer", "js_endpoints", "js_secrets",
                        "dom_xss_scanner"):
                try:
                    data = fn(client, cfg, crawl_result=crawl_data)
                except TypeError:
                    data = fn(client, cfg)
            else:
                data = fn(client, cfg)

            if not isinstance(data, dict):
                data = {"result": data}
            elapsed = round(time.time() - t0, 2)
            data["_elapsed"] = elapsed
            return (name, data, elapsed, None)
        except Exception as e:
            elapsed = round(time.time() - t0, 2)
            return (name, {"error": str(e), "_elapsed": elapsed}, elapsed, str(e))

    # --- Wave 1: sequential (dependencies) ---
    for name in first_wave_modules:
        if name not in enabled:
            results["module_results"][name] = {"skipped": True}
            continue
        if not quiet:
            console.print(f"[bold cyan]\u25b6 Running[/bold cyan] [yellow]{name}[/yellow]...")
        name_r, data, elapsed, err = run_one(name, client, cfg, crawl_data, quiet)
        results["module_results"][name] = data
        results[name] = data
        if name == "fingerprint" and isinstance(data, dict):
            cfg["_fingerprint"] = data
            fingerprint_data = data
        if name == "crawler" and isinstance(data, dict):
            crawl_data = data
        if not quiet and not err:
            console.print(f"  [green]\u2713[/green] {name} done in {elapsed}s")
        elif not quiet and err:
            console.print(f"  [red]\u2717[/red] {name} FAILED: {err}")

    # --- Wave 2: parallel (or sequential if parallel=1) ---
    if parallel > 1 and len(second_wave_modules) > 1:
        if not quiet:
            console.print(f"[bold magenta]\u26a1 Running {len(second_wave_modules)} modules with {parallel} workers[/bold magenta]...")

        with ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = {}
            for name in second_wave_modules:
                if name not in enabled:
                    results["module_results"][name] = {"skipped": True}
                    continue
                futures[executor.submit(run_one, name, client, cfg, crawl_data, True)] = name

            for future in as_completed(futures):
                name_r, data, elapsed, err = future.result()
                results["module_results"][name_r] = data
                results[name_r] = data
                if not quiet:
                    if err:
                        console.print(f"  [red]\u2717[/red] {name_r} FAILED: {err}")
                    else:
                        console.print(f"  [green]\u2713[/green] {name_r} done in {elapsed}s")
    else:
        # Sequential fallback
        for name in second_wave_modules:
            if name not in enabled:
                results["module_results"][name] = {"skipped": True}
                continue
            if not quiet:
                console.print(f"[bold cyan]\u25b6 Running[/bold cyan] [yellow]{name}[/yellow]...")
            name_r, data, elapsed, err = run_one(name, client, cfg, crawl_data, quiet)
            results["module_results"][name_r] = data
            results[name_r] = data
            if not quiet and not err:
                console.print(f"  [green]\u2713[/green] {name_r} done in {elapsed}s")
            elif not quiet and err:
                console.print(f"  [red]\u2717[/red] {name_r} FAILED: {err}")

    # === Skip the old loop ===
    for name in []:
        if name not in enabled:
            log.debug(f"Skipping disabled module: {name}")
            results["module_results"][name] = {"skipped": True}
            continue

        if not quiet:
            console.print(f"[bold cyan]▶ Running[/bold cyan] [yellow]{name}[/yellow]...")

        t0 = time.time()
        try:
            fn = _load_module(name)

            # Pass crawl_result to modules that accept it
            if name in ("xss_scanner", "csrf_checker", "idor_scanner", "js_analyzer", "js_endpoints", "js_secrets", "dom_xss_scanner"):
                try:
                    data = fn(client, cfg, crawl_result=crawl_data)
                except TypeError:
                    data = fn(client, cfg)
            else:
                data = fn(client, cfg)

            # Cache for later modules
            if name == "fingerprint" and isinstance(data, dict):
                cfg["_fingerprint"] = data
                fingerprint_data = data
            if name == "crawler" and isinstance(data, dict):
                crawl_data = data
            if not isinstance(data, dict):
                data = {"result": data}
            data["_elapsed"] = round(time.time() - t0, 2)
            results["module_results"][name] = data

            # Mirror into top-level keys so report.extract_findings() finds them
            results[name] = data

            if not quiet:
                console.print(f"  [green]✓[/green] {name} done in {data['_elapsed']}s")
        except Exception as e:
            elapsed = round(time.time() - t0, 2)
            log.error(f"Module {name} failed: {e}")
            results["module_results"][name] = {
                "error": str(e), "_elapsed": elapsed,
            }
            results[name] = {"error": str(e)}
            if not quiet:
                console.print(f"  [red]✗[/red] {name} FAILED: {e}")

    elapsed = time.time() - start
    results["duration"] = round(elapsed, 2)
    results["http_requests_count"] = len(client.history)

    # 4.5 AI Analysis (if enabled)
    if cfg.get("ai", {}).get("enabled", True):
        try:
            from core.ai_analyzer import _is_available, analyze_all_findings, generate_executive_summary
            if _is_available():
                if not quiet:
                    console.print()
                    console.print("[bold magenta]🤖 AI Analysis (DeepSeek)...[/bold magenta]")
                all_findings_flat = []
                for name in module_names:
                    data = results.get(name, {})
                    if not isinstance(data, dict):
                        continue
                    for v in (data.get("vulnerable", []) or []):
                        if isinstance(v, dict):
                            all_findings_flat.append(v)
                if all_findings_flat:
                    enriched = analyze_all_findings(all_findings_flat, max_findings=15)
                    results["_ai_enriched"] = enriched
                    summary = generate_executive_summary(results, all_findings_flat)
                    results["_ai_summary"] = summary
                    if not quiet and summary:
                        console.print()
                        console.print(Panel(summary, title="📋 Executive Summary (AI)", border_style="magenta"))
        except Exception as e:
            log.warning("AI analysis failed: " + str(e))

    # 5. Reports
    try:
        paths = generate_reports(results, cfg)
        results["report_paths"] = paths
        if not quiet:
            console.print()
            console.print(Panel.fit(
                "[bold green]Reports generated:[/bold green]\n" +
                "\n".join(f"  [cyan]{k}[/cyan]: {v}" for k, v in paths.items()),
                border_style="green",
            ))
    except Exception as e:
        log.error(f"Report generation failed: {e}")

    # 6. Summary
    if not quiet:
        console.print()
        _print_summary_table(results, elapsed)

    return results


# ============================================================
# Commands
# ============================================================
@app.command("scan")
def scan_cmd(
    target: str = typer.Argument(..., help="Target URL (e.g. https://example.com)"),
    modules: str = typer.Option(
        None, "--modules", "-m",
        help="Comma-separated module names. Default: all enabled in config.",
    ),
    all_modules: bool = typer.Option(
        False, "--all", "-a", help="Enable ALL modules.",
    ),
    config: str = typer.Option(
        None, "--config", "-c", help="Path to config.yaml.",
    ),
    output: str = typer.Option(
        None, "--output", "-o", help="Output directory override.",
    ),
    json_out: bool = typer.Option(
        False, "--json", help="Print final JSON to stdout.",
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress progress output.",
    ),
    # ---- Authentication ----
    login_url: str = typer.Option(
        None, "--login-url", help="Login URL for authenticated scans.",
    ),
    username: str = typer.Option(
        None, "--username", "-u", help="Username for login.",
    ),
    password: str = typer.Option(
        None, "--password", "-p", help="Password for login.",
    ),
    bearer_token: str = typer.Option(
        None, "--bearer-token", help="Bearer token for API auth.",
    ),
    cookie: str = typer.Option(
        None, "--cookie", help="Manual cookie string (e.g. 'session=abc; xyz=1').",
    ),
    # ---- HTTP Method / Body ----
    method: str = typer.Option(
        "GET", "--method", "-X", help="HTTP method (GET/POST/PUT/etc).",
    ),
    post_data: str = typer.Option(
        None, "--post-data", help="POST body (form-encoded: 'a=1&b=2').",
    ),
    post_json: str = typer.Option(
        None, "--post-json", help="POST body as JSON (e.g. {\"a\":1}).",
    ),
    header: str = typer.Option(
        None, "--header", "-H", help="Extra headers, separated by ';' (e.g. 'X-A: 1; X-B: 2').",
    ),
    parallel: int = typer.Option(
        1, "--parallel", "-j", help="Number of parallel workers (1=sequential).",
    ),
):
    """Run a security scan against TARGET."""
    if all_modules:
        module_names = list(MODULE_REGISTRY.keys())
    elif modules:
        module_names = [m.strip() for m in modules.split(",") if m.strip()]
    else:
        cfg = load_config(config) if config else load_config()
        module_names = get_enabled_modules(cfg)
        if not module_names:
            module_names = ["fingerprint", "headers_check"]

    # validate
    unknown = [m for m in module_names if m not in MODULE_REGISTRY]
    if unknown:
        console.print(f"[red]Unknown modules:[/red] {', '.join(unknown)}")
        console.print(f"[dim]Available:[/dim] {', '.join(MODULE_REGISTRY.keys())}")
        raise typer.Exit(code=1)

    auth_kwargs = {
        "login_url": login_url or "",
        "username": username or "",
        "password": password or "",
        "bearer_token": bearer_token or "",
        "manual_cookie": cookie or "",
    }

    http_kwargs = {
        "method": (method or "GET").upper(),
        "post_data": post_data or "",
        "post_json": post_json or "",
        "extra_header": header or "",
    }

    results = _run_scan(target, module_names, config, output, quiet,
                        auth_kwargs=auth_kwargs, http_kwargs=http_kwargs,
                        parallel=parallel)

    if json_out:
        console.print_json(json.dumps(results, ensure_ascii=False, default=str))

    # exit code based on findings
    n = len(results.get("findings", []))
    raise typer.Exit(code=1 if n > 0 else 0)


@app.command("list")
def list_cmd():
    """List all available modules."""
    table = Table(title="🦅 Available Modules", box=box.ROUNDED)
    table.add_column("#", style="dim", justify="right")
    table.add_column("Module", style="cyan")
    table.add_column("Status", style="green")

    for i, name in enumerate(MODULE_REGISTRY.keys(), 1):
        try:
            _load_module(name)
            status = "[green]✓ ready[/green]"
        except Exception as e:
            status = f"[red]✗ {type(e).__name__}[/red]"
        table.add_row(str(i), name, status)

    console.print(table)


@app.command("test")
def test_cmd(
    target: str = typer.Option("https://httpbin.org", "--target", "-t"),
):
    """Quick smoke test on a known-safe target."""
    console.print(f"[yellow]Smoke test on {target}[/yellow]")
    results = _run_scan(
        target,
        ["fingerprint", "headers_check", "path_discovery"],
        quiet=False,
    )
    return results


@app.command("version")
def version_cmd():
    """Print version."""
    console.print("[bold red]Falcon MAG Framework[/bold red] v2.0.0")

# -*- coding: utf-8 -*-
"""Patch: create modules/cors_checker.py"""

CORS_CHECKER = '''"""Falcon MAG Framework - CORS Misconfiguration Checker

Tests the target for common CORS misconfigurations:
  - Arbitrary Origin reflected in Access-Control-Allow-Origin
  - Wildcard ACAO combined with credentials
  - Null origin accepted
  - Subdomain prefix/suffix bypass

Returns findings in unified schema: {"vulnerable": [ ... ]}
"""

from urllib.parse import urlparse
from core.logger import get_logger

log = get_logger("cors")


# Evil origins to test
EVIL_ORIGINS = [
    "https://evil.example.com",
    "null",
    "https://attacker.com",
]


def _extract_origin(target: str) -> str:
    """Return scheme://host from target (for subdomain tests)."""
    p = urlparse(target)
    if not p.hostname:
        return ""
    return f"{p.scheme}://{p.hostname}"


def _build_subdomain_origin(target: str) -> str:
    """Return scheme://evil.<hostname> for subdomain bypass tests."""
    p = urlparse(target)
    if not p.hostname:
        return ""
    return f"{p.scheme}://evil.{p.hostname}"


def run(client, config) -> dict:
    """Run CORS misconfiguration check."""
    target = config.get("target", "")
    if not target:
        return {"error": "No target"}

    log.info(f"CORS check on {target}")

    result = {
        "target": target,
        "url": target,
        "tests": [],
        "vulnerable": [],
    }

    # Build list of origins to test
    real_origin = _extract_origin(target)
    subdomain_origin = _build_subdomain_origin(target)

    origins_to_test = list(EVIL_ORIGINS)
    if subdomain_origin and subdomain_origin not in origins_to_test:
        origins_to_test.append(subdomain_origin)

    # Baseline (no Origin header)
    baseline = client.get(target, headers={"Origin": real_origin})
    if not baseline or baseline.status == 0:
        log.warning(f"  Baseline failed: {baseline.error if baseline else 'no response'}")
        result["error"] = "baseline failed"
        return result

    baseline_acao = baseline.headers.get("Access-Control-Allow-Origin")
    baseline_acac = baseline.headers.get("Access-Control-Allow-Credentials")
    result["baseline"] = {
        "acao": baseline_acao,
        "acac": baseline_acac,
    }

    # Test each evil origin
    for origin in origins_to_test:
        resp = client.get(target, headers={"Origin": origin})
        if not resp or resp.status == 0:
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")
        vary = resp.headers.get("Vary", "")

        test_entry = {
            "origin": origin,
            "status": resp.status,
            "acao": acao,
            "acac": acac,
            "vary": vary,
        }

        # ---- Verdict ----
        is_vulnerable = False
        reason = ""

        if acao and acac and acac.lower() == "true":
            # Case A: exact origin reflected + credentials
            if acao == origin and origin != real_origin:
                is_vulnerable = True
                reason = f"Origin '{origin}' reflected with credentials=true"

            # Case B: wildcard + credentials (invalid but misconfigured)
            elif acao == "*" and acac.lower() == "true":
                is_vulnerable = True
                reason = "Wildcard ACAO with credentials=true"

        # Case C: null origin accepted with credentials
        if origin == "null" and acao == "null" and acac and acac.lower() == "true":
            is_vulnerable = True
            reason = "Null origin accepted with credentials=true"

        # Case D: subdomain prefix/suffix bypass (ACAO reflects evil.<host>)
        if subdomain_origin and acao == subdomain_origin and origin == subdomain_origin:
            is_vulnerable = True
            reason = f"Subdomain bypass: evil.{urlparse(target).hostname} reflected"

        test_entry["vulnerable"] = is_vulnerable
        test_entry["reason"] = reason
        result["tests"].append(test_entry)

        if is_vulnerable:
            log.warning(f"  CORS VULN: {reason}")
            result["vulnerable"].append({
                "url": target,
                "original_url": target,
                "injected_url": target,
                "param": "Origin",
                "payload": origin,
                "evil_origin": origin,
                "acao": acao,
                "acac": acac,
                "severity": "high",
                "description": reason,
            })

    if not result["vulnerable"]:
        log.info(f"  No CORS issues detected ({len(origins_to_test)} origins tested)")
    else:
        log.warning(f"  Found {len(result['vulnerable'])} CORS issue(s)")

    return result
'''

with open("modules/cors_checker.py", "w", encoding="utf-8") as f:
    f.write(CORS_CHECKER)
print("OK cors_checker.py:", len(CORS_CHECKER), "bytes")

# ============================================================
# Entry point
# ============================================================
if __name__ == "__main__":
    app()