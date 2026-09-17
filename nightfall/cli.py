"""
NIGHTFALL CLI — Command-line interface for the autonomous AI VAPT platform.

Commands:
  scan         Run a full autonomous scan against a target
  oast-server  Start the OAST callback server standalone
  report       Generate reports from a previous scan's database
  version      Show version information
"""
from __future__ import annotations
import sys, io
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


import asyncio
import json
import os
import sys
from pathlib import Path

import structlog
import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

app = typer.Typer(
    name="nightfall",
    help="🌑 NIGHTFALL — Autonomous AI VAPT Platform",
    add_completion=False,
    rich_markup_mode="rich",
)


# ── Logging Setup ────────────────────────────────────────────────────────────

def _setup_logging(level: str = "INFO", log_file: str | None = None):
    """Configure structured logging."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer() if not log_file else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(structlog, level.upper(), structlog.INFO) if hasattr(structlog, level.upper()) else 20
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


# ── Banner ───────────────────────────────────────────────────────────────────

BANNER = r"""
[bold red]
    ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗ █████╗ ██╗     ██╗
    ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██║     ██║
    ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ███████║██║     ██║
    ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██╔══██║██║     ██║
    ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ██║  ██║███████╗███████╗
    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
[/bold red]
[dim]    Autonomous AI VAPT Platform v1.0.0[/dim]
[dim]    Agentic • Reasoning-Driven • Unrestricted[/dim]
"""


def _show_banner():
    console.print(BANNER)


# ── Scan Command ─────────────────────────────────────────────────────────────

@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL to scan"),
    config: str = typer.Option("config.yaml", "--config", "-c", help="Path to config file"),
    budget: int = typer.Option(None, "--budget", "-b", help="Override total request budget"),
    workers: int = typer.Option(None, "--workers", "-w", help="Override worker count"),
    exploit: str = typer.Option(None, "--exploit", "-e", help="Exploit mode: off | confirm"),
    output: str = typer.Option("reports", "--output", "-o", help="Output directory"),
    db_path: str = typer.Option("nightfall.db", "--db", help="Database file path"),
    log_level: str = typer.Option("INFO", "--log-level", "-l", help="Log level"),
    no_oast: bool = typer.Option(False, "--no-oast", help="Disable OAST server"),
    proxy: str = typer.Option(None, "--proxy", help="HTTP proxy URL"),
):
    """🌑 Run a full autonomous VAPT scan against the target URL."""
    _show_banner()
    _setup_logging(log_level)

    asyncio.run(_run_scan(
        url=url,
        config_path=config,
        budget=budget,
        workers=workers,
        exploit=exploit,
        output=output,
        db_path=db_path,
        no_oast=no_oast,
        proxy=proxy,
    ))


async def _run_scan(
    url: str,
    config_path: str,
    budget: int | None,
    workers: int | None,
    exploit: str | None,
    output: str,
    db_path: str,
    no_oast: bool,
    proxy: str | None,
):
    """Async scan implementation."""
    from nightfall.config import load_config, default_config
    from nightfall.core.scope import ScopeGuard
    from nightfall.core.ratelimit import RateLimiter
    from nightfall.core.http import HttpPool
    from nightfall.core.db import Database
    from nightfall.core.oast import OAST
    from nightfall.core.orchestrator import Orchestrator
    from nightfall.ai.client import ModelClient
    from nightfall.report.markdown import render
    from nightfall.report.sarif import to_sarif_json

    # Load config
    config_file = Path(config_path)
    if config_file.exists():
        cfg = load_config(config_file)
        console.print(f"[green]✓[/green] Config loaded from {config_file}")
    else:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        cfg = default_config()
        cfg.targets = [parsed.hostname or "localhost"]
        console.print(f"[yellow]⚠[/yellow] No config file — using defaults for {parsed.hostname}")

    # Apply CLI overrides
    if budget:
        cfg.total_requests = budget
    if workers:
        cfg.workers = workers
    if exploit:
        cfg.exploit_mode = exploit
    if proxy:
        cfg.proxy = proxy

    # Validate API key
    if not cfg.ai.resolved_api_key:
        console.print("[red]✗[/red] No API key found. Set MODEL_API_KEY env var or ai.api_key in config.")
        raise typer.Exit(1)

    # Display scan configuration
    _show_config(cfg, url)

    # Initialize components
    scope = ScopeGuard.from_config(cfg)
    rate_limiter = RateLimiter(cfg.rate_limit_per_host, cfg.burst)
    pool = HttpPool.from_config(cfg, scope, rate_limiter)
    db = Database(db_path)
    await db.connect()

    ai = ModelClient.from_config(cfg)

    oast = None
    if not no_oast and cfg.oast.enabled:
        oast = OAST.from_config(cfg)
        try:
            await oast.start()
            console.print(f"[green]✓[/green] OAST server started on {cfg.oast.domain}")
        except Exception as exc:
            console.print(f"[yellow]⚠[/yellow] OAST server failed: {exc} — blind detection disabled")
            oast = None

    # Run the scan
    console.print("")
    console.print(Panel(
        f"[bold]Target:[/bold] {url}\n"
        f"[bold]Budget:[/bold] {cfg.total_requests} requests\n"
        f"[bold]Model:[/bold] {cfg.ai.model}\n"
        f"[bold]Exploit Mode:[/bold] {cfg.exploit_mode}",
        title="🌑 Scan Starting",
        border_style="red",
    ))
    console.print("")

    orchestrator = Orchestrator(cfg, ai, pool, oast, db, scope)

    try:
        summary = await orchestrator.run(url)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan interrupted by user[/yellow]")
        summary = {"interrupted": True}
    except Exception as exc:
        console.print(f"\n[red]✗ Scan error: {exc}[/red]")
        summary = {"error": str(exc)}

    # Generate reports
    findings = await db.finalize_report()
    os.makedirs(output, exist_ok=True)

    # Markdown report
    md_report = render(findings, summary)
    md_path = os.path.join(output, "nightfall_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_report)
    console.print(f"[green]✓[/green] Markdown report: {md_path}")

    # SARIF report
    sarif_report = to_sarif_json(findings, summary)
    sarif_path = os.path.join(output, "nightfall_report.sarif")
    with open(sarif_path, "w", encoding="utf-8") as f:
        f.write(sarif_report)
    console.print(f"[green]✓[/green] SARIF report: {sarif_path}")

    # Summary table
    _show_summary(findings, summary)

    # Cleanup
    await pool.close()
    await db.close()
    if oast:
        await oast.stop()


def _show_config(cfg, url):
    """Display the scan configuration."""
    table = Table(title="Scan Configuration", show_lines=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Target", url)
    table.add_row("Scope", ", ".join(cfg.targets))
    table.add_row("Budget", str(cfg.total_requests))
    table.add_row("Workers", str(cfg.workers))
    table.add_row("Rate Limit", f"{cfg.rate_limit_per_host} rps")
    table.add_row("Proxy", cfg.proxy or "none")
    table.add_row("Exploit Mode", cfg.exploit_mode)
    table.add_row("AI Model", cfg.ai.model)
    table.add_row("Thinking", cfg.ai.thinking)
    table.add_row("OAST", f"{cfg.oast.domain}" if cfg.oast.enabled else "disabled")

    console.print(table)


def _show_summary(findings, summary):
    """Display the scan results summary."""
    console.print("")
    table = Table(title="🌑 Scan Results", show_lines=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Total Findings", str(len(findings)))

    # Count by severity
    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_counts.get(sev, 0)
        style = {"critical": "red", "high": "yellow", "medium": "blue", "low": "cyan", "info": "dim"}.get(sev, "white")
        if count > 0:
            table.add_row(f"  {sev.upper()}", f"[{style}]{count}[/{style}]")

    if isinstance(summary, dict):
        if "elapsed_seconds" in summary:
            table.add_row("Duration", f"{summary['elapsed_seconds']}s")
        if "budget_used" in summary:
            table.add_row("Requests Used", str(summary["budget_used"]))
        if "waf" in summary and summary["waf"]:
            table.add_row("WAF Detected", str(summary["waf"]))

    console.print(table)

    if severity_counts.get("critical", 0) > 0:
        console.print("\n[bold red]⚠  CRITICAL vulnerabilities found — immediate remediation required[/bold red]")
    elif severity_counts.get("high", 0) > 0:
        console.print("\n[bold yellow]⚠  HIGH severity issues found — remediation recommended[/bold yellow]")
    elif findings:
        console.print("\n[green]✓  Scan complete — review findings in the report[/green]")
    else:
        console.print("\n[green]✓  No vulnerabilities detected[/green]")


# ── OAST Server Command ─────────────────────────────────────────────────────

@app.command("oast-server")
def oast_server(
    domain: str = typer.Option("o.nightfall.local", "--domain", "-d", help="OAST domain"),
    dns_port: int = typer.Option(5353, "--dns-port", help="DNS listener port"),
    http_port: int = typer.Option(8089, "--http-port", help="HTTP callback port"),
    bind: str = typer.Option("0.0.0.0", "--bind", help="Bind address"),
):
    """🌐 Start the OAST callback server standalone."""
    _show_banner()
    _setup_logging("INFO")

    console.print(Panel(
        f"[bold]Domain:[/bold] {domain}\n"
        f"[bold]DNS:[/bold] {bind}:{dns_port}\n"
        f"[bold]HTTP:[/bold] {bind}:{http_port}",
        title="🌐 OAST Server",
        border_style="green",
    ))

    asyncio.run(_run_oast(domain, bind, dns_port, http_port))


async def _run_oast(domain: str, bind: str, dns_port: int, http_port: int):
    from nightfall.core.oast import OAST

    oast = OAST(domain=domain, server_ip=bind, dns_port=dns_port, http_port=http_port)
    await oast.start()

    console.print("[green]✓[/green] OAST server running. Press Ctrl+C to stop.")
    try:
        while True:
            await asyncio.sleep(10)
            stats = {
                "pending_nonces": len(oast._pending),
                "total_callbacks": sum(len(v) for v in oast._callbacks.values()),
            }
            console.print(f"[dim]  ♦ Pending: {stats['pending_nonces']} | Callbacks: {stats['total_callbacks']}[/dim]")
    except KeyboardInterrupt:
        await oast.stop()
        console.print("\n[yellow]OAST server stopped[/yellow]")


# ── Report Command ───────────────────────────────────────────────────────────

@app.command()
def report(
    db_path: str = typer.Option("nightfall.db", "--db", help="Database file path"),
    format: str = typer.Option("markdown", "--format", "-f", help="Report format: markdown | sarif | both"),
    output: str = typer.Option("reports", "--output", "-o", help="Output directory"),
):
    """📄 Generate reports from a previous scan's database."""
    _setup_logging("WARNING")
    asyncio.run(_generate_report(db_path, format, output))


async def _generate_report(db_path: str, format: str, output: str):
    from nightfall.core.db import Database
    from nightfall.report.markdown import render
    from nightfall.report.sarif import to_sarif_json

    if not Path(db_path).exists():
        console.print(f"[red]✗[/red] Database not found: {db_path}")
        raise typer.Exit(1)

    db = Database(db_path)
    await db.connect()
    findings = await db.finalize_report()
    await db.close()

    os.makedirs(output, exist_ok=True)

    if format in ("markdown", "both"):
        md = render(findings)
        md_path = os.path.join(output, "nightfall_report.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        console.print(f"[green]✓[/green] Markdown: {md_path}")

    if format in ("sarif", "both"):
        sarif = to_sarif_json(findings)
        sarif_path = os.path.join(output, "nightfall_report.sarif")
        with open(sarif_path, "w", encoding="utf-8") as f:
            f.write(sarif)
        console.print(f"[green]✓[/green] SARIF: {sarif_path}")

    console.print(f"\n[green]✓[/green] Generated report with {len(findings)} findings")


# ── Version Command ──────────────────────────────────────────────────────────

@app.command()
def version():
    """📦 Show NIGHTFALL version information."""
    console.print("NIGHTFALL v1.0.0 — Autonomous AI VAPT Platform")
    console.print("Agentic • Reasoning-Driven • Unrestricted")


# ── Entry Point ──────────────────────────────────────────────────────────────

def main():
    app()


if __name__ == "__main__":
    main()
