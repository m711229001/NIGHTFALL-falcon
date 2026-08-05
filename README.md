# 🌑 NIGHTFALL

**Autonomous AI VAPT (Vulnerability Assessment & Penetration Testing) Platform**

NIGHTFALL is an agentic, reasoning-driven penetration testing platform designed to autonomously discover, triage, and exploit web vulnerabilities. Unlike traditional checklist-based scanners, NIGHTFALL uses a frontier reasoning model (Claude, GPT-4, etc.) to drive its decision-making, synthesizing context-aware payloads and executing dynamic WAF bypass chains.

---

## ⚡ Features

- **Agentic Loop**: Operates on an `observe → reason → plan → act → triage → persist` lifecycle. It adapts its strategy based on findings rather than just spraying static payloads.
- **AI-Driven Reasoning Core**: Uses an LLM to generate attack plans, synthesize payloads tailored to the specific context (like exact JSON structures or JS execution contexts), and perform semantic FP (False Positive) triage.
- **Comprehensive Detection Engines**:
  - **SQLi**: Error-based, boolean differential, time-based, out-of-band (OAST), and a sqlmap bridge for deep extraction.
  - **XSS**: Context-aware injection (HTML body, attributes, JS strings, DOM sinks) and stored XSS verification.
  - **IDOR**: Dual-session differential engine that detects cross-tenant read/write vulnerabilities.
  - **SSRF**: Cloud metadata probing, OOB callbacks, and internal service access.
  - **XXE, CSRF, JWT, Authn, Session**: Full coverage for modern web application vulnerabilities.
- **Bypass Plane**: Built-in encoder chains (URL, hex, Unicode, SQL comments, zero-width, etc.) to evade WAFs. Successful chains are "frozen" and reused.
- **Self-Hosted OAST**: Includes a built-in DNS and HTTP callback server for detecting blind vulnerabilities (SQLi, XXE, SSRF).
- **Rich Reporting**: Outputs comprehensive Markdown and CI/CD-ready SARIF 2.1.0 reports.

---

## 🛠️ Installation

Requires Python 3.10+.

```bash
# Clone or download the repository
cd nightfall

# Install the package and its dependencies
pip install -e .

# Set your LLM provider API key
# For Anthropic/Claude:
export MODEL_API_KEY="your-anthropic-api-key"
# (On Windows CMD use: set MODEL_API_KEY=your-api-key)
```

*(Optional)* To use Playwright for Single Page Application (SPA) crawling:
```bash
pip install -e .[browser]
playwright install chromium
```

---

## 🚀 Usage

NIGHTFALL provides a unified CLI. You can see all options by running `nightfall --help`.

### 1. Run a Scan
Run an autonomous scan against a target URL. Ensure you have permission to test the target!

```bash
nightfall scan https://target.example.com --config config.yaml
```

**Options:**
- `--config`, `-c`: Path to the YAML configuration file.
- `--budget`, `-b`: Override the total request budget (e.g., 5000).
- `--exploit`, `-e`: Set exploit mode (`off` or `confirm`).
- `--no-oast`: Disable the built-in OAST server.

### 2. Standalone OAST Server
If you want to run the OAST callback server separately (e.g., on a VPS for public reachability):

```bash
nightfall oast-server --domain o.yourdomain.com
```

### 3. Generate Reports
Regenerate reports from a previous scan's database:

```bash
nightfall report --db nightfall.db --format both --output ./reports
```

---

## ⚙️ Configuration

NIGHTFALL uses a `config.yaml` file to define scan parameters, LLM settings, and target scope. A default `config.yaml` is generated if one is not provided.

Key settings include:
- `total_requests`: The hard cap on HTTP requests the agent can make.
- `ai.model`: The LLM to use (e.g., `claude-3-opus-20240229`, `gpt-4o`).
- `ai.thinking`: Enable extended thinking mode (if supported by the provider).
- `rate_limit_per_host`: Throttle requests to prevent DoS.

---

## ⚠️ Disclaimer

**NIGHTFALL is a powerful offensive security tool.**
It must only be used on systems, networks, and applications for which you have explicit, written authorization to perform penetration testing. Unauthorized use is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this tool.
