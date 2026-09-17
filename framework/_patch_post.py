# -*- coding: utf-8 -*-
"""Add POST/JSON body support to cli.py"""

with open("cli.py", encoding="utf-8") as f:
    src = f.read()

# ============================================================
# 1) Add flags to scan_cmd signature
# ============================================================
OLD_SIG = '''    cookie: str = typer.Option(
        None, "--cookie", help="Manual cookie string (e.g. 'session=abc; xyz=1').",
    ),
):
    """Run a security scan against TARGET."""'''

NEW_SIG = '''    cookie: str = typer.Option(
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
        None, "--post-json", help="POST body (JSON: '{\"a\":1}').",
    ),
    header: str = typer.Option(
        None, "--header", "-H", help="Extra header (repeatable: 'X-A: 1').",
    ),
):
    """Run a security scan against TARGET."""'''

if OLD_SIG not in src:
    print("ERROR: scan_cmd signature not found")
    raise SystemExit(1)
src = src.replace(OLD_SIG, NEW_SIG, 1)
print("OK: scan_cmd signature updated")


# ============================================================
# 2) Build http_kwargs in scan_cmd and pass
# ============================================================
OLD_CALL = '''    auth_kwargs = {
        "login_url": login_url or "",
        "username": username or "",
        "password": password or "",
        "bearer_token": bearer_token or "",
        "manual_cookie": cookie or "",
    }

    results = _run_scan(target, module_names, config, output, quiet, auth_kwargs=auth_kwargs)'''

NEW_CALL = '''    auth_kwargs = {
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
                        auth_kwargs=auth_kwargs, http_kwargs=http_kwargs)'''

if OLD_CALL not in src:
    print("ERROR: _run_scan call not found")
    raise SystemExit(1)
src = src.replace(OLD_CALL, NEW_CALL, 1)
print("OK: scan_cmd body updated")


# ============================================================
# 3) Update _run_scan signature
# ============================================================
OLD_RUN_SIG = '''def _run_scan(target: str, module_names: list, config_path: str = None,
              output_override: str = None, quiet: bool = False,
              auth_kwargs: dict = None):'''

NEW_RUN_SIG = '''def _run_scan(target: str, module_names: list, config_path: str = None,
              output_override: str = None, quiet: bool = False,
              auth_kwargs: dict = None, http_kwargs: dict = None):'''

if OLD_RUN_SIG not in src:
    print("ERROR: _run_scan signature not found")
    raise SystemExit(1)
src = src.replace(OLD_RUN_SIG, NEW_RUN_SIG, 1)
print("OK: _run_scan signature updated")


# ============================================================
# 4) Inject http_kwargs into cfg after auth
# ============================================================
OLD_AFTER_AUTH = '''        except Exception as e:
            log.warning("Auth error: " + str(e))'''

NEW_AFTER_AUTH = '''        except Exception as e:
            log.warning("Auth error: " + str(e))

    # 3.6 HTTP method / body overrides
    if http_kwargs:
        cfg["_http_method"] = http_kwargs.get("method", "GET")
        cfg["_post_data"] = http_kwargs.get("post_data", "")
        cfg["_post_json"] = http_kwargs.get("post_json", "")
        extra_header = http_kwargs.get("extra_header", "")
        if extra_header:
            # Parse "X-A: 1" format
            if ":" in extra_header:
                k, v = extra_header.split(":", 1)
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
                console.print("[dim]   + POST JSON: " + cfg["_post_json"][:60] + "[/dim]")'''

if OLD_AFTER_AUTH not in src:
    print("ERROR: auth block not found")
    raise SystemExit(1)
src = src.replace(OLD_AFTER_AUTH, NEW_AFTER_AUTH, 1)
print("OK: http_kwargs injection added")


# ============================================================
# Write
# ============================================================
with open("cli.py", "w", encoding="utf-8") as f:
    f.write(src)

print("DONE. cli.py size:", len(src))