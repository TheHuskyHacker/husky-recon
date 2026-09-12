#!/usr/bin/env python3
"""
Husky WebRecon — focused web application enumeration.

Runs whatweb, directory busting, tech fingerprinting, header audit,
robots/sitemap parsing, JS endpoint extraction, backup file hunting,
and exposed config detection against a single web target.

Requires: requests (pip install requests)
Optional tools: whatweb, gobuster, feroxbuster, nikto, curl
"""

import argparse
import os
import re
import subprocess
import shutil
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import requests.exceptions

# Suppress SSL warnings
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

    {bold('W E B   R E C O N')}
    {dim('Every page. Every path. Every leak.')}
"""

TIMEOUT = 10
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
FINDINGS = []

def log(icon, msg, color_fn=None):
    if color_fn:
        print(f"  {color_fn(icon)} {msg}")
    else:
        print(f"  {icon} {msg}")

def finding(msg):
    FINDINGS.append(msg)
    log("[!!!]", msg, green)

def tool_exists(name):
    return shutil.which(name) is not None

def fetch(url, timeout=TIMEOUT):
    try:
        resp = requests.get(url, timeout=timeout, verify=False,
                           headers={"User-Agent": UA}, allow_redirects=True)
        return resp
    except Exception:
        return None

def run_cmd(cmd, timeout=300):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=timeout)
        return result.stdout
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════
#                    SCAN MODULES
# ═══════════════════════════════════════════════════════════

def scan_headers(url, outdir):
    """Analyze HTTP response headers for security and info disclosure."""
    log("[*]", f"Header analysis...", cyan)
    resp = fetch(url)
    if not resp:
        log("[-]", "Could not connect", red)
        return

    # Save raw headers
    with open(f"{outdir}/headers.txt", "w") as f:
        for k, v in resp.headers.items():
            f.write(f"{k}: {v}\n")

    # Info disclosure
    disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version",
                         "X-AspNetMvc-Version", "X-Generator", "X-Runtime",
                         "X-Debug-Token", "X-Debug-Token-Link"]
    for h in disclosure_headers:
        val = resp.headers.get(h)
        if val:
            finding(f"Header leak: {h}: {val}")

    # Missing security headers
    security_headers = {
        "Strict-Transport-Security": "HSTS missing — no HTTPS enforcement",
        "Content-Security-Policy": "CSP missing — XSS risk",
        "X-Frame-Options": "X-Frame-Options missing — clickjacking risk",
        "X-Content-Type-Options": "X-Content-Type-Options missing — MIME sniffing risk",
    }
    for header, warning in security_headers.items():
        if not resp.headers.get(header):
            log("[!]", warning, yellow)

    # Cookie flags
    cookies = resp.headers.get("Set-Cookie", "")
    if cookies:
        if "httponly" not in cookies.lower():
            log("[!]", "Cookies missing HttpOnly flag", yellow)
        if "secure" not in cookies.lower():
            log("[!]", "Cookies missing Secure flag", yellow)
        if "samesite" not in cookies.lower():
            log("[!]", "Cookies missing SameSite attribute", yellow)

    return resp


def scan_whatweb(url, outdir):
    """Run whatweb for technology fingerprinting."""
    if not tool_exists("whatweb"):
        log("[-]", "whatweb not installed — skipping", dim)
        return

    log("[*]", "WhatWeb fingerprinting...", cyan)
    output = run_cmd(f"whatweb -a 3 --color=never '{url}'", timeout=60)

    with open(f"{outdir}/whatweb.txt", "w") as f:
        f.write(output)

    # Parse interesting findings
    tech_patterns = {
        "WordPress": "WordPress detected",
        "Drupal": "Drupal detected",
        "Joomla": "Joomla detected",
        "PHP": "PHP detected",
        "ASP.NET": "ASP.NET detected",
        "Apache": "Apache web server",
        "nginx": "nginx web server",
        "IIS": "IIS web server",
        "Tomcat": "Tomcat detected",
        "Node.js": "Node.js detected",
        "Django": "Django detected",
        "Flask": "Flask detected",
        "Laravel": "Laravel detected",
        "Ruby on Rails": "Rails detected",
    }
    for tech, label in tech_patterns.items():
        if tech.lower() in output.lower():
            log("[+]", f"Technology: {bold(label)}", green)

    # Version extraction
    version_matches = re.findall(r'(\w+)\[([\d.]+)\]', output)
    for name, ver in version_matches:
        log("[+]", f"Version: {name} {bold(ver)}", green)


def scan_robots_sitemap(url, outdir):
    """Fetch and parse robots.txt and sitemap.xml."""
    log("[*]", "Checking robots.txt & sitemap.xml...", cyan)

    # robots.txt
    resp = fetch(urljoin(url, "/robots.txt"))
    if resp and resp.status_code == 200 and "disallow" in resp.text.lower():
        with open(f"{outdir}/robots.txt", "w") as f:
            f.write(resp.text)
        finding("robots.txt found!")
        # Extract disallowed paths
        for line in resp.text.split("\n"):
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    log("[+]", f"  Disallowed: {bold(path)}", green)

    # sitemap.xml
    resp = fetch(urljoin(url, "/sitemap.xml"))
    if resp and resp.status_code == 200 and "<url" in resp.text.lower():
        with open(f"{outdir}/sitemap.xml", "w") as f:
            f.write(resp.text)
        urls_found = len(re.findall(r'<loc>(.*?)</loc>', resp.text))
        finding(f"sitemap.xml found with {urls_found} URLs!")


def scan_sensitive_files(url, outdir):
    """Hunt for exposed configuration files, backups, and dev artifacts."""
    log("[*]", "Hunting for sensitive files...", cyan)

    targets = [
        # Config files
        ("/.env", "Environment file — may contain credentials"),
        ("/.env.bak", "Environment backup"),
        ("/.env.old", "Environment old"),
        ("/config.php", "PHP config — database creds"),
        ("/config.php.bak", "Config backup"),
        ("/wp-config.php", "WordPress config"),
        ("/wp-config.php.bak", "WordPress config backup"),
        ("/configuration.php", "Joomla config"),
        ("/web.config", "IIS/ASP.NET config"),
        ("/appsettings.json", ".NET config"),
        ("/settings.py", "Django settings"),
        ("/config.yml", "YAML config"),
        ("/config.yaml", "YAML config"),
        ("/database.yml", "Rails database config"),
        # Git / SVN
        ("/.git/HEAD", "Git repository exposed"),
        ("/.git/config", "Git config"),
        ("/.svn/entries", "SVN repository exposed"),
        ("/.hg/requires", "Mercurial repository exposed"),
        # Backups
        ("/backup.zip", "Backup archive"),
        ("/backup.tar.gz", "Backup archive"),
        ("/backup.sql", "Database backup"),
        ("/db.sql", "Database dump"),
        ("/dump.sql", "Database dump"),
        ("/database.sql", "Database dump"),
        ("/.htpasswd", "Apache password file"),
        ("/.htaccess", "Apache config"),
        ("/server-status", "Apache server-status"),
        ("/server-info", "Apache server-info"),
        # Debug / info
        ("/info.php", "PHP info page"),
        ("/phpinfo.php", "PHP info page"),
        ("/test.php", "Test page"),
        ("/debug", "Debug endpoint"),
        ("/console", "Console (Flask/Werkzeug debug)"),
        ("/elmah.axd", "ASP.NET error log"),
        ("/trace.axd", "ASP.NET trace"),
        # API docs
        ("/swagger/", "Swagger API docs"),
        ("/swagger-ui.html", "Swagger UI"),
        ("/api-docs", "API documentation"),
        ("/graphql", "GraphQL endpoint"),
        ("/graphiql", "GraphQL IDE"),
        # Admin panels
        ("/admin/", "Admin panel"),
        ("/administrator/", "Admin panel"),
        ("/wp-admin/", "WordPress admin"),
        ("/wp-login.php", "WordPress login"),
        ("/phpmyadmin/", "phpMyAdmin"),
        ("/adminer.php", "Adminer database tool"),
    ]

    hits = []

    def check(path, desc):
        full_url = urljoin(url, path)
        resp = fetch(full_url, timeout=5)
        if resp and resp.status_code == 200:
            # Filter out generic 200s (custom 404 pages)
            if len(resp.text) > 50:
                # Check it's not just a redirect to home/login
                if resp.url.rstrip("/") != url.rstrip("/"):
                    pass  # redirected — might still be valid
                return (path, desc, len(resp.text))
        return None

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(check, path, desc): (path, desc) for path, desc in targets}
        for future in as_completed(futures):
            result = future.result()
            if result:
                path, desc, size = result
                hits.append(result)
                finding(f"Exposed: {path} — {desc} ({size} bytes)")

    with open(f"{outdir}/sensitive_files.txt", "w") as f:
        for path, desc, size in hits:
            f.write(f"{path} | {desc} | {size} bytes\n")

    if not hits:
        log("[-]", "No sensitive files found", dim)


def scan_html_intel(url, outdir):
    """Extract intelligence from the HTML source."""
    log("[*]", "Extracting HTML intelligence...", cyan)
    resp = fetch(url)
    if not resp:
        return

    html = resp.text
    intel = []

    # HTML comments
    comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    interesting_comments = [c.strip() for c in comments
                          if len(c.strip()) > 10
                          and not c.strip().startswith("[if")
                          and "google" not in c.lower()]
    if interesting_comments:
        log("[+]", f"Found {len(interesting_comments)} HTML comments", green)
        for c in interesting_comments[:5]:
            preview = c[:80].replace("\n", " ")
            log("", f"    {dim('<!--')} {preview} {dim('-->')}")
            intel.append(f"COMMENT: {c[:200]}")

    # Email addresses
    emails = set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', html))
    if emails:
        log("[+]", f"Email addresses found: {', '.join(emails)}", green)
        intel.extend(f"EMAIL: {e}" for e in emails)

    # Internal paths / endpoints in JS
    js_paths = set(re.findall(r'["\']/(api|admin|upload|login|auth|user|dashboard|portal|internal)[/\w.-]*["\']', html, re.IGNORECASE))
    if js_paths:
        log("[+]", f"Interesting paths in source:", green)
        for p in sorted(js_paths)[:10]:
            clean = p.strip("\"'")
            log("", f"    {green(clean)}")
            intel.append(f"PATH: {clean}")

    # Forms (potential attack surfaces)
    forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']', html, re.IGNORECASE)
    forms += re.findall(r'<form[^>]*method=["\']([^"\']*)["\'][^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE)
    if forms:
        log("[+]", f"Forms detected:", green)
        for parts in forms[:5]:
            log("", f"    {bold(parts[0])} ({parts[1]})")

    # Input fields
    inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']([^"\']*)["\']', html, re.IGNORECASE)
    file_uploads = [name for name, itype in inputs if itype.lower() == "file"]
    hidden_fields = [(name, "") for name, itype in inputs if itype.lower() == "hidden"]
    password_fields = [name for name, itype in inputs if itype.lower() == "password"]

    if file_uploads:
        finding(f"File upload field(s): {', '.join(file_uploads)}")
    if password_fields:
        log("[+]", f"Login form detected (password field: {', '.join(password_fields)})", green)

    # JS files for further analysis
    js_files = set(re.findall(r'src=["\']([^"\']*\.js)["\']', html))
    if js_files:
        log("[+]", f"{len(js_files)} JavaScript file(s) found", green)
        intel.extend(f"JS: {js}" for js in js_files)

    # Hidden/interesting meta tags
    generators = re.findall(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
    for gen in generators:
        finding(f"Generator meta tag: {gen}")

    with open(f"{outdir}/html_intel.txt", "w") as f:
        for item in intel:
            f.write(item + "\n")


def scan_js_endpoints(url, outdir):
    """Fetch JS files and extract API endpoints, secrets, paths."""
    log("[*]", "Scanning JavaScript files for endpoints...", cyan)
    resp = fetch(url)
    if not resp:
        return

    js_urls = set(re.findall(r'src=["\']([^"\']*\.js)["\']', resp.text))
    all_endpoints = set()
    all_secrets = []

    for js_url in list(js_urls)[:20]:  # limit to 20 JS files
        full_url = urljoin(url, js_url)
        js_resp = fetch(full_url, timeout=15)
        if not js_resp or js_resp.status_code != 200:
            continue

        js_text = js_resp.text

        # API endpoints
        endpoints = re.findall(r'["\']/(api|v[0-9]|rest|graphql)[/\w.-]+["\']', js_text)
        all_endpoints.update(e.strip("\"'") for e in endpoints)

        # Full URL paths
        url_paths = re.findall(r'["\']https?://[^"\']+["\']', js_text)
        for u in url_paths:
            clean = u.strip("\"'")
            if urlparse(url).netloc in clean or "localhost" in clean or "127.0.0.1" in clean:
                all_endpoints.add(clean)

        # Potential secrets
        secret_patterns = [
            (r'(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', "Potential secret/key"),
            (r'(?:Authorization|Bearer)\s*[:=]\s*["\']([^"\']+)["\']', "Auth token"),
            (r'["\'](?:sk_live|pk_live|sk_test|pk_test)_[a-zA-Z0-9]+["\']', "Stripe key"),
            (r'["\']AIza[0-9A-Za-z_-]{35}["\']', "Google API key"),
            (r'["\']AKIA[0-9A-Z]{16}["\']', "AWS access key"),
        ]
        for pattern, label in secret_patterns:
            matches = re.findall(pattern, js_text, re.IGNORECASE)
            for m in matches:
                all_secrets.append(f"{label}: {m[:60]}... (in {js_url})")

    if all_endpoints:
        log("[+]", f"Found {len(all_endpoints)} endpoint(s) in JS:", green)
        for ep in sorted(all_endpoints)[:15]:
            log("", f"    {green(ep)}")

    if all_secrets:
        for s in all_secrets:
            finding(f"JS secret: {s}")

    with open(f"{outdir}/js_endpoints.txt", "w") as f:
        for ep in sorted(all_endpoints):
            f.write(ep + "\n")


def scan_directories(url, outdir, wordlist=None):
    """Run directory/file brute force."""
    # Try feroxbuster first, then gobuster
    if tool_exists("feroxbuster"):
        tool = "feroxbuster"
    elif tool_exists("gobuster"):
        tool = "gobuster"
    else:
        log("[-]", "No directory scanner installed (feroxbuster/gobuster) — skipping", yellow)
        return

    # Find wordlist
    wl = wordlist
    wordlist_options = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ]
    if not wl:
        for w in wordlist_options:
            if os.path.exists(w):
                wl = w
                break

    if not wl:
        log("[-]", "No wordlist found — install seclists", yellow)
        return

    outfile = f"{outdir}/directory_scan.txt"
    log("[*]", f"Directory scan with {tool}...", cyan)
    log("", f"    {dim(f'Wordlist: {wl}')}")

    if tool == "feroxbuster":
        cmd = (f"feroxbuster -u '{url}' -w {wl} -t 30 -k --no-state "
               f"-x php,html,txt,asp,aspx,jsp,bak,old,conf,zip,sql "
               f"-o {outfile} --quiet 2>/dev/null")
    else:
        cmd = (f"gobuster dir -u '{url}' -w {wl} -t 30 -q --no-error "
               f"-x php,html,txt,asp,aspx,jsp,bak,old,conf,zip,sql "
               f"-o {outfile} 2>/dev/null")

    run_cmd(cmd, timeout=600)

    # Parse and flag interesting finds
    if os.path.exists(outfile):
        with open(outfile) as f:
            content = f.read()

        interesting = ["/admin", "/login", "/upload", "/api", "/config",
                      "/backup", "/dev", "/test", "/portal", "/support",
                      "/shell", "/console", "/manager", "/phpmyadmin",
                      ".env", "web.config", "wp-config", ".git",
                      ".bak", ".old", ".sql", ".zip"]
        for path in interesting:
            if path in content.lower():
                finding(f"Directory scan hit: {path}")

    log("[+]", f"Directory scan done → {dim(outfile)}", green)


def scan_vhosts(url, outdir, wordlist=None):
    """Virtual host enumeration."""
    if not tool_exists("gobuster"):
        return

    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0]

    # Only meaningful for hostnames, not raw IPs
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
        return

    wl = wordlist
    vhost_lists = [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
    ]
    if not wl:
        for w in vhost_lists:
            if os.path.exists(w):
                wl = w
                break

    if not wl:
        return

    log("[*]", "Virtual host enumeration...", cyan)
    outfile = f"{outdir}/vhosts.txt"
    cmd = (f"gobuster vhost -u '{url}' -w {wl} -t 30 --append-domain "
           f"-o {outfile} 2>/dev/null")
    run_cmd(cmd, timeout=300)
    log("[+]", f"Vhost scan done → {dim(outfile)}", green)


def scan_nikto(url, outdir):
    """Run nikto web vulnerability scanner."""
    if not tool_exists("nikto"):
        log("[-]", "nikto not installed — skipping", dim)
        return

    log("[*]", "Nikto vulnerability scan...", cyan)
    outfile = f"{outdir}/nikto.txt"
    cmd = f"nikto -h '{url}' -o {outfile} -Format txt -maxtime 300s 2>/dev/null"
    run_cmd(cmd, timeout=360)
    log("[+]", f"Nikto done → {dim(outfile)}", green)


# ═══════════════════════════════════════════════════════════
#                    ORCHESTRATOR
# ═══════════════════════════════════════════════════════════

def run_webrecon(args):
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    url = url.rstrip("/")

    outdir = args.output or f"./webrecon/{urlparse(url).netloc}"
    Path(outdir).mkdir(parents=True, exist_ok=True)

    start = time.time()
    print(f"\n  {bold('Target:')} {bold(green(url))}")
    print(f"  {bold('Output:')} {outdir}")
    print(f"  {dim('─' * 50)}\n")

    # Run scans
    scan_headers(url, outdir)
    print()
    scan_whatweb(url, outdir)
    print()
    scan_robots_sitemap(url, outdir)
    print()
    scan_sensitive_files(url, outdir)
    print()
    scan_html_intel(url, outdir)
    print()
    scan_js_endpoints(url, outdir)
    print()

    if not args.skip_dirs:
        scan_directories(url, outdir, args.wordlist)
        print()

    if not args.skip_vhosts:
        scan_vhosts(url, outdir)
        print()

    if not args.skip_nikto:
        scan_nikto(url, outdir)
        print()

    # Summary
    elapsed = time.time() - start
    print(f"  {bold('─' * 50)}")
    print(f"  {bold('Scan complete')} in {elapsed:.1f}s")
    print(f"  Output: {outdir}/")

    if FINDINGS:
        print(f"\n  {bold(green('═══ FINDINGS ═══'))}")
        for f in FINDINGS:
            print(f"  {green('[!!!]')} {f}")
    else:
        print(f"\n  {dim('No major findings — review output files manually')}")
    print()


# ═══════════════════════════════════════════════════════════
#                        CLI
# ═══════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Husky WebRecon — focused web application enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 webrecon.py http://10.10.10.5
              python3 webrecon.py http://10.10.10.5:8080 -o ./loot/web
              python3 webrecon.py https://target.htb -w /usr/share/seclists/Discovery/Web-Content/big.txt
              python3 webrecon.py http://10.10.10.5 --skip-dirs --skip-nikto
        """),
    )
    p.add_argument("url", help="Target URL (e.g. http://10.10.10.5)")
    p.add_argument("-o", "--output", help="Output directory")
    p.add_argument("-w", "--wordlist", help="Custom wordlist for directory scanning")
    p.add_argument("--skip-dirs", action="store_true", help="Skip directory scanning")
    p.add_argument("--skip-nikto", action="store_true", help="Skip nikto")
    p.add_argument("--skip-vhosts", action="store_true", help="Skip vhost enumeration")
    return p.parse_args()


def main():
    args = parse_args()
    print(BANNER)
    run_webrecon(args)


if __name__ == "__main__":
    main()
