#!/usr/bin/env python3
"""
Husky Exploit Finder — searchsploit on steroids.

Takes a service+version or an nmap output file, searches exploit-db
via searchsploit, prioritizes by exploit type (RCE > auth bypass >
LFI > privesc > DoS), and searches GitHub for PoCs. Prints the exact
mirror/download commands so you're not fumbling mid-exam.

Rule 8: "if there is a metasploit option, there is a github repo
or exploit-db number. exploit-db.com is your friend."
  — The Husky Hacker

No pip dependencies. Requires: searchsploit (sudo apt install exploitdb)
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time

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

    {bold('E X P L O I T   F I N D E R')}
    {dim('Search. Prioritize. Mirror. Pwn.')}
"""

# ───────────────── exploit type priority ──────────────────
# Lower number = higher priority (hit these first)

EXPLOIT_PRIORITY = {
    "remote code execution": 1,
    "rce": 1,
    "command execution": 1,
    "command injection": 1,
    "code execution": 1,
    "shell upload": 1,
    "reverse shell": 1,
    "authenticated rce": 2,
    "file upload": 2,
    "sql injection": 2,
    "sqli": 2,
    "authentication bypass": 2,
    "auth bypass": 2,
    "password reset": 2,
    "arbitrary file read": 3,
    "file read": 3,
    "local file inclusion": 3,
    "lfi": 3,
    "path traversal": 3,
    "directory traversal": 3,
    "file disclosure": 3,
    "information disclosure": 3,
    "remote file inclusion": 3,
    "rfi": 3,
    "xxe": 3,
    "ssrf": 3,
    "privilege escalation": 4,
    "privesc": 4,
    "local privilege escalation": 4,
    "xss": 5,
    "cross-site scripting": 5,
    "csrf": 5,
    "cross-site request forgery": 5,
    "open redirect": 6,
    "denial of service": 7,
    "dos": 7,
    "buffer overflow": 3,
    "stack overflow": 3,
    "heap overflow": 3,
}

PRIORITY_LABELS = {
    1: (red, "CRITICAL — Remote Code Execution"),
    2: (yellow, "HIGH — Auth Bypass / SQLi / Upload"),
    3: (cyan, "MEDIUM — File Read / LFI / Overflow"),
    4: (magenta, "USEFUL — Privilege Escalation"),
    5: (dim, "LOW — XSS / CSRF"),
    6: (dim, "LOW — Open Redirect"),
    7: (dim, "NOISE — DoS (skip on OSCP)"),
    99: (dim, "UNKNOWN"),
}


def classify_exploit(title):
    """Classify an exploit by its title into a priority bucket."""
    title_lower = title.lower()
    best_priority = 99

    for keyword, priority in EXPLOIT_PRIORITY.items():
        if keyword in title_lower:
            best_priority = min(best_priority, priority)

    return best_priority


def log(icon, msg, color_fn=None):
    if color_fn:
        print(f"  {color_fn(icon)} {msg}")
    else:
        print(f"  {icon} {msg}")


# ═══════════════════════════════════════════════════════════
#              SEARCHSPLOIT WRAPPER
# ═══════════════════════════════════════════════════════════

def run_searchsploit(query, exact=False):
    """Run searchsploit and parse JSON output."""
    if not shutil.which("searchsploit"):
        log("[!]", "searchsploit not installed — run: sudo apt install exploitdb", red)
        return []

    cmd = ["searchsploit", "--json"]
    if exact:
        cmd.append("--exact")
    cmd.extend(query.split())

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0 and not result.stdout:
            return []

        # searchsploit JSON can be messy — find the JSON block
        output = result.stdout.strip()

        # Sometimes searchsploit outputs warnings before JSON
        json_start = output.find("{")
        if json_start == -1:
            return []
        output = output[json_start:]

        data = json.loads(output)
        exploits = data.get("RESULTS_EXPLOIT", [])
        return exploits
    except json.JSONDecodeError:
        # Fallback: parse text output
        return _parse_text_output(query)
    except subprocess.TimeoutExpired:
        return []
    except Exception as e:
        log("[!]", f"searchsploit error: {e}", red)
        return []


def _parse_text_output(query):
    """Fallback: parse searchsploit text output."""
    try:
        result = subprocess.run(
            ["searchsploit"] + query.split(),
            capture_output=True, text=True, timeout=30
        )
        exploits = []
        for line in result.stdout.split("\n"):
            # Match lines with an EDB-ID at the end
            match = re.match(r'^(.+?)\s+\|\s+(\S+)$', line.strip())
            if match and "/" in match.group(2):
                title = match.group(1).strip()
                path = match.group(2).strip()
                if title and not title.startswith("-") and "Title" not in title:
                    edb_match = re.search(r'/(\d+)\.\w+$', path)
                    edb_id = edb_match.group(1) if edb_match else ""
                    exploits.append({
                        "Title": title,
                        "Path": path,
                        "EDB-ID": edb_id,
                    })
        return exploits
    except Exception:
        return []


def format_exploit(exploit, index=None):
    """Format a single exploit result with priority coloring."""
    title = exploit.get("Title", "Unknown")
    path = exploit.get("Path", "")
    edb_id = exploit.get("EDB-ID", "")

    priority = classify_exploit(title)
    color_fn, _ = PRIORITY_LABELS.get(priority, (dim, ""))

    idx = f"{index}. " if index else ""
    edb_str = f"EDB-{edb_id}" if edb_id else ""

    print(f"    {color_fn(f'{idx}{title}')}")
    if edb_str:
        print(f"      {dim(edb_str)}  {dim(path)}")
        print(f"      {cyan(f'https://www.exploit-db.com/exploits/{edb_id}')}")

    return priority


def search_and_display(query, exact=False, show_mirror=True):
    """Search, classify, sort, and display results."""
    log("[*]", f"Searching: {bold(query)}", cyan)

    exploits = run_searchsploit(query, exact=exact)

    if not exploits:
        log("[-]", "No exploits found", dim)
        return []

    # Classify and sort by priority
    classified = []
    for exp in exploits:
        priority = classify_exploit(exp.get("Title", ""))
        classified.append((priority, exp))

    classified.sort(key=lambda x: x[0])

    # Display
    log("[+]", f"{len(classified)} exploit(s) found:", green)
    print()

    shown_priorities = set()
    rce_exploits = []

    for i, (priority, exp) in enumerate(classified, 1):
        # Show priority header when it changes
        if priority not in shown_priorities:
            shown_priorities.add(priority)
            color_fn, label = PRIORITY_LABELS.get(priority, (dim, "UNKNOWN"))
            print(f"    {color_fn(f'── {label} ──')}")

        p = format_exploit(exp, index=i)
        if p <= 2:  # RCE or High
            rce_exploits.append(exp)
        print()

    # Mirror commands for top exploits
    if show_mirror and rce_exploits:
        print(f"  {bold(green('═══ GRAB THESE FIRST ═══'))}\n")
        for exp in rce_exploits[:5]:
            edb_id = exp.get("EDB-ID", "")
            path = exp.get("Path", "")
            title = exp.get("Title", "")

            if edb_id:
                print(f"    {bold(title[:70])}")
                print(f"    {cyan(f'searchsploit -m {edb_id}')}")
                print(f"    {dim(f'https://www.exploit-db.com/exploits/{edb_id}')}")
                print()

    return classified


# ═══════════════════════════════════════════════════════════
#              NMAP OUTPUT PARSER
# ═══════════════════════════════════════════════════════════

def parse_nmap_file(filepath):
    """Parse an nmap -oN output file and extract service+version pairs."""
    services = []
    try:
        with open(filepath) as f:
            content = f.read()
    except Exception as e:
        log("[!]", f"Could not read file: {e}", red)
        return services

    for line in content.split("\n"):
        # Match: 80/tcp open http Apache httpd 2.4.49 ((Unix))
        match = re.match(
            r'^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)',
            line.strip()
        )
        if match:
            port = match.group(1)
            proto = match.group(2)
            service = match.group(3)
            version_info = match.group(4).strip()

            # Clean up version info — remove trailing parens, "httpd" etc.
            version_info = re.sub(r'\(.*?\)', '', version_info).strip()

            # Build search queries
            queries = []

            if version_info:
                # Full version string
                queries.append(f"{service} {version_info}")

                # Extract just the product + version number
                ver_match = re.search(r'([\w.-]+)\s+([\d.]+)', version_info)
                if ver_match:
                    product = ver_match.group(1)
                    version = ver_match.group(2)
                    queries.append(f"{product} {version}")

            # Service name alone as fallback
            if service not in ("tcpwrapped", "unknown"):
                queries.append(service)

            services.append({
                "port": port,
                "proto": proto,
                "service": service,
                "version": version_info,
                "queries": queries,
            })

    return services


def scan_from_nmap(filepath, top_n=10):
    """Parse nmap output and search exploits for each service."""
    services = parse_nmap_file(filepath)

    if not services:
        log("[!]", "No services parsed from nmap file", red)
        return

    log("[+]", f"Parsed {len(services)} service(s) from nmap output:", green)
    for svc in services:
        ver = svc["version"] or "unknown version"
        log("", f"    {svc['port']}/{svc['proto']} — {bold(svc['service'])} {dim(ver)}")
    print()

    all_findings = {}

    for svc in services:
        port = svc["port"]
        service_name = svc["service"]

        if service_name in ("tcpwrapped", "unknown"):
            continue

        print(f"  {bold(f'──── Port {port}/{svc["proto"]} — {service_name} {svc["version"]} ────')}")

        best_results = []
        for query in svc["queries"]:
            results = run_searchsploit(query)
            if results:
                # Classify all
                for exp in results:
                    priority = classify_exploit(exp.get("Title", ""))
                    best_results.append((priority, exp))

            if best_results:
                break  # Got results, no need for vaguer queries

        if not best_results:
            log("[-]", "No exploits found", dim)
            print()
            continue

        # Deduplicate by EDB-ID
        seen_ids = set()
        unique = []
        for priority, exp in best_results:
            eid = exp.get("EDB-ID", "")
            if eid and eid in seen_ids:
                continue
            seen_ids.add(eid)
            unique.append((priority, exp))

        unique.sort(key=lambda x: x[0])

        # Show top N
        shown = 0
        for priority, exp in unique:
            if shown >= top_n:
                remaining = len(unique) - shown
                log("", f"    {dim(f'... and {remaining} more (use --all to see everything)')}")
                break
            format_exploit(exp, index=shown + 1)
            edb_id = exp.get("EDB-ID", "")
            if edb_id and priority <= 2:
                print(f"      {cyan(f'searchsploit -m {edb_id}')}")
            print()
            shown += 1

        all_findings[f"{port}/{service_name}"] = unique

    # Final summary
    print(f"\n  {bold(red('═' * 50))}")
    print(f"  {bold('EXPLOIT SUMMARY')}")
    print(f"  {dim('─' * 50)}")

    total_rce = 0
    for key, results in all_findings.items():
        rce_count = sum(1 for p, _ in results if p <= 2)
        total = len(results)
        total_rce += rce_count

        if rce_count > 0:
            log("[!!!]", f"{bold(key)}: {red(f'{rce_count} RCE/High')} out of {total} exploits", green)
        else:
            log("[*]", f"{key}: {total} exploits (no RCE)", dim)

    if total_rce > 0:
        print(f"\n  {green(f'[!!!] {total_rce} high-priority exploit(s) found — grab and test!')}")
    else:
        print(f"\n  {dim('No RCE exploits found — check for auth bypass, LFI, or try broader queries')}")

    print(f"  {bold(red('═' * 50))}\n")


# ═══════════════════════════════════════════════════════════
#              GITHUB POC SEARCH
# ═══════════════════════════════════════════════════════════

def search_github(query):
    """Search GitHub for PoC exploits (requires internet)."""
    log("[*]", f"Searching GitHub for: {bold(query)}", cyan)

    try:
        import urllib.request
        import urllib.parse

        search_url = (
            f"https://api.github.com/search/repositories?"
            f"q={urllib.parse.quote(query + ' exploit OR poc OR CVE')}"
            f"&sort=stars&order=desc&per_page=10"
        )

        req = urllib.request.Request(search_url)
        req.add_header("User-Agent", "HuskyExploitFinder/1.0")
        req.add_header("Accept", "application/vnd.github.v3+json")

        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        items = data.get("items", [])
        if not items:
            log("[-]", "No GitHub repos found", dim)
            return

        log("[+]", f"{len(items)} GitHub repo(s) found:", green)
        print()

        for repo in items[:10]:
            name = repo.get("full_name", "")
            desc = repo.get("description", "") or ""
            stars = repo.get("stargazers_count", 0)
            url = repo.get("html_url", "")
            lang = repo.get("language", "") or ""

            star_str = f"★{stars}" if stars else ""
            lang_str = f"[{lang}]" if lang else ""

            priority = classify_exploit(name + " " + desc)
            color_fn = PRIORITY_LABELS.get(priority, (dim, ""))[0]

            print(f"    {color_fn(name)} {dim(star_str)} {dim(lang_str)}")
            if desc:
                print(f"      {dim(desc[:100])}")
            print(f"      {cyan(url)}")
            print(f"      {green(f'git clone {url}.git')}")
            print()

    except Exception as e:
        log("[!]", f"GitHub search failed: {e}", yellow)
        log("[*]", "Try manually: https://github.com/search?q=<service>+exploit", dim)


# ═══════════════════════════════════════════════════════════
#              CVE LOOKUP
# ═══════════════════════════════════════════════════════════

def lookup_cve(cve_id):
    """Look up a specific CVE and find exploits for it."""
    print(f"\n  {bold(cyan(f'═══ CVE Lookup: {cve_id} ═══'))}\n")

    # searchsploit
    search_and_display(cve_id)

    # GitHub
    search_github(cve_id)


# ═══════════════════════════════════════════════════════════
#                    QUICK SEARCH
# ═══════════════════════════════════════════════════════════

def quick_search(query, exact=False):
    """Quick manual search."""
    print(f"\n  {bold(cyan('═══ Exploit Search ═══'))}\n")
    search_and_display(query, exact=exact)

    # Also try GitHub
    search_github(query)


# ═══════════════════════════════════════════════════════════
#                        CLI
# ═══════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Husky Exploit Finder — searchsploit on steroids",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Search by service + version
              xfind search "Apache 2.4.49"
              xfind search "OpenSSH 7.2"
              xfind search "Drupal 7"

              # Parse nmap output and search all services
              xfind nmap nmap_scan.txt
              xfind nmap ./recon/10.10.10.5/nmap/quick_tcp.txt

              # Look up a specific CVE
              xfind cve CVE-2021-41773

              # Search GitHub for PoCs
              xfind github "Apache 2.4.49 RCE"
              xfind github "CVE-2021-41773"

              # Exact match (stricter searchsploit results)
              xfind search "vsftpd 2.3.4" --exact
        """),
    )

    sub = p.add_subparsers(dest="mode", help="Search mode")

    # Manual search
    sr = sub.add_parser("search", help="Search by service name + version")
    sr.add_argument("query", nargs="+", help="Search terms (e.g. 'Apache 2.4.49')")
    sr.add_argument("--exact", action="store_true", help="Exact match only")

    # Nmap file
    nm = sub.add_parser("nmap", help="Parse nmap output and search all services")
    nm.add_argument("file", help="nmap -oN output file")
    nm.add_argument("--top", type=int, default=10, help="Max results per service (default: 10)")
    nm.add_argument("--all", action="store_true", help="Show all results (no limit)")

    # CVE lookup
    cv = sub.add_parser("cve", help="Look up a specific CVE")
    cv.add_argument("cve_id", help="CVE identifier (e.g. CVE-2021-41773)")

    # GitHub search
    gh = sub.add_parser("github", help="Search GitHub for PoC exploits")
    gh.add_argument("query", nargs="+", help="Search terms")

    return p.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    if not args.mode:
        print(f"  Usage: python3 xfind.py {{search,nmap,cve,github}} [options]")
        print(f"\n  {bold('Quick start:')}")
        print(f"    {cyan('python3 xfind.py search')} {dim('\"Apache 2.4.49\"')}")
        print(f"    {cyan('python3 xfind.py nmap')}   {dim('nmap_scan.txt')}")
        print(f"    {cyan('python3 xfind.py cve')}    {dim('CVE-2021-41773')}")
        print(f"    {cyan('python3 xfind.py github')} {dim('\"vsftpd 2.3.4 backdoor\"')}\n")
        sys.exit(0)

    if args.mode == "search":
        query = " ".join(args.query)
        quick_search(query, exact=args.exact)

    elif args.mode == "nmap":
        top_n = 999 if args.all else args.top
        scan_from_nmap(args.file, top_n=top_n)

    elif args.mode == "cve":
        lookup_cve(args.cve_id)

    elif args.mode == "github":
        query = " ".join(args.query)
        search_github(query)


if __name__ == "__main__":
    main()
