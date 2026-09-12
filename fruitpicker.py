#!/usr/bin/env python3
"""
Husky Fruit Picker — low-hanging fruit detector for individual boxes.

Takes a target IP, identifies services, and checks every one for
quick wins: anonymous access, default creds, known CVE versions,
misconfigurations. Tells you what to hit first.

Requires: requests (pip install requests)
Optional tools: nmap, smbclient, rpcclient, snmpwalk, ftp, dig,
                hydra, enum4linux-ng, crackmapexec/netexec
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

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

    {bold('F R U I T   P I C K E R')}
    {dim('Find the easy wins. Hit them first.')}
"""

TIMEOUT = 10
FRUITS = []  # (priority, category, description, details)

def fruit(priority, category, desc, details=""):
    """Register a finding. Priority: 1=critical, 2=high, 3=medium."""
    FRUITS.append((priority, category, desc, details))

def tool_exists(name):
    return shutil.which(name) is not None

def run_cmd(cmd, timeout=60):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=timeout)
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return -1, "[TIMEOUT]"
    except Exception as e:
        return -1, str(e)

def log(icon, msg, color_fn=None):
    if color_fn:
        print(f"  {color_fn(icon)} {msg}")
    else:
        print(f"  {icon} {msg}")


# ═══════════════════════════════════════════════════════════
#               SERVICE CHECKERS
# ═══════════════════════════════════════════════════════════

def check_ftp(target, port=21):
    """Check FTP for anonymous access."""
    log("[*]", f"FTP :{port} — anonymous login check...", cyan)

    # curl method
    rc, output = run_cmd(f"curl -s --connect-timeout 5 --max-time 10 "
                        f"ftp://anonymous:anonymous@{target}:{port}/ 2>&1", timeout=15)
    if rc == 0 and output.strip() and "530" not in output and "Login incorrect" not in output:
        fruit(1, "FTP", f"Anonymous FTP login on port {port}",
              f"curl ftp://anonymous:anonymous@{target}:{port}/")
        # Check for interesting files
        for keyword in [".txt", ".conf", ".bak", ".sql", ".zip", ".pcap", "password", "backup"]:
            if keyword in output.lower():
                fruit(1, "FTP", f"Interesting file in anonymous FTP: contains '{keyword}'")
        return

    # Check for writable
    rc2, output2 = run_cmd(f"curl -s -T /dev/null ftp://anonymous:anonymous@{target}:{port}/test_write 2>&1", timeout=10)
    if "uploaded" in output2.lower() or rc2 == 0:
        fruit(1, "FTP", f"FTP anonymous WRITE access on port {port}",
              "Upload a webshell if FTP root overlaps with web root")

    log("[-]", "FTP anonymous login failed", dim)


def check_smb(target):
    """Check SMB for null/guest sessions and open shares."""
    log("[*]", "SMB — null session & share enumeration...", cyan)

    # smbclient null session
    if tool_exists("smbclient"):
        rc, output = run_cmd(f"smbclient -N -L //{target}/ 2>&1", timeout=15)
        if "Sharename" in output and "NT_STATUS_ACCESS_DENIED" not in output:
            fruit(1, "SMB", "Null session — shares listed!",
                  f"smbclient -N -L //{target}/")
            # Extract share names
            for line in output.split("\n"):
                line = line.strip()
                if line and "Disk" in line:
                    share = line.split()[0]
                    if share.lower() not in ("ipc$", "print$"):
                        # Try to connect
                        rc2, out2 = run_cmd(f"smbclient -N '//{target}/{share}' -c 'ls' 2>&1", timeout=10)
                        if "NT_STATUS" not in out2 and ("blocks" in out2 or "." in out2):
                            fruit(1, "SMB", f"Readable share: {share}",
                                  f"smbclient -N '//{target}/{share}'")

        # Guest session
        rc, output = run_cmd(f"smbclient -U 'guest%' -L //{target}/ 2>&1", timeout=15)
        if "Sharename" in output and "NT_STATUS_ACCESS_DENIED" not in output:
            fruit(2, "SMB", "Guest session — shares accessible",
                  f"smbclient -U 'guest%' -L //{target}/")

    # RPC null session
    if tool_exists("rpcclient"):
        rc, output = run_cmd(f"rpcclient -U '' -N {target} -c 'enumdomusers' 2>&1", timeout=15)
        if "user:" in output.lower() and "NT_STATUS" not in output:
            fruit(1, "SMB", "RPC null session — domain users enumerated!",
                  f"rpcclient -U '' -N {target} -c 'enumdomusers'")
            # Count users
            user_count = output.lower().count("user:")
            log("[+]", f"  Found {user_count} domain user(s)", green)

    # CME/NXC fingerprint
    for tool in ["crackmapexec", "netexec"]:
        if tool_exists(tool):
            rc, output = run_cmd(f"{tool} smb {target} 2>&1", timeout=15)
            if output.strip():
                # Check for signing not required
                if "signing:False" in output or "signing: False" in output:
                    fruit(2, "SMB", "SMB signing not required — relay attacks possible")
                log("[+]", f"  {output.strip().split(chr(10))[0][:100]}", green)
            break


def check_snmp(target):
    """Check SNMP for default community strings."""
    log("[*]", "SNMP — community string check...", cyan)

    if not tool_exists("snmpwalk"):
        # Fallback to Python
        log("[-]", "snmpwalk not installed — skipping", dim)
        return

    communities = ["public", "private", "community", "manager", "admin"]
    for comm in communities:
        rc, output = run_cmd(f"snmpwalk -v2c -c {comm} {target} system 2>&1", timeout=15)
        if rc == 0 and "Timeout" not in output and "sysDescr" in output:
            fruit(1, "SNMP", f"Community string '{comm}' valid!",
                  f"snmpwalk -v2c -c {comm} {target}")

            # Extract system description
            for line in output.split("\n"):
                if "sysDescr" in line:
                    log("[+]", f"  {line.split('STRING:')[-1].strip()[:80]}", green)
                    break

            # Check for user enum
            rc2, out2 = run_cmd(f"snmpwalk -v2c -c {comm} {target} 1.3.6.1.4.1.77.1.2.25 2>&1", timeout=15)
            if "STRING:" in out2:
                users = re.findall(r'STRING:\s*"?(\S+)"?', out2)
                if users:
                    fruit(1, "SNMP", f"SNMP user enumeration — found {len(users)} user(s): {', '.join(users[:5])}",
                          f"snmpwalk -v2c -c {comm} {target} 1.3.6.1.4.1.77.1.2.25")
            return

    log("[-]", "No valid SNMP community strings found", dim)


def check_dns(target):
    """Check DNS for zone transfers."""
    log("[*]", "DNS — zone transfer check...", cyan)

    if not tool_exists("dig"):
        log("[-]", "dig not installed — skipping", dim)
        return

    # Try reverse lookup first
    rc, output = run_cmd(f"dig -x {target} @{target} +short 2>&1", timeout=10)
    domain = None
    if rc == 0 and output.strip() and "SERVFAIL" not in output:
        ptr = output.strip().rstrip(".")
        if "." in ptr:
            parts = ptr.split(".")
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else None
            log("[+]", f"  PTR record: {ptr} → domain: {domain}", green)

    if domain:
        rc, output = run_cmd(f"dig axfr {domain} @{target} 2>&1", timeout=15)
        if "XFR size" in output or output.count("\n") > 15:
            fruit(1, "DNS", f"Zone transfer successful for {domain}!",
                  f"dig axfr {domain} @{target}")
        else:
            log("[-]", f"Zone transfer failed for {domain}", dim)


def check_ldap(target):
    """Check LDAP for anonymous bind."""
    log("[*]", "LDAP — anonymous bind check...", cyan)

    if not tool_exists("ldapsearch"):
        log("[-]", "ldapsearch not installed — skipping", dim)
        return

    rc, output = run_cmd(f"ldapsearch -x -H ldap://{target} -b '' -s base namingContexts 2>&1", timeout=15)
    if "namingContexts" in output:
        fruit(1, "LDAP", "Anonymous LDAP bind successful!",
              f"ldapsearch -x -H ldap://{target} -b '' -s base namingContexts")

        # Extract base DN for further enum
        for line in output.split("\n"):
            if "namingContexts:" in line:
                base_dn = line.split(":")[-1].strip()
                log("[+]", f"  Base DN: {base_dn}", green)
                fruit(2, "LDAP", f"Base DN: {base_dn} — dump with ldapsearch -b '{base_dn}'")
                break
    else:
        log("[-]", "LDAP anonymous bind failed", dim)


def check_http(target, port, scheme="http"):
    """Check HTTP for default pages, known apps, version leaks."""
    url = f"{scheme}://{target}:{port}"
    log("[*]", f"HTTP :{port} — quick checks...", cyan)

    try:
        resp = requests.get(url, timeout=TIMEOUT, verify=False,
                           headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
    except Exception:
        log("[-]", f"Could not connect to {url}", dim)
        return

    headers = resp.headers
    html = resp.text.lower()

    # Server version leak
    server = headers.get("Server", "")
    if server:
        log("[+]", f"  Server: {bold(server)}", green)
        # Known vulnerable versions
        vuln_patterns = [
            (r"apache/2\.4\.(49|50)", "CVE-2021-41773 — Apache path traversal/RCE"),
            (r"apache/2\.4\.7", "Potentially vulnerable Apache (old)"),
            (r"iis/6\.0", "IIS 6.0 — CVE-2017-7269 WebDAV RCE"),
            (r"iis/7\.[05]", "IIS 7.x — check for short filename vuln"),
            (r"nginx/1\.(1[0-9]|[0-9]\b)", "Old nginx version"),
            (r"tomcat/[4-8]", "Tomcat — check /manager and /host-manager"),
        ]
        for pattern, vuln in vuln_patterns:
            if re.search(pattern, server, re.IGNORECASE):
                fruit(2, "HTTP", f"Port {port}: {vuln}", server)

    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        log("[+]", f"  X-Powered-By: {bold(powered_by)}", green)

    # CMS / app detection
    cms_checks = [
        ("wordpress", "WordPress", ["/wp-login.php", "/wp-admin/"]),
        ("drupal", "Drupal", ["/user/login", "/admin/config"]),
        ("joomla", "Joomla", ["/administrator/"]),
        ("tomcat", "Tomcat", ["/manager/html", "/host-manager/html"]),
        ("jenkins", "Jenkins", ["/login"]),
        ("gitlab", "GitLab", ["/users/sign_in"]),
        ("grafana", "Grafana", ["/login"]),
        ("roundcube", "Roundcube", ["/roundcube/"]),
        ("phpmyadmin", "phpMyAdmin", ["/phpmyadmin/"]),
    ]

    for keyword, name, paths in cms_checks:
        if keyword in html or keyword in server.lower() or keyword in powered_by.lower():
            fruit(2, "HTTP", f"Port {port}: {name} detected — check for default creds / known CVEs")
            for path in paths:
                try:
                    r = requests.get(urljoin(url, path), timeout=5, verify=False,
                                    headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)
                    if r.status_code in (200, 302):
                        log("[+]", f"  {name} path accessible: {path}", green)
                except Exception:
                    pass
            break

    # Default pages
    default_indicators = [
        "apache2 ubuntu default page",
        "welcome to nginx",
        "iis windows server",
        "default web site page",
        "it works!",
        "test page for the apache",
    ]
    for indicator in default_indicators:
        if indicator in html:
            fruit(3, "HTTP", f"Port {port}: Default web page — directory bust for hidden content")
            break

    # File upload detection
    if 'type="file"' in html or "enctype" in html:
        fruit(2, "HTTP", f"Port {port}: File upload form detected — test with upfi.py")

    # Login forms
    if 'type="password"' in html:
        log("[+]", f"  Login form detected", green)


def check_ssh(target, port=22):
    """Check SSH banner for version and weak config."""
    log("[*]", f"SSH :{port} — banner grab...", cyan)

    rc, output = run_cmd(f"ssh -o BatchMode=yes -o ConnectTimeout=5 "
                        f"-o StrictHostKeyChecking=no -p {port} "
                        f"nobody@{target} 2>&1", timeout=10)

    # Extract banner
    for line in output.split("\n"):
        if "SSH-" in line or "OpenSSH" in line:
            log("[+]", f"  Banner: {bold(line.strip())}", green)
            if "OpenSSH" in line:
                ver_match = re.search(r'OpenSSH[_\s]([\d.]+)', line)
                if ver_match:
                    ver = ver_match.group(1)
                    # Flag old versions
                    major_minor = float(ver.rsplit(".", 1)[0]) if "." in ver else 0
                    if major_minor < 7.7:
                        fruit(3, "SSH", f"Port {port}: Old OpenSSH {ver} — check for user enum CVE-2018-15473")
            break

    if "Permission denied" not in output and "publickey" not in output:
        log("[+]", f"  Password auth may be enabled", green)


def check_mssql(target, port=1433):
    """Check MSSQL for default/weak credentials."""
    log("[*]", f"MSSQL :{port} — default cred check...", cyan)

    default_creds = [("sa", ""), ("sa", "sa"), ("sa", "password"), ("sa", "Password1")]

    for user, passwd in default_creds:
        try:
            # Use sqsh or impacket if available
            if tool_exists("impacket-mssqlclient"):
                rc, output = run_cmd(
                    f"impacket-mssqlclient '{user}:{passwd}'@{target} -port {port} "
                    f"-windows-auth 2>&1 | head -5", timeout=10)
                if "SQL>" in output or "mssql" in output.lower():
                    fruit(1, "MSSQL", f"Port {port}: Default creds work: {user}:{passwd or '(blank)'}",
                          f"impacket-mssqlclient '{user}:{passwd}'@{target} -port {port}")
                    return
        except Exception:
            pass

    log("[-]", "No default MSSQL creds worked", dim)


def check_mysql(target, port=3306):
    """Check MySQL for default/weak credentials."""
    log("[*]", f"MySQL :{port} — default cred check...", cyan)

    if not tool_exists("mysql"):
        log("[-]", "mysql client not installed — skipping", dim)
        return

    default_creds = [("root", ""), ("root", "root"), ("root", "toor"), ("root", "password")]
    for user, passwd in default_creds:
        p_flag = f"-p'{passwd}'" if passwd else ""
        rc, output = run_cmd(f"mysql -h {target} -P {port} -u {user} {p_flag} "
                            f"-e 'SELECT version();' 2>&1", timeout=10)
        if "version" in output.lower() and "ERROR" not in output:
            fruit(1, "MySQL", f"Port {port}: Default creds: {user}:{passwd or '(blank)'}",
                  f"mysql -h {target} -u {user} {p_flag}")
            return

    log("[-]", "No default MySQL creds worked", dim)


def check_rdp(target, port=3389):
    """Check RDP for NLA and basic info."""
    log("[*]", f"RDP :{port} — NLA check...", cyan)

    rc, output = run_cmd(f"nmap -p {port} --script rdp-ntlm-info {target} 2>&1", timeout=30)
    if "Target_Name:" in output or "DNS_Computer_Name:" in output:
        for line in output.split("\n"):
            if "Target_Name:" in line or "DNS_Computer_Name:" in line or "DNS_Domain_Name:" in line:
                log("[+]", f"  {line.strip().lstrip('|').strip()}", green)
                fruit(3, "RDP", f"Port {port}: {line.strip().lstrip('|').strip()}")


# ═══════════════════════════════════════════════════════════
#                    ORCHESTRATOR
# ═══════════════════════════════════════════════════════════

from urllib.parse import urljoin

def parse_nmap_output(output):
    """Parse nmap output to get port/service pairs."""
    services = {}
    for line in output.split("\n"):
        m = re.match(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
        if m:
            port = int(m.group(1))
            proto = m.group(2)
            svc = m.group(3)
            ver = m.group(4).strip()
            services[port] = {"proto": proto, "service": svc, "version": ver}
    return services


def run_fruit_picker(args):
    target = args.target
    outdir = args.output or f"./fruit/{target}"
    Path(outdir).mkdir(parents=True, exist_ok=True)

    start = time.time()
    print(f"\n  {bold('Target:')} {bold(green(target))}")
    print(f"  {bold('Output:')} {outdir}")
    print(f"  {dim('─' * 50)}\n")

    # Port discovery
    if args.ports:
        # Manual port list
        services = {}
        for entry in args.ports.split(","):
            parts = entry.strip().split("/")
            port = int(parts[0])
            svc = parts[1] if len(parts) > 1 else "unknown"
            services[port] = {"proto": "tcp", "service": svc, "version": ""}
    else:
        log("[*]", "Running nmap service scan...", cyan)
        nmap_out = f"{outdir}/nmap.txt"
        rc, output = run_cmd(f"nmap -sCV -T4 --open -oN {nmap_out} {target}", timeout=300)
        services = parse_nmap_output(output)

        if not services:
            log("[-]", "No open ports found", red)
            return

        print()
        for port, info in sorted(services.items()):
            log("[+]", f"Port {green(str(port))}/{info['proto']} — "
                f"{bold(info['service'])} {dim(info['version'])}")
        print()

    # Run service-specific checks
    log("═══", bold("Checking for low-hanging fruit..."), cyan)
    print()

    checked = set()

    for port, info in sorted(services.items()):
        svc = info["service"].lower()

        if svc == "ftp" or port == 21:
            check_ftp(target, port)
            print()

        if (svc in ("microsoft-ds", "netbios-ssn") or port in (139, 445)) and "smb" not in checked:
            checked.add("smb")
            check_smb(target)
            print()

        if svc == "ssh" or port == 22:
            check_ssh(target, port)
            print()

        if svc in ("http", "http-proxy") or port in (80, 8080, 8888, 8000, 9090):
            check_http(target, port, "http")
            print()

        if svc in ("https", "ssl/http") or port in (443, 8443):
            check_http(target, port, "https")
            print()

        if svc == "domain" or port == 53:
            check_dns(target)
            print()

        if svc == "snmp" or port == 161:
            check_snmp(target)
            print()

        if svc in ("ldap", "ldaps") or port in (389, 636):
            check_ldap(target)
            print()

        if svc == "ms-sql-s" or port == 1433:
            check_mssql(target, port)
            print()

        if svc == "mysql" or port == 3306:
            check_mysql(target, port)
            print()

        if svc == "ms-wbt-server" or port == 3389:
            check_rdp(target, port)
            print()

    # Also check SNMP on UDP if not already found
    if "snmp" not in checked and not args.skip_udp:
        log("[*]", "Probing UDP SNMP...", cyan)
        check_snmp(target)
        print()

    # Summary — sorted by priority
    elapsed = time.time() - start
    FRUITS.sort(key=lambda x: x[0])

    print(f"  {bold(red('═' * 50))}")
    print(f"  {bold('FRUIT PICKER RESULTS')} ({elapsed:.1f}s)")
    print(f"  {dim('─' * 50)}")

    if FRUITS:
        priority_labels = {1: red("[CRITICAL]"), 2: yellow("[HIGH]"), 3: cyan("[MEDIUM]")}
        print(f"\n  {bold('Hit these first:')}\n")
        for priority, category, desc, details in FRUITS:
            label = priority_labels.get(priority, dim("[LOW]"))
            print(f"  {label} {bold(category)} — {desc}")
            if details:
                print(f"    {dim('→')} {cyan(details)}")
        print()

        # Save to file
        with open(f"{outdir}/findings.txt", "w") as f:
            for p, cat, desc, details in FRUITS:
                f.write(f"[P{p}] {cat}: {desc}\n")
                if details:
                    f.write(f"  → {details}\n")
    else:
        print(f"\n  {dim('No low-hanging fruit found — time for deeper enumeration')}")
        print(f"  {dim('Try: webrecon.py, upfi.py, or manual service-specific enum')}\n")

    print(f"  {bold(red('═' * 50))}\n")


# ═══════════════════════════════════════════════════════════
#                        CLI
# ═══════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Husky Fruit Picker — find and prioritize low-hanging fruit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              sudo python3 fruitpicker.py 10.10.10.5
              sudo python3 fruitpicker.py 10.10.10.5 --ports "21/ftp,22/ssh,80/http,445/smb"
              sudo python3 fruitpicker.py 10.10.10.5 --skip-udp -o ./loot/box1
        """),
    )
    p.add_argument("target", help="Target IP address")
    p.add_argument("--ports", help="Manual port list (skip nmap): '21/ftp,80/http,445/smb'")
    p.add_argument("-o", "--output", help="Output directory")
    p.add_argument("--skip-udp", action="store_true", help="Skip UDP SNMP probe")
    return p.parse_args()


def main():
    args = parse_args()
    print(BANNER)
    run_fruit_picker(args)


if __name__ == "__main__":
    main()
