#!/usr/bin/env python3
"""
Husky Recon — automated initial enumeration pipeline.

Takes a target IP, runs the full nmap → web → SMB → SNMP → FTP → DNS
dance in parallel, organizes output into clean folders, and flags
quick wins at the end.

Requires: python-nmap (pip install python-nmap), nmap installed.
Optional: gobuster, whatweb, enum4linux-ng, snmpwalk,
          smbclient, dig, ftp (standard Kali install).
"""

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import nmap as pynmap
except ImportError:
    print("[!] python-nmap not installed. Run: pip install python-nmap")
    sys.exit(1)

# ───────────────── ANSI helpers ───────────────────────────

def _has_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_C = _has_color()

def _a(code, t): return f"\033[{code}m{t}\033[0m" if _C else t
def red(t):     return _a("91", t)
def green(t):   return _a("92", t)
def yellow(t):  return _a("93", t)
def blue(t):    return _a("94", t)
def magenta(t): return _a("95", t)
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

    {bold('A U T O - R E C O N   P I P E L I N E')}
    {dim('Full enum. Zero typing.')}
"""

# ───────────────── globals ────────────────────────────────

LOCK = threading.Lock()
QUICK_WINS = []
RUNNING_PROCS = []

def log(icon, msg, color_fn=None):
    with LOCK:
        ts = time.strftime("%H:%M:%S")
        prefix = f"  {dim(ts)}"
        if color_fn:
            print(f"{prefix} {color_fn(icon)} {msg}")
        else:
            print(f"{prefix} {icon} {msg}")

def win(msg):
    with LOCK:
        QUICK_WINS.append(msg)
    log("[!!!]", msg, green)

def tool_exists(name):
    return shutil.which(name) is not None

def run_cmd(cmd, outfile=None, timeout=None):
    """Run a command, optionally save output, return (returncode, stdout)."""
    try:
        # Create output directory BEFORE the command runs
        # (nmap -oN needs the dir to exist)
        if outfile:
            Path(outfile).parent.mkdir(parents=True, exist_ok=True)

        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
        with LOCK:
            RUNNING_PROCS.append(proc)

        stdout, _ = proc.communicate(timeout=timeout)
        output = stdout.decode("utf-8", errors="replace")

        with LOCK:
            if proc in RUNNING_PROCS:
                RUNNING_PROCS.remove(proc)

        if outfile:
            with open(outfile, "w") as f:
                f.write(output)

        return proc.returncode, output
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        with LOCK:
            if proc in RUNNING_PROCS:
                RUNNING_PROCS.remove(proc)
        return -1, f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return -1, str(e)


def parse_nmap_ports(nmap_output):
    """Extract open ports and services from nmap output."""
    ports = {}
    for line in nmap_output.split("\n"):
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
        if m:
            port = int(m.group(1))
            proto = m.group(2)
            service = m.group(3)
            version = m.group(4).strip()
            ports[port] = {
                "proto": proto,
                "service": service,
                "version": version,
            }
    return ports


# ═══════════════════════════════════════════════════════════
#                    SCAN MODULES (python-nmap)
# ═══════════════════════════════════════════════════════════

def _pynmap_to_ports(nm):
    """Convert python-nmap result to our ports dict and save readable output."""
    ports = {}
    lines = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                entry = nm[host][proto][port]
                if entry.get("state") == "open":
                    product = entry.get("product", "")
                    version = entry.get("version", "")
                    extrainfo = entry.get("extrainfo", "")
                    ver_str = " ".join(x for x in [product, version, extrainfo] if x).strip()
                    ports[port] = {
                        "proto": proto,
                        "service": entry.get("name", "unknown"),
                        "version": ver_str,
                    }
                    lines.append(f"{port}/{proto}  open  {entry.get('name','')}  {ver_str}")
    return ports, "\n".join(lines)


def _save_nmap_output(nm, outfile):
    """Save readable nmap results to file."""
    Path(outfile).parent.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append(f"# Nmap scan - {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"# Command: {nm.command_line()}")
    lines.append("")
    for host in nm.all_hosts():
        lines.append(f"Host: {host} ({nm[host].hostname()})")
        lines.append(f"State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            lines.append(f"\nProtocol: {proto}")
            lines.append(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'VERSION'}")
            for port in sorted(nm[host][proto].keys()):
                e = nm[host][proto][port]
                product = e.get("product", "")
                version = e.get("version", "")
                extrainfo = e.get("extrainfo", "")
                ver_str = " ".join(x for x in [product, version, extrainfo] if x).strip()
                lines.append(f"{port:<10} {e['state']:<10} {e.get('name',''):<15} {ver_str}")
    with open(outfile, "w") as f:
        f.write("\n".join(lines) + "\n")


def nmap_quick(target, outdir):
    """Full TCP scan - all 65535 ports with service detection using python-nmap."""
    log("[*]", f"Nmap full TCP scan starting (-p- --min-rate 1000)...", cyan)
    outfile = f"{outdir}/nmap/quick_tcp.txt"

    nm = pynmap.PortScanner()
    try:
        nm.scan(hosts=target, ports="1-65535",
                arguments="-sC -sV -Pn --open --min-rate 1000")
    except pynmap.PortScannerError as e:
        log("[!]", f"Nmap error: {e}", red)
        if "requires root" in str(e).lower():
            log("[*]", "Run with sudo for SYN scan", yellow)
        return {}
    except Exception as e:
        log("[!]", f"Scan failed: {e}", red)
        return {}

    ports, _ = _pynmap_to_ports(nm)
    _save_nmap_output(nm, outfile)

    if ports:
        for port, info in sorted(ports.items()):
            svc = info["service"]
            ver = info["version"]
            log("[+]", f"Port {green(str(port))}/{info['proto']} — {bold(svc)} {dim(ver)}")

            if svc == "ftp" and "Anonymous" in ver:
                win(f"FTP Anonymous access on port {port}")
            if "Apache" in ver or "nginx" in ver or "IIS" in ver:
                if re.search(r"[\d.]+", ver):
                    log("[*]", f"Web server version exposed: {ver}", yellow)
    else:
        log("[-]", "No open ports found in scan", red)

    log("[+]", f"Scan done — {len(ports)} ports → {dim(outfile)}", green)
    return ports


def nmap_full_tcp(target, outdir):
    """Full TCP port scan - all 65535 (background, no scripts)."""
    log("[*]", "Nmap full TCP scan (all ports, background)...", cyan)
    outfile = f"{outdir}/nmap/full_tcp.txt"

    nm = pynmap.PortScanner()
    try:
        nm.scan(hosts=target, ports="1-65535",
                arguments="-Pn --open --min-rate 1000")
    except Exception as e:
        log("[!]", f"Full scan error: {e}", red)
        return {}

    ports, _ = _pynmap_to_ports(nm)
    _save_nmap_output(nm, outfile)
    log("[+]", f"Full TCP done — {len(ports)} ports → {dim(outfile)}", green)
    return ports


def nmap_udp(target, outdir):
    """Top UDP ports scan."""
    log("[*]", "Nmap UDP scan (top 50)...", cyan)
    outfile = f"{outdir}/nmap/udp.txt"

    nm = pynmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments="-Pn -sU --top-ports 50 --open")
    except Exception as e:
        log("[!]", f"UDP scan error: {e}", red)
        return {}

    ports, _ = _pynmap_to_ports(nm)
    _save_nmap_output(nm, outfile)

    for port, info in sorted(ports.items()):
        log("[+]", f"UDP {green(str(port))} — {bold(info['service'])} {dim(info['version'])}")
        if info["service"] == "snmp":
            win(f"SNMP open on UDP {port}")
    log("[+]", f"UDP scan done — {len(ports)} ports → {dim(outfile)}", green)
    return ports


def nmap_vuln(target, outdir, ports_str):
    """Run nmap vuln scripts against discovered ports."""
    log("[*]", "Nmap vulnerability scripts...", cyan)
    outfile = f"{outdir}/nmap/vuln.txt"

    nm = pynmap.PortScanner()
    try:
        nm.scan(hosts=target, ports=ports_str,
                arguments="-Pn --script vuln")
    except Exception as e:
        log("[!]", f"Vuln scan error: {e}", red)
        return

    # Save output
    _save_nmap_output(nm, outfile)

    # Check for vuln findings in script output
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                entry = nm[host][proto][port]
                if "script" in entry:
                    for script_name, script_output in entry["script"].items():
                        if "VULNERABLE" in script_output or "CVE-" in script_output:
                            win(f"Vuln on {port}: {script_name}")

    log("[+]", f"Vuln scripts done → {dim(outfile)}", green)


# ── Web enumeration ──

def web_enum(target, port, outdir, scheme="http", wordlist=None):
    """Run web enumeration on an HTTP port."""
    base_url = f"{scheme}://{target}:{port}"
    web_dir = f"{outdir}/web/{scheme}_{port}"
    Path(web_dir).mkdir(parents=True, exist_ok=True)

    # whatweb
    if tool_exists("whatweb"):
        log("[*]", f"WhatWeb fingerprint on {base_url}...", cyan)
        outfile = f"{web_dir}/whatweb.txt"
        cmd = f"whatweb -a 3 --color=never {base_url}"
        rc, output = run_cmd(cmd, outfile=outfile, timeout=60)
        # Flag interesting tech
        for tech in ["WordPress", "Drupal", "Joomla", "Tomcat", "PHP", "ASP.NET"]:
            if tech.lower() in output.lower():
                log("[+]", f"Technology detected: {bold(tech)}", green)

    # gobuster directory scan
    if tool_exists("gobuster"):
        wl = wordlist or "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wl):
            wl = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        if not os.path.exists(wl):
            wl = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"

        if os.path.exists(wl):
            log("[*]", f"Gobuster dir scan on {base_url}...", cyan)
            outfile = f"{web_dir}/gobuster_dir.txt"
            cmd = (f"gobuster dir -u {base_url} -w {wl} "
                   f"-t 30 -q --no-error -o {outfile} "
                   f"-x php,html,txt,asp,aspx,jsp,bak,old,conf")
            rc, output = run_cmd(cmd, timeout=300)

            # Flag interesting finds
            interesting = ["/admin", "/login", "/upload", "/api", "/config",
                         "/backup", "/dev", "/test", "/portal", "/support",
                         "/shell", ".env", "web.config", "wp-config", ".git"]
            if os.path.exists(outfile):
                with open(outfile) as f:
                    content = f.read()
                for path in interesting:
                    if path in content.lower():
                        win(f"Interesting web path on {port}: {path}")

            log("[+]", f"Gobuster done → {dim(outfile)}", green)
        else:
            log("[-]", "No wordlist found for gobuster — install seclists", yellow)
    else:
        log("[-]", "gobuster not installed — skipping directory scan", yellow)

    # nikto (if enabled)
    if tool_exists("nikto"):
        log("[*]", f"Nikto scan on {base_url}...", cyan)
        outfile = f"{web_dir}/nikto.txt"
        cmd = f"nikto -h {base_url} -o {outfile} -Format txt -maxtime 180s"
        rc, output = run_cmd(cmd, timeout=240)
        log("[+]", f"Nikto done → {dim(outfile)}", green)

    # curl headers
    log("[*]", f"Grabbing headers from {base_url}...", cyan)
    outfile = f"{web_dir}/headers.txt"
    cmd = f"curl -sIkL {base_url}"
    rc, output = run_cmd(cmd, outfile=outfile, timeout=15)
    # Check for security headers
    for header in ["X-Powered-By", "Server"]:
        for line in output.split("\n"):
            if line.lower().startswith(header.lower()):
                log("[*]", f"Header disclosure: {line.strip()}", yellow)


# ── SMB enumeration ──

def smb_enum(target, outdir):
    """SMB enumeration — shares, users, null sessions."""
    smb_dir = f"{outdir}/smb"
    Path(smb_dir).mkdir(parents=True, exist_ok=True)

    # smbclient list shares
    if tool_exists("smbclient"):
        log("[*]", "SMB — listing shares (null session)...", cyan)
        outfile = f"{smb_dir}/shares_null.txt"
        cmd = f"smbclient -N -L //{target}/ 2>&1"
        rc, output = run_cmd(cmd, outfile=outfile, timeout=30)
        if "Sharename" in output and "NT_STATUS_ACCESS_DENIED" not in output:
            win(f"SMB null session — shares listed!")
            for line in output.split("\n"):
                line = line.strip()
                if line and not line.startswith("-") and "Sharename" not in line:
                    parts = line.split()
                    if parts and parts[0] not in ("Server", "Workgroup", ""):
                        log("[+]", f"Share: {green(parts[0])}", green)

        # Try guest session
        outfile = f"{smb_dir}/shares_guest.txt"
        cmd = f"smbclient -U 'guest%' -L //{target}/ 2>&1"
        rc, output = run_cmd(cmd, outfile=outfile, timeout=30)
        if "Sharename" in output and "NT_STATUS_ACCESS_DENIED" not in output:
            win(f"SMB guest session — shares listed!")

    # enum4linux-ng
    if tool_exists("enum4linux-ng"):
        log("[*]", "enum4linux-ng running...", cyan)
        outfile = f"{smb_dir}/enum4linux.txt"
        cmd = f"enum4linux-ng -A {target} 2>&1"
        rc, output = run_cmd(cmd, outfile=outfile, timeout=120)

        if "username:" in output.lower() or "user:" in output.lower():
            log("[+]", "enum4linux found usernames — check output", green)
        log("[+]", f"enum4linux done → {dim(outfile)}", green)

    elif tool_exists("enum4linux"):
        log("[*]", "enum4linux running...", cyan)
        outfile = f"{smb_dir}/enum4linux.txt"
        cmd = f"enum4linux -a {target} 2>&1"
        rc, output = run_cmd(cmd, outfile=outfile, timeout=120)
        log("[+]", f"enum4linux done → {dim(outfile)}", green)

    # crackmapexec quick check
    if tool_exists("crackmapexec"):
        log("[*]", "crackmapexec SMB fingerprint...", cyan)
        outfile = f"{smb_dir}/cme_smb.txt"
        cmd = f"crackmapexec smb {target} 2>&1"
        rc, output = run_cmd(cmd, outfile=outfile, timeout=30)
        if output.strip():
            # Extract OS / hostname / domain info
            log("[+]", f"CME: {output.strip().split(chr(10))[0][:100]}", green)

    elif tool_exists("netexec"):
        log("[*]", "netexec SMB fingerprint...", cyan)
        outfile = f"{smb_dir}/nxc_smb.txt"
        cmd = f"netexec smb {target} 2>&1"
        rc, output = run_cmd(cmd, outfile=outfile, timeout=30)
        if output.strip():
            log("[+]", f"NXC: {output.strip().split(chr(10))[0][:100]}", green)

    # rpcclient null session
    if tool_exists("rpcclient"):
        log("[*]", "RPC null session check...", cyan)
        outfile = f"{smb_dir}/rpcclient_null.txt"
        cmd = f"rpcclient -U '' -N {target} -c 'enumdomusers' 2>&1"
        rc, output = run_cmd(cmd, outfile=outfile, timeout=30)
        if "user:" in output.lower() and "NT_STATUS" not in output:
            win("RPC null session — domain users enumerated!")


# ── SNMP enumeration ──

def snmp_enum(target, outdir):
    """SNMP enumeration with common community strings."""
    snmp_dir = f"{outdir}/snmp"
    Path(snmp_dir).mkdir(parents=True, exist_ok=True)

    if not tool_exists("snmpwalk"):
        log("[-]", "snmpwalk not installed — skipping SNMP enum", yellow)
        return

    communities = ["public", "private", "community", "manager"]

    for comm in communities:
        log("[*]", f"SNMP walk with community '{comm}'...", cyan)
        outfile = f"{snmp_dir}/snmpwalk_{comm}.txt"
        cmd = f"snmpwalk -v2c -c {comm} {target} 2>&1"
        rc, output = run_cmd(cmd, outfile=outfile, timeout=60)

        if rc == 0 and "Timeout" not in output and len(output) > 100:
            win(f"SNMP community '{comm}' is valid!")

            # Check for juicy OIDs
            if "hrSWRunName" in output or "hrSWInstalledName" in output:
                log("[+]", "SNMP exposes running processes / installed software", green)
            if "sysDescr" in output:
                for line in output.split("\n"):
                    if "sysDescr" in line:
                        log("[+]", f"System: {line.split('STRING:')[-1].strip()[:80]}", green)
                        break

            # Extended walk on interesting OIDs
            extended_oids = {
                "processes": "1.3.6.1.2.1.25.4.2.1.2",
                "software": "1.3.6.1.2.1.25.6.3.1.2",
                "tcp_ports": "1.3.6.1.2.1.6.13.1.3",
                "users": "1.3.6.1.4.1.77.1.2.25",
            }
            for name, oid in extended_oids.items():
                ext_outfile = f"{snmp_dir}/snmp_{name}.txt"
                ext_cmd = f"snmpwalk -v2c -c {comm} {target} {oid} 2>&1"
                run_cmd(ext_cmd, outfile=ext_outfile, timeout=30)

            break  # Found a working community, no need to try others

    # snmp-check if available
    if tool_exists("snmp-check"):
        log("[*]", "snmp-check running...", cyan)
        outfile = f"{snmp_dir}/snmp-check.txt"
        cmd = f"snmp-check {target} 2>&1"
        rc, output = run_cmd(cmd, outfile=outfile, timeout=90)
        log("[+]", f"snmp-check done → {dim(outfile)}", green)


# ── FTP enumeration ──

def ftp_enum(target, port, outdir):
    """Test FTP anonymous login and list files."""
    ftp_dir = f"{outdir}/ftp"
    Path(ftp_dir).mkdir(parents=True, exist_ok=True)

    log("[*]", f"FTP anonymous login test on port {port}...", cyan)
    outfile = f"{ftp_dir}/anon_login.txt"
    # Use curl for a clean anonymous FTP listing
    cmd = f"curl -s --connect-timeout 10 --max-time 30 ftp://anonymous:anonymous@{target}:{port}/ 2>&1"
    rc, output = run_cmd(cmd, outfile=outfile, timeout=45)

    if rc == 0 and output.strip() and "530" not in output and "Login incorrect" not in output:
        win(f"FTP Anonymous login successful on port {port}!")
        for line in output.strip().split("\n")[:10]:
            log("[+]", f"  {line.strip()}", green)
        if output.strip().count("\n") > 10:
            log("[*]", f"  ... and more — see {outfile}", dim)
    else:
        log("[-]", "FTP anonymous login failed", dim)


# ── DNS enumeration ──

def dns_enum(target, outdir, domain=None):
    """DNS enumeration — zone transfer, reverse lookup."""
    dns_dir = f"{outdir}/dns"
    Path(dns_dir).mkdir(parents=True, exist_ok=True)

    if not tool_exists("dig"):
        log("[-]", "dig not installed — skipping DNS enum", yellow)
        return

    # Try to get the domain from reverse lookup if not provided
    if not domain:
        log("[*]", "DNS reverse lookup...", cyan)
        cmd = f"dig -x {target} @{target} +short 2>&1"
        rc, output = run_cmd(cmd, timeout=15)
        if rc == 0 and output.strip() and "SERVFAIL" not in output:
            # Extract domain from PTR
            ptr = output.strip().rstrip(".")
            if "." in ptr:
                parts = ptr.split(".")
                if len(parts) >= 2:
                    domain = ".".join(parts[-2:])
                    log("[+]", f"Domain from PTR: {bold(domain)}", green)

    if domain:
        # Zone transfer
        log("[*]", f"Attempting zone transfer for {domain}...", cyan)
        outfile = f"{dns_dir}/axfr_{domain}.txt"
        cmd = f"dig axfr {domain} @{target} 2>&1"
        rc, output = run_cmd(cmd, outfile=outfile, timeout=30)
        if "XFR size" in output or (rc == 0 and output.count("\n") > 10):
            win(f"DNS Zone Transfer successful for {domain}!")
        else:
            log("[-]", "Zone transfer failed (as expected)", dim)

        # Any records
        outfile = f"{dns_dir}/any_{domain}.txt"
        cmd = f"dig any {domain} @{target} 2>&1"
        rc, output = run_cmd(cmd, outfile=outfile, timeout=15)

    # Version query
    outfile = f"{dns_dir}/version.txt"
    cmd = f"dig version.bind chaos txt @{target} +short 2>&1"
    rc, output = run_cmd(cmd, outfile=outfile, timeout=15)
    if output.strip() and "REFUSED" not in output:
        log("[+]", f"DNS version: {output.strip()}", green)


# ── LDAP enumeration ──

def ldap_enum(target, outdir):
    """LDAP anonymous bind check."""
    ldap_dir = f"{outdir}/ldap"
    Path(ldap_dir).mkdir(parents=True, exist_ok=True)

    if not tool_exists("ldapsearch"):
        log("[-]", "ldapsearch not installed — skipping LDAP enum", yellow)
        return

    log("[*]", "LDAP anonymous bind check...", cyan)
    outfile = f"{ldap_dir}/anonymous.txt"
    cmd = f"ldapsearch -x -H ldap://{target} -b '' -s base namingContexts 2>&1"
    rc, output = run_cmd(cmd, outfile=outfile, timeout=30)

    if "namingContexts" in output:
        win("LDAP anonymous bind successful!")
        # Extract base DN
        for line in output.split("\n"):
            if "namingContexts:" in line:
                base_dn = line.split(":")[-1].strip()
                log("[+]", f"Base DN: {bold(base_dn)}", green)

                # Full dump
                outfile2 = f"{ldap_dir}/full_dump.txt"
                cmd2 = f"ldapsearch -x -H ldap://{target} -b '{base_dn}' 2>&1"
                run_cmd(cmd2, outfile=outfile2, timeout=60)
                log("[+]", f"Full LDAP dump → {dim(outfile2)}", green)
                break


# ═══════════════════════════════════════════════════════════
#                    ORCHESTRATOR
# ═══════════════════════════════════════════════════════════

def run_recon(args):
    target = args.target
    outdir = args.output or f"./recon/{target}"
    Path(outdir).mkdir(parents=True, exist_ok=True)

    start_time = time.time()
    print(f"\n  {bold('Target:')}  {bold(green(target))}")
    print(f"  {bold('Output:')}  {outdir}")
    print(f"  {bold('Started:')} {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {dim('─' * 50)}\n")

    # ── Phase 1: Quick nmap to discover ports ──
    log("═══", bold("PHASE 1: Port Discovery"), cyan)
    ports = nmap_quick(target, outdir)

    if not ports:
        log("[!]", "Quick scan found no open ports on top 1000", yellow)
        log("[*]", "Running full 65535 port scan — services may be on non-standard ports...", cyan)

        # Run full scan immediately (not background) and use those results
        full_ports = nmap_full_tcp(target, outdir)
        if full_ports:
            ports = full_ports
            log("[+]", f"Full scan found {len(ports)} port(s)!", green)
            for port, info in sorted(ports.items()):
                svc = info["service"]
                ver = info["version"]
                log("[+]", f"Port {port}/{info['proto']} — {svc} {ver}")
        else:
            log("[!]", "Full scan also found nothing — target may be down or fully filtered", red)
            if not args.force:
                return

    # Kick off full TCP + UDP in background
    background = []
    with ThreadPoolExecutor(max_workers=3) as bg_pool:
        if not args.skip_full:
            background.append(bg_pool.submit(nmap_full_tcp, target, outdir))
            background.append(bg_pool.submit(nmap_udp, target, outdir))

        # ── Phase 2: Service-specific enumeration ──
        log("\n═══", bold("PHASE 2: Service Enumeration"), cyan)

        service_futures = []
        with ThreadPoolExecutor(max_workers=args.threads) as svc_pool:

            for port, info in sorted(ports.items()):
                svc = info["service"].lower()

                # Web servers
                if svc in ("http", "http-proxy", "http-alt") or port in (80, 8080, 8888, 8000, 9090):
                    service_futures.append(
                        svc_pool.submit(web_enum, target, port, outdir, "http", args.wordlist))

                elif svc in ("https", "ssl/http", "https-alt") or port in (443, 8443):
                    service_futures.append(
                        svc_pool.submit(web_enum, target, port, outdir, "https", args.wordlist))

                # SMB
                elif port in (139, 445) or svc in ("microsoft-ds", "netbios-ssn"):
                    service_futures.append(svc_pool.submit(smb_enum, target, outdir))

                # FTP
                elif svc == "ftp" or port == 21:
                    service_futures.append(svc_pool.submit(ftp_enum, target, port, outdir))

                # DNS
                elif svc == "domain" or port == 53:
                    service_futures.append(
                        svc_pool.submit(dns_enum, target, outdir, args.domain))

                # SNMP (from UDP or if manually specified)
                elif svc == "snmp" or port == 161:
                    service_futures.append(svc_pool.submit(snmp_enum, target, outdir))

                # LDAP
                elif svc in ("ldap", "ldaps") or port in (389, 636):
                    service_futures.append(svc_pool.submit(ldap_enum, target, outdir))

            # Also check for SNMP even if not in TCP results
            if 161 not in ports and not args.skip_udp:
                service_futures.append(svc_pool.submit(snmp_enum, target, outdir))

            # Wait for all service scans
            for f in as_completed(service_futures):
                try:
                    f.result()
                except Exception as e:
                    log("[!]", f"Scan error: {e}", red)

        # ── Phase 3: Vuln scripts ──
        if not args.skip_vuln and ports:
            log("\n═══", bold("PHASE 3: Vulnerability Scripts"), cyan)
            ports_str = ",".join(str(p) for p in sorted(ports.keys()))
            nmap_vuln(target, outdir, ports_str)

        # Wait for background full scans
        if background:
            log("\n═══", bold("BACKGROUND: Full scans completing..."), cyan)
            for f in as_completed(background):
                try:
                    extra_ports = f.result()
                    if extra_ports:
                        new_ports = set(extra_ports.keys()) - set(ports.keys())
                        if new_ports:
                            log("[+]", f"Full scan found {len(new_ports)} additional port(s): "
                                f"{', '.join(str(p) for p in sorted(new_ports))}", yellow)
                except Exception as e:
                    log("[!]", f"Background scan error: {e}", red)

    # ── Summary ──
    elapsed = time.time() - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)

    print(f"\n  {bold(red('═' * 50))}")
    print(f"  {bold('RECON COMPLETE')}")
    print(f"  {dim('─' * 50)}")
    print(f"  Target:    {bold(target)}")
    print(f"  Duration:  {minutes}m {seconds}s")
    print(f"  Output:    {outdir}/")

    # List output structure
    print(f"\n  {bold('Output structure:')}")
    for root, dirs, files in os.walk(outdir):
        level = root.replace(outdir, "").count(os.sep)
        indent = "    " + "  " * level
        dirname = os.path.basename(root)
        if level == 0:
            dirname = outdir
        print(f"{indent}{dim(dirname + '/')}")
        for file in sorted(files):
            filepath = os.path.join(root, file)
            size = os.path.getsize(filepath)
            size_str = f"{size/1024:.1f}K" if size > 1024 else f"{size}B"
            print(f"{indent}  {file} {dim(f'({size_str})')}")

    # Quick wins
    if QUICK_WINS:
        print(f"\n  {bold(green('═══ QUICK WINS ═══'))}")
        for w in QUICK_WINS:
            print(f"  {green('[!!!]')} {w}")
    else:
        print(f"\n  {dim('No quick wins flagged — manual review recommended')}")

    print(f"  {bold(red('═' * 50))}\n")

    # Save summary
    summary_file = f"{outdir}/SUMMARY.txt"
    with open(summary_file, "w") as f:
        f.write(f"Husky Recon Summary\n")
        f.write(f"{'=' * 40}\n")
        f.write(f"Target:   {target}\n")
        f.write(f"Date:     {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Duration: {minutes}m {seconds}s\n\n")
        f.write(f"Open Ports:\n")
        for port, info in sorted(ports.items()):
            f.write(f"  {port}/{info['proto']} — {info['service']} {info['version']}\n")
        f.write(f"\nQuick Wins:\n")
        for w in QUICK_WINS:
            f.write(f"  [!!!] {w}\n")
        if not QUICK_WINS:
            f.write("  None flagged\n")


# ═══════════════════════════════════════════════════════════
#                        CLI
# ═══════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Husky Recon — automated initial enumeration pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              huskyrecon 10.10.10.5
              huskyrecon 10.10.10.5 -o ./loot/target1
              huskyrecon 192.168.1.50 --domain corp.local
              huskyrecon 10.10.10.5 --skip-vuln --threads 8
              huskyrecon 10.10.10.5 -w /usr/share/seclists/Discovery/Web-Content/big.txt
        """),
    )
    p.add_argument("target", help="Target IP address")
    p.add_argument("-o", "--output", help="Output directory (default: ./recon/<target>)")
    p.add_argument("-d", "--domain", help="Domain name for DNS zone transfers")
    p.add_argument("-w", "--wordlist", help="Custom wordlist for web directory scanning")
    p.add_argument("--threads", type=int, default=4,
                   help="Parallel service scan threads (default: 4)")
    p.add_argument("--skip-full", action="store_true",
                   help="Skip full 65535-port TCP scan")
    p.add_argument("--skip-udp", action="store_true",
                   help="Skip UDP scan")
    p.add_argument("--skip-vuln", action="store_true",
                   help="Skip nmap vuln scripts")
    p.add_argument("--force", action="store_true",
                   help="Continue even if quick scan finds no open ports")
    return p.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    # Check for root (nmap SYN scan needs it)
    if os.geteuid() != 0:
        log("[!]", f"Running without root — nmap will use connect scan (slower)", yellow)
        log("[*]", f"Run with {bold('sudo')} for SYN scan + UDP", dim)

    # Check for essential tools
    missing = []
    for tool in ["nmap"]:
        if not tool_exists(tool):
            missing.append(tool)
    if missing:
        log("[!]", f"Missing required tools: {', '.join(missing)}", red)
        sys.exit(1)

    optional = ["gobuster", "whatweb", "enum4linux-ng", "snmpwalk",
                "smbclient", "dig", "nikto", "ldapsearch", "crackmapexec"]
    available = [t for t in optional if tool_exists(t)]
    not_available = [t for t in optional if not tool_exists(t)]
    if not_available:
        log("[*]", f"Optional tools missing (will skip): {dim(', '.join(not_available))}", dim)

    # Handle Ctrl+C gracefully
    def handler(sig, frame):
        print(f"\n\n  {red('[!]')} Interrupted — killing running scans...")
        with LOCK:
            for proc in RUNNING_PROCS:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    pass
        sys.exit(1)
    signal.signal(signal.SIGINT, handler)

    run_recon(args)


if __name__ == "__main__":
    main()
