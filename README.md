# Husky Recon — Auto-Recon Pipeline

Full initial enumeration on autopilot. Takes a target IP, discovers ports, branches into service-specific enumeration in parallel, organizes everything into clean folders, and flags quick wins at the end.

Stop typing the same nmap → gobuster → enum4linux dance at the start of every box.

Zero external Python dependencies — just needs the standard Kali tools installed.

---

## Install

```bash
git clone https://github.com/YOUR_USER/huskyrecon.git
cd huskyrecon
chmod +x huskyrecon.py
sudo ln -s $(pwd)/huskyrecon.py /usr/local/bin/huskyrecon
```

---

## Usage

```bash
# Full auto — just give it a target
sudo huskyrecon 10.10.10.5

# Specify domain for DNS zone transfers
sudo huskyrecon 10.10.10.5 -d corp.local

# Custom output directory
sudo huskyrecon 10.10.10.5 -o ./loot/box1

# Custom wordlist for web scanning
sudo huskyrecon 10.10.10.5 -w /usr/share/seclists/Discovery/Web-Content/big.txt

# Quick scan only (skip full 65535 + UDP + vuln scripts)
sudo huskyrecon 10.10.10.5 --skip-full --skip-udp --skip-vuln

# More parallel threads for service scans
sudo huskyrecon 10.10.10.5 --threads 8
```

---

## What It Does

### Phase 1: Port Discovery
- **Quick nmap** — top 1000 TCP ports with service/version detection and default scripts
- **Full TCP** — all 65535 ports (runs in background while service scans start)
- **UDP** — top 50 UDP ports (runs in background)

### Phase 2: Service Enumeration (parallel)

Automatically branches based on discovered services:

| Port/Service | What It Runs |
|---|---|
| **HTTP/HTTPS** (80, 443, 8080, etc.) | whatweb fingerprint, gobuster dir scan (php/html/txt/asp/jsp/bak extensions), nikto, header grab |
| **SMB** (139, 445) | smbclient null/guest share listing, enum4linux-ng, crackmapexec/netexec fingerprint, rpcclient null session |
| **FTP** (21) | Anonymous login test, directory listing |
| **DNS** (53) | Reverse lookup, zone transfer attempt, version query |
| **SNMP** (161) | snmpwalk with public/private/community/manager, extended OID walks (processes, software, users, TCP ports), snmp-check |
| **LDAP** (389, 636) | Anonymous bind check, base DN extraction, full dump |

### Phase 3: Vulnerability Scripts
- nmap `--script vuln` against all discovered ports
- Flags any CVE hits as quick wins

### Output
Everything organized into:
```
./recon/10.10.10.5/
  nmap/
    quick_tcp.txt
    full_tcp.txt
    udp.txt
    vuln.txt
  web/
    http_80/
      whatweb.txt
      gobuster_dir.txt
      nikto.txt
      headers.txt
    https_443/
      ...
  smb/
    shares_null.txt
    shares_guest.txt
    enum4linux.txt
    cme_smb.txt
    rpcclient_null.txt
  ftp/
    anon_login.txt
  dns/
    axfr_domain.txt
    version.txt
  snmp/
    snmpwalk_public.txt
    snmp_processes.txt
    snmp_users.txt
  ldap/
    anonymous.txt
    full_dump.txt
  SUMMARY.txt
```

---

## Quick Wins

The tool automatically flags these during the scan:

- FTP anonymous access
- SMB null/guest sessions
- RPC null session (user enumeration)
- SNMP valid community strings
- DNS zone transfer success
- LDAP anonymous bind
- Web server version disclosure
- Nmap vuln script CVE hits
- Interesting web paths (admin, upload, login, .env, wp-config, etc.)

All quick wins are collected and printed at the end, plus saved to `SUMMARY.txt`.

---

## Options

| Flag | Description | Default |
|---|---|---|
| `target` | Target IP address | required |
| `-o, --output` | Output directory | `./recon/<target>` |
| `-d, --domain` | Domain for DNS zone transfers | auto-detected from PTR |
| `-w, --wordlist` | Custom gobuster wordlist | common.txt / dirb |
| `--threads` | Parallel service scan threads | 4 |
| `--skip-full` | Skip full 65535-port TCP scan | off |
| `--skip-udp` | Skip UDP scan | off |
| `--skip-vuln` | Skip nmap vuln scripts | off |
| `--force` | Continue even with no open ports | off |

---

## Tool Dependencies

Only `nmap` is required. Everything else is optional and skipped gracefully:

**Required:** nmap

**Optional (standard Kali install):** gobuster, whatweb, enum4linux-ng (or enum4linux), snmpwalk, snmp-check, smbclient, rpcclient, dig, nikto, ldapsearch, crackmapexec (or netexec), curl

---

## License

MIT
