# Husky Recon — Auto-Recon Pipeline

Automated initial enumeration pipeline. Takes a target IP, runs a full nmap port scan with service detection, then kicks off parallel service-specific enumeration — web, SMB, SNMP, FTP, DNS, LDAP — organizes output into clean folders, and flags quick wins at the end.

Uses `python-nmap` for reliable port scanning. No more subprocess parsing issues.

**Part of the [Husky Hacker](https://medium.com/@TheHuskyHacker) toolkit.**

---

## Install

```bash
# Required
sudo pip install python-nmap --break-system-packages

# Clone
git clone https://github.com/TheHuskyHacker/husky-recon
cd husky-recon
chmod +x huskyrecon.py
```

**Important:** Use `sudo pip` — the script runs with sudo for SYN scans, and root's Python needs to see the package.

---

## Usage

```bash
# Standard full recon
sudo python3 huskyrecon.py 10.10.10.5

# Custom output directory
sudo python3 huskyrecon.py 10.10.10.5 -o ./loot/target1

# With domain for DNS zone transfers
sudo python3 huskyrecon.py 10.10.10.5 -d corp.local

# Custom wordlist for web directories
sudo python3 huskyrecon.py 10.10.10.5 -w /usr/share/seclists/Discovery/Web-Content/big.txt

# Skip slow scans
sudo python3 huskyrecon.py 10.10.10.5 --skip-vuln --skip-udp

# More parallel threads
sudo python3 huskyrecon.py 10.10.10.5 --threads 8

# Force continue even if no ports found
sudo python3 huskyrecon.py 10.10.10.5 --force
```

---

## What It Does

### Phase 1: Port Discovery
Scans all 65535 TCP ports with service detection using python-nmap:
- `-sC -sV -Pn -p- --open --min-rate 1000`
- If no ports found, auto-runs a second full scan as fallback
- UDP top 50 ports in background
- Flags quick wins immediately (FTP anon, web server versions)

### Phase 2: Service Enumeration (Parallel)
Based on discovered ports, runs service-specific checks in parallel:

| Service | Port(s) | What It Runs |
|---|---|---|
| **HTTP/HTTPS** | 80, 443, 8080+ | whatweb, gobuster (dir + extensions), nikto, header grab |
| **SMB** | 139, 445 | smbclient null/guest, enum4linux-ng, crackmapexec, rpcclient |
| **FTP** | 21 | Anonymous login test, file listing |
| **SNMP** | 161 (UDP) | Community string check (public/private/community/manager), extended OID walks |
| **DNS** | 53 | Reverse lookup, zone transfer, version query |
| **LDAP** | 389, 636 | Anonymous bind check, base DN extraction, full dump |

### Phase 3: Vulnerability Scripts
Runs `nmap --script vuln` against all discovered ports and flags CVEs.

---

## Output Structure

```
./recon/10.10.10.5/
├── nmap/
│   ├── quick_tcp.txt        Full TCP scan results
│   ├── full_tcp.txt         Background full scan
│   ├── udp.txt              UDP top 50
│   └── vuln.txt             Vulnerability scripts
├── web/
│   ├── http_80/
│   │   ├── whatweb.txt      Technology fingerprint
│   │   ├── gobuster_dir.txt Directory scan
│   │   ├── nikto.txt        Vulnerability scan
│   │   └── headers.txt      HTTP headers
│   └── https_443/
├── smb/
│   ├── shares_null.txt      Null session shares
│   ├── shares_guest.txt     Guest session shares
│   ├── enum4linux.txt       Full SMB enum
│   ├── cme_smb.txt          CrackMapExec fingerprint
│   └── rpcclient_null.txt   RPC null session
├── snmp/
│   ├── snmpwalk_public.txt  Community string walk
│   ├── snmp_users.txt       User enumeration
│   ├── snmp_processes.txt   Running processes
│   └── snmp-check.txt       Full SNMP dump
├── ftp/
│   └── anon_login.txt       Anonymous login test
├── dns/
│   ├── axfr_domain.txt      Zone transfer attempt
│   └── version.txt          DNS version
├── ldap/
│   ├── anonymous.txt        Anonymous bind
│   └── full_dump.txt        Full LDAP dump
└── SUMMARY.txt              Quick reference with all findings
```

---

## Quick Wins

The script flags high-value findings as they're discovered:

```
[!!!] FTP Anonymous login successful on port 21!
[!!!] SMB null session — shares listed!
[!!!] SNMP community 'public' is valid!
[!!!] LDAP anonymous bind successful!
[!!!] RPC null session — domain users enumerated!
[!!!] Interesting web path on 80: /admin
[!!!] Vuln on 445: smb-vuln-ms17-010
```

---

## Options

| Flag | Description | Default |
|---|---|---|
| `target` | Target IP address | required |
| `-o, --output` | Output directory | `./recon/<target>` |
| `-d, --domain` | Domain for DNS zone transfers | auto-detect |
| `-w, --wordlist` | Custom web directory wordlist | common.txt |
| `--threads` | Parallel service scan threads | 4 |
| `--skip-full` | Skip background full TCP scan | off |
| `--skip-udp` | Skip UDP scan | off |
| `--skip-vuln` | Skip nmap vuln scripts | off |
| `--force` | Continue if no ports found | off |

---

## Optional Tools

Skips gracefully if missing — all pre-installed on Kali:

| Tool | What For | Install |
|---|---|---|
| gobuster | Directory scanning | `sudo apt install gobuster` |
| whatweb | Tech fingerprinting | `sudo apt install whatweb` |
| nikto | Web vuln scanning | `sudo apt install nikto` |
| enum4linux-ng | SMB enumeration | `sudo apt install enum4linux` |
| smbclient | SMB share access | `sudo apt install smbclient` |
| snmpwalk | SNMP enumeration | `sudo apt install snmp` |
| snmp-check | SNMP dump | `sudo apt install snmp-check` |
| crackmapexec | SMB fingerprinting | `sudo apt install crackmapexec` |
| dig | DNS queries | `sudo apt install dnsutils` |
| ldapsearch | LDAP queries | `sudo apt install ldap-utils` |

---

## Pairs With

```bash
# Feed nmap results into exploit finder
xfind nmap ./recon/10.10.10.5/nmap/quick_tcp.txt

# Deep web enum on HTTP ports
webrecon http://10.10.10.5

# Low-hanging fruit check
fruitpicker 10.10.10.5

# Test web input points found by gobuster
webtester sqli -u "http://10.10.10.5/login.php" --param user -m POST
```

---

## License

MIT
