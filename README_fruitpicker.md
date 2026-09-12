# Husky Fruit Picker

Low-hanging fruit detector for individual boxes. Scans a target, identifies every service, and checks each one for quick wins — anonymous access, default creds, known CVE versions, misconfigurations. Results are priority-sorted so you know what to hit first.

Requires: `requests` (pip install requests). Optional tools: nmap, smbclient, rpcclient, snmpwalk, dig, ldapsearch, crackmapexec/netexec, mysql, impacket.

---

## Install

```bash
git clone https://github.com/TheHuskyHacker/husky-recon
cd huskytools
pip install requests
chmod +x fruitpicker.py
sudo ln -s $(pwd)/fruitpicker.py /usr/local/bin/fruitpicker
```

---

## Usage

```bash
# Auto-scan — discovers ports with nmap then checks everything
sudo python3 fruitpicker.py 10.10.10.5

# Already know the ports — skip nmap
sudo python3 fruitpicker.py 10.10.10.5 --ports "21/ftp,22/ssh,80/http,445/smb"

# Custom output directory
sudo python3 fruitpicker.py 10.10.10.5 -o ./loot/box1

# Skip UDP SNMP probe
sudo python3 fruitpicker.py 10.10.10.5 --skip-udp
```

---

## What It Checks

| Service | Port(s) | Checks |
|---|---|---|
| **FTP** | 21 | Anonymous login, writable upload, interesting files (.txt, .conf, .bak, .pcap, passwords) |
| **SSH** | 22 | Banner/version grab, old OpenSSH user enum (CVE-2018-15473), password auth detection |
| **HTTP/S** | 80, 443, 8080+ | Server version CVEs (Apache 2.4.49, IIS 6.0, etc.), CMS detection (WordPress, Drupal, Joomla, Tomcat, Jenkins, GitLab, Grafana, Roundcube), default pages, file upload forms, login forms |
| **SMB** | 139, 445 | Null session shares, guest session, readable share contents, RPC null session user enum, SMB signing check, CME/NXC fingerprint |
| **SNMP** | 161 (UDP) | 5 community strings (public, private, community, manager, admin), system description, user enumeration via OID walk |
| **DNS** | 53 | Reverse PTR lookup, zone transfer attempt |
| **LDAP** | 389, 636 | Anonymous bind, base DN extraction |
| **MSSQL** | 1433 | Default sa credentials (blank, sa, password, Password1) |
| **MySQL** | 3306 | Default root credentials (blank, root, toor, password) |
| **RDP** | 3389 | NLA check, NTLM info leak (hostname, domain name) |

---

## Output

Results are **priority-sorted** — attack these first:

```
═══════════════════════════════════════════════════
FRUIT PICKER RESULTS (12.3s)
──────────────────────────────────────────────────

Hit these first:

  [CRITICAL] FTP — Anonymous FTP login on port 21
    → curl ftp://anonymous:anonymous@10.10.10.5:21/

  [CRITICAL] SMB — Null session — shares listed!
    → smbclient -N -L //10.10.10.5/

  [CRITICAL] SMB — Readable share: HR
    → smbclient -N '//10.10.10.5/HR'

  [HIGH] HTTP — Port 80: WordPress detected — check for default creds / known CVEs

  [MEDIUM] SSH — Port 22: Old OpenSSH 7.4 — check for user enum CVE-2018-15473

═══════════════════════════════════════════════════
```

Priority levels:
- **CRITICAL** — direct access, credentials, or data exposure. Hit immediately.
- **HIGH** — known attack surface (CMS, vulnerable version, file uploads). Investigate next.
- **MEDIUM** — information disclosure or potential vectors. Useful for deeper enum.

Findings are also saved to `findings.txt` in the output directory.

---

## Options

| Flag | Description | Default |
|---|---|---|
| `target` | Target IP address | required |
| `--ports` | Manual port list to skip nmap (e.g. `"21/ftp,80/http,445/smb"`) | auto-scan |
| `-o, --output` | Output directory | `./fruit/<target>` |
| `--skip-udp` | Skip UDP SNMP probe | off |

---

## Pairs Well With

After Fruit Picker identifies what's interesting, go deeper:

```bash
# Found HTTP? Deep web enum
python3 webrecon.py http://10.10.10.5

# Found a file upload? Test bypass matrix
python3 upfi.py upload -u http://10.10.10.5/upload.php -d /uploads/

# Found LFI? Automate exploitation
python3 upfi.py lfi -u "http://10.10.10.5/page.php" --param file

# Got credentials? Check AD attack paths
python3 adchain.py lookup "Pass-the-Hash" -s admin -t dc01 -H 'hash'
```

---

## License

MIT
