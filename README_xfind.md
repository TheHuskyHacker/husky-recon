# Husky Exploit Finder (xfind)

Searchsploit on steroids. Searches exploit-db, classifies results by exploit type (RCE → auth bypass → LFI → privesc → DoS), parses nmap output to search all services automatically, searches GitHub for PoCs, and prints the exact `searchsploit -m` mirror commands.

No pip dependencies. Requires: `searchsploit` (sudo apt install exploitdb).

---

## Install

```bash
chmod +x xfind.py
sudo ln -s $(pwd)/xfind.py /usr/local/bin/xfind
```

---

## Usage

```bash
# Search by service + version
xfind search "Apache 2.4.49"
xfind search "OpenSSH 7.2"
xfind search "Drupal 7"
xfind search "vsftpd 2.3.4" --exact

# Feed it your nmap output — searches every service automatically
xfind nmap nmap_scan.txt
xfind nmap ./recon/10.10.10.5/nmap/quick_tcp.txt
xfind nmap nmap_scan.txt --all    # show everything, no limit

# Look up a specific CVE (searches exploit-db + GitHub)
xfind cve CVE-2021-41773
xfind cve CVE-2021-22204

# Search GitHub for PoC repos
xfind github "Apache 2.4.49 RCE"
xfind github "CVE-2021-41773"
```

---

## How It Works

### Priority Classification

Every exploit result is classified by type and sorted so you see RCE first:

| Priority | Type | Color |
|---|---|---|
| CRITICAL | Remote Code Execution, Command Injection, Shell Upload | Red |
| HIGH | Auth Bypass, SQLi, File Upload | Yellow |
| MEDIUM | LFI, Path Traversal, File Read, Buffer Overflow | Cyan |
| USEFUL | Privilege Escalation | Magenta |
| LOW | XSS, CSRF, Open Redirect | Gray |
| NOISE | Denial of Service (skip on OSCP) | Gray |

### Nmap Mode

Parses an nmap `-oN` output file, extracts every service+version, and searches exploit-db for each one. Deduplicates results, prioritizes by exploit type, and prints a summary showing which ports have RCE-level exploits.

```
══════════════════════════════════════════════════
EXPLOIT SUMMARY
──────────────────────────────────────────────────
[!!!] 80/http: 3 RCE/High out of 12 exploits
[*]   22/ssh: 5 exploits (no RCE)
[!!!] 445/smb: 1 RCE/High out of 8 exploits

[!!!] 4 high-priority exploit(s) found — grab and test!
══════════════════════════════════════════════════
```

### Mirror Commands

For every high-priority exploit, the tool prints the exact commands:

```
searchsploit -m 50383
https://www.exploit-db.com/exploits/50383
```

### GitHub PoC Search

Searches GitHub for exploit repositories, sorted by stars. Prints the `git clone` command for each.

---

## Exam Day Workflow

```bash
# Run your nmap scan (Rule 1)
nmap -sCV -p- --open -oN scan.txt $target

# Feed it straight into xfind
xfind nmap scan.txt

# See "Apache 2.4.49" flagged as CRITICAL RCE?
# Mirror it instantly
searchsploit -m 50383

# Or search GitHub for a cleaner PoC
xfind github "CVE-2021-41773"
git clone <repo_url>

# Found a CVE mentioned somewhere? Look it up
xfind cve CVE-2021-22204
```

---

## Options

| Command | Flag | Description |
|---|---|---|
| `search` | `query` | Search terms (e.g. "Apache 2.4.49") |
| `search` | `--exact` | Exact match only |
| `nmap` | `file` | nmap -oN output file path |
| `nmap` | `--top N` | Max results per service (default: 10) |
| `nmap` | `--all` | Show all results |
| `cve` | `cve_id` | CVE identifier (e.g. CVE-2021-41773) |
| `github` | `query` | Search terms for GitHub |

---

## Pairs With

```bash
# huskyrecon generates nmap output → xfind consumes it
sudo huskyrecon 10.10.10.5
xfind nmap ./recon/10.10.10.5/nmap/quick_tcp.txt

# fruitpicker finds versions → xfind finds exploits
sudo fruitpicker 10.10.10.5
xfind search "Apache 2.4.49"
```

---

## License

MIT
