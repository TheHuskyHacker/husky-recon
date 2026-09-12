# Husky WebRecon

Deep web application enumeration on a single target URL. Runs whatweb, directory busting, sensitive file hunting, HTML/JS intelligence extraction, header auditing, and more — all in one shot.

Requires: `requests` (pip install requests). Optional tools: whatweb, gobuster/feroxbuster, nikto.

---

## Install

```bash
git clone https://github.com/YOUR_USER/huskytools.git
cd huskytools
pip install requests
chmod +x webrecon.py
sudo ln -s $(pwd)/webrecon.py /usr/local/bin/webrecon
```

---

## Usage

```bash
# Full scan on a web target
python3 webrecon.py http://10.10.10.5

# Custom port + output dir
python3 webrecon.py http://10.10.10.5:8080 -o ./loot/web

# Custom wordlist for directory scanning
python3 webrecon.py http://target.htb -w /usr/share/seclists/Discovery/Web-Content/big.txt

# Quick mode — skip the slow stuff
python3 webrecon.py http://10.10.10.5 --skip-dirs --skip-nikto --skip-vhosts
```

---

## What It Scans

| Module | What It Does |
|---|---|
| **Header Analysis** | Info disclosure (Server, X-Powered-By, debug tokens), missing security headers (HSTS, CSP, X-Frame-Options), cookie flag audit |
| **WhatWeb** | Technology fingerprinting — CMS, frameworks, languages, server versions |
| **robots.txt / sitemap.xml** | Parses disallowed paths and sitemap URLs |
| **Sensitive File Hunt** | 50+ paths: .env, .git, configs, backups, database dumps, admin panels, phpinfo, debug consoles, API docs, phpMyAdmin, Adminer |
| **HTML Intelligence** | Comment extraction, email harvesting, form/upload detection, internal path discovery, generator meta tags |
| **JS Endpoint Scan** | API endpoints, internal URLs, hardcoded secrets (API keys, AWS keys, auth tokens) across all linked JS files |
| **Directory Scan** | feroxbuster or gobuster with common extensions (php, html, txt, asp, aspx, jsp, bak, old, conf, zip, sql) |
| **VHost Enum** | Virtual host discovery via gobuster (hostname targets only) |
| **Nikto** | Web vulnerability scanner |

---

## Output Structure

```
./webrecon/10.10.10.5/
  headers.txt
  whatweb.txt
  robots.txt
  sitemap.xml
  sensitive_files.txt
  html_intel.txt
  js_endpoints.txt
  directory_scan.txt
  vhosts.txt
  nikto.txt
```

All findings are flagged with `[!!!]` during the scan and collected in a summary at the end.

---

## Options

| Flag | Description | Default |
|---|---|---|
| `url` | Target URL | required |
| `-o, --output` | Output directory | `./webrecon/<host>` |
| `-w, --wordlist` | Custom directory scan wordlist | common.txt / dirb |
| `--skip-dirs` | Skip directory brute force | off |
| `--skip-nikto` | Skip nikto scan | off |
| `--skip-vhosts` | Skip vhost enumeration | off |

---

## License

MIT
