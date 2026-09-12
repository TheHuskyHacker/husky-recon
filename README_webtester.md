# Husky Web Tester

Test web attack payloads and identify what works — you pull the trigger yourself. OSCP exam safe: no automated exploitation, just smart enumeration.

Covers SQLi detection, command injection, file upload filter bypass, and LFI/path traversal. Also dumps raw payload lists for manual use in Burp Intruder or curl loops.

Requires: `requests` (pip install requests). No other dependencies.

---

## Install

```bash
chmod +x webtester.py
sudo ln -s $(pwd)/webtester.py /usr/local/bin/webtester
```

---

## Usage

```bash
# Test a login form for SQLi
python3 webtester.py sqli -u "http://target/login.php" --param user -m POST

# Test a ping utility for command injection
python3 webtester.py cmdi -u "http://target/ping.php" --param ip

# Test what file extensions an upload form accepts (no webshells uploaded)
python3 webtester.py upload -u "http://target/upload.php" --field fileUpload

# Test a page parameter for LFI
python3 webtester.py lfi -u "http://target/index.php" --param page

# Dump payload lists for Burp Intruder
python3 webtester.py payloads --category all
python3 webtester.py payloads --category sqli > sqli_payloads.txt

# With authentication
python3 webtester.py sqli -u "http://target/search" --param q --cookie "PHPSESSID=abc123"
```

---

## Test Modes

### `sqli` — SQL Injection Detection
Sends 20+ payloads and checks for SQL error messages, time-based blind delays, boolean blind response differences, and UNION column enumeration. Detects MySQL, MSSQL, PostgreSQL, Oracle, and SQLite errors.

### `cmdi` — Command Injection Detection
Tests 20+ separator/substitution payloads (`;`, `|`, `&&`, backticks, `$()`, `%0a`, IFS bypass) and checks for command output markers (`uid=`, custom echo tokens) and time-based confirmation (`sleep`, `ping`, `timeout`).

### `upload` — Upload Filter Testing
Tests 20+ extensions × 6 MIME types × 3 magic byte headers. Uploads **benign test files only** (no webshells) to identify which extension/MIME/magic combos get accepted. Tells you exactly which filter bypass works so you can upload the real payload manually.

### `lfi` — LFI / Path Traversal
Tests 18+ traversal encodings (basic, double-dot, URL-encoded, double-encoded, overlong UTF-8, null byte) plus PHP filter wrappers for source code extraction and `data://` wrapper for RCE indicator testing.

### `payloads` — Raw Payload Dump
Dumps payload lists to stdout for use in Burp Intruder, wfuzz, or curl loops. Categories: `sqli`, `cmdi`, `lfi`, `upload`, `all`.

---

## Why This Is OSCP Exam Safe

Per the OffSec exam guide, custom Python scripts and tools like Nmap, Nikto, Burp Free, and DirBuster are allowed. What's banned is **automatic exploitation** (SQLmap, db_autopwn, etc.).

This tool identifies vulnerabilities through response analysis — it doesn't exploit them. The upload module sends benign test content, not webshells. You do the exploitation step manually and document it in your report. Same approach as using Burp Intruder, just faster.

---

## Options

| Flag | Description | Default |
|---|---|---|
| `-u, --url` | Target URL | required |
| `--param` | Parameter to test | required (except upload) |
| `-m, --method` | HTTP method | GET |
| `--field` | Upload form field name | file |
| `--cookie` | Session cookies | — |
| `--header` | Extra HTTP headers | — |
| `--category` | Payload dump category | all |

---

## License

MIT
