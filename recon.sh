#!/bin/bash
# OSCP Network Sweep & Scan
# Usage: ./oscp-sweep.sh [SUBNET] [MY_IP]
# Example: ./oscp-sweep.sh 10.0.2 10.0.2.15

SUBNET="${1:-10.0.2}"
MY_IP="${2:-10.0.2.15}"
OUTDIR="./scan_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

mkdir -p "$OUTDIR"

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  OSCP Network Sweep - $SUBNET.0/24${NC}"
echo -e "${CYAN}  Excluding: $MY_IP${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# ──────────────────────────────────────
# Phase 1: Ping Sweep
# ──────────────────────────────────────
ALIVE_FILE="$OUTDIR/alive_hosts.txt"
> "$ALIVE_FILE"

echo -e "${YELLOW}[Phase 1] Ping sweep...${NC}"
for i in $(seq 1 254); do
    ip="$SUBNET.$i"
    [[ "$ip" == "$MY_IP" ]] && continue
    (ping -c 1 -W 1 "$ip" &>/dev/null && echo "$ip" >> "$ALIVE_FILE" && echo -e "${GREEN}  [+] ALIVE: $ip${NC}") &
done
wait

# Sort and dedupe
sort -t. -k4 -n "$ALIVE_FILE" -o "$ALIVE_FILE"
HOST_COUNT=$(wc -l < "$ALIVE_FILE")

echo ""
echo -e "${GREEN}[*] Found $HOST_COUNT alive hosts${NC}"
echo ""

if [[ "$HOST_COUNT" -eq 0 ]]; then
    echo -e "${RED}[!] No hosts found via ping. Trying ARP scan...${NC}"
    if command -v arp-scan &>/dev/null; then
        arp-scan --localnet 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v "$MY_IP" | sort -t. -k4 -n > "$ALIVE_FILE"
        HOST_COUNT=$(wc -l < "$ALIVE_FILE")
        echo -e "${GREEN}[*] ARP scan found $HOST_COUNT hosts${NC}"
    else
        echo -e "${YELLOW}[!] arp-scan not available. Running nmap ping scan instead...${NC}"
        nmap -sn "$SUBNET.1-254" --exclude "$MY_IP" -oG - 2>/dev/null | grep "Up" | awk '{print $2}' | sort -t. -k4 -n > "$ALIVE_FILE"
        HOST_COUNT=$(wc -l < "$ALIVE_FILE")
        echo -e "${GREEN}[*] Nmap ping scan found $HOST_COUNT hosts${NC}"
    fi
    echo ""
fi

if [[ "$HOST_COUNT" -eq 0 ]]; then
    echo -e "${RED}[!] Still no hosts. Scanning full range anyway...${NC}"
    TARGETS="$SUBNET.1-254"
else
    TARGETS=$(paste -sd',' "$ALIVE_FILE")
fi

# ──────────────────────────────────────
# Phase 2: Quick TCP port scan (all ports)
# ──────────────────────────────────────
echo -e "${YELLOW}[Phase 2] Fast TCP scan (all ports)...${NC}"
nmap -p- --min-rate=1000 -T4 -Pn $TARGETS --exclude "$MY_IP" -oG "$OUTDIR/tcp_quick.gnmap" -oN "$OUTDIR/tcp_quick.txt" 2>/dev/null

# Extract open ports per host
echo ""
echo -e "${CYAN}  Open ports found:${NC}"
grep "Ports:" "$OUTDIR/tcp_quick.gnmap" 2>/dev/null | while read -r line; do
    host=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
    ports=$(echo "$line" | grep -oP '\d+/open' | cut -d/ -f1 | paste -sd',')
    if [[ -n "$ports" ]]; then
        echo -e "${GREEN}  $host → $ports${NC}"
        # Save per-host port list for targeted scan
        echo "$host:$ports" >> "$OUTDIR/host_ports.txt"
    fi
done

echo ""

# ──────────────────────────────────────
# Phase 3: Service + script scan on open ports
# ──────────────────────────────────────
echo -e "${YELLOW}[Phase 3] Service enumeration on open ports...${NC}"

if [[ -f "$OUTDIR/host_ports.txt" ]]; then
    while IFS=: read -r host ports; do
        echo -e "${CYAN}  Scanning $host ($ports)...${NC}"
        nmap -sC -sV -Pn -p"$ports" "$host" -oN "$OUTDIR/svc_${host}.txt" 2>/dev/null &
    done < "$OUTDIR/host_ports.txt"
    wait
else
    # Fallback: scan common ports on all targets
    nmap -sC -sV -Pn -T4 $TARGETS --exclude "$MY_IP" -oN "$OUTDIR/svc_all.txt" 2>/dev/null
fi

echo ""

# ──────────────────────────────────────
# Phase 4: Top UDP ports
# ──────────────────────────────────────
echo -e "${YELLOW}[Phase 4] UDP scan (top 50 ports)...${NC}"
nmap -sU --top-ports=50 -Pn -T4 $TARGETS --exclude "$MY_IP" -oN "$OUTDIR/udp_top50.txt" 2>/dev/null &
UDP_PID=$!

# ──────────────────────────────────────
# Phase 5: Quick wins check
# ──────────────────────────────────────
echo -e "${YELLOW}[Phase 5] Quick wins check...${NC}"

if [[ -f "$OUTDIR/host_ports.txt" ]]; then
    while IFS=: read -r host ports; do
        # SMB
        if echo "$ports" | grep -qE '(^|,)(445|139)(,|$)'; then
            echo -e "${CYAN}  [SMB] $host — checking anonymous access...${NC}"
            smbclient -L "//$host" -N 2>/dev/null | tee -a "$OUTDIR/smb_${host}.txt" | grep -i "disk\|ipc" && \
                echo -e "${GREEN}  [+] SMB shares found on $host${NC}"
        fi

        # FTP
        if echo "$ports" | grep -qE '(^|,)21(,|$)'; then
            echo -e "${CYAN}  [FTP] $host — checking anonymous login...${NC}"
            timeout 5 bash -c "echo -e 'USER anonymous\nPASS anonymous\nQUIT' | nc -w 3 $host 21" 2>/dev/null | tee -a "$OUTDIR/ftp_${host}.txt" | grep -i "230" && \
                echo -e "${GREEN}  [+] FTP anonymous login on $host!${NC}"
        fi

        # HTTP/HTTPS — flag for manual review
        if echo "$ports" | grep -qE '(^|,)(80|443|8080|8443|8000|8888|3000|5000)(,|$)'; then
            web_ports=$(echo "$ports" | tr ',' '\n' | grep -E '^(80|443|8080|8443|8000|8888|3000|5000)$' | paste -sd',')
            echo -e "${GREEN}  [WEB] $host → ports $web_ports — remember to dirbust!${NC}"
        fi

        # Kerberos = Domain Controller
        if echo "$ports" | grep -qE '(^|,)88(,|$)'; then
            echo -e "${RED}  [DC!] $host has Kerberos (88) — this is a Domain Controller!${NC}"
        fi

        # MSSQL
        if echo "$ports" | grep -qE '(^|,)1433(,|$)'; then
            echo -e "${GREEN}  [MSSQL] $host:1433 — try impacket-mssqlclient${NC}"
        fi

        # WinRM
        if echo "$ports" | grep -qE '(^|,)5985(,|$)'; then
            echo -e "${GREEN}  [WINRM] $host:5985 — evil-winrm if you get creds${NC}"
        fi

        # RDP
        if echo "$ports" | grep -qE '(^|,)3389(,|$)'; then
            echo -e "${GREEN}  [RDP] $host:3389 — xfreerdp if you get creds${NC}"
        fi

    done < "$OUTDIR/host_ports.txt"
fi

# Wait for UDP scan
echo ""
echo -e "${YELLOW}[*] Waiting for UDP scan to finish...${NC}"
wait $UDP_PID 2>/dev/null

# Check for SNMP in UDP results
if grep -q "161/open" "$OUTDIR/udp_top50.txt" 2>/dev/null; then
    SNMP_HOSTS=$(grep -B5 "161/open" "$OUTDIR/udp_top50.txt" | grep "Nmap scan report" | awk '{print $NF}')
    for h in $SNMP_HOSTS; do
        echo -e "${RED}  [SNMP!] $h:161 — run: snmpwalk -v2c -c public $h${NC}"
    done
fi

# ──────────────────────────────────────
# Summary
# ──────────────────────────────────────
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  SCAN COMPLETE${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "  Results saved to: ${GREEN}$OUTDIR/${NC}"
echo ""
echo "  Files:"
ls -1 "$OUTDIR/" 2>/dev/null | sed 's/^/    /'
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo "    1. Review service scans: cat $OUTDIR/svc_*.txt"
echo "    2. Check UDP results:    cat $OUTDIR/udp_top50.txt"
echo "    3. Dirbust any web ports you found"
echo "    4. searchsploit exact service versions"
echo "    5. Try found creds EVERYWHERE"
echo ""
