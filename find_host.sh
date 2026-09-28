#!/bin/bash
# find_hosts.sh — Quick subnet host discovery via ping sweep

if [[ -z "$1" ]]; then
    echo "Usage: $0 <subnet>"
    echo "Example: $0 192.168.1"
    exit 1
fi

SUBNET="$1"
TIMEOUT=1
ALIVE=()

echo "[*] Scanning ${SUBNET}.0/24..."
echo ""

for host in $(seq 1 254); do
    ping -c 1 -W "$TIMEOUT" "${SUBNET}.${host}" &>/dev/null && {
        echo "[+] Host found: ${SUBNET}.${host}"
        ALIVE+=("${SUBNET}.${host}")
    } &
done

wait

echo ""
echo "[*] Scan complete. ${#ALIVE[@]} host(s) found."
