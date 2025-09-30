#!/usr/bin/env bash
# HYPERINFO — hypersenseindia
# Tool: HYPERINFO (bash)
# Project: hypersenseindia - Masterindustriesindia
# Developed by: MASTER S ASWIN
# PROTECT CODE: 321 (simple run-passcode protection)
# Script name: HYPERINFO
# Purpose: Given an IP address (or hostname), perform passive OSINT lookups and collect
#          publicly-available data: WHOIS, ASN/ISP, reverse DNS, geolocation, open banners
#          (if available via Shodan), reputation hints, and any emails/contacts found in
#          public records. The script will NOT attempt intrusive active scanning.
#
# WARNING & LEGAL NOTICE:
# - This tool only performs passive and publicly-allowed queries. Do NOT use it to
#   harass, stalk, or illegally identify private individuals. Active scanning of systems
#   you do not own or have permission to test may be illegal in your jurisdiction.
# - If you need precise subscriber info, contact the ISP or law enforcement with proper
#   authority. This tool will only display what is publicly accessible.
#
# DEPENDENCIES (install in Termux):
# pkg update && pkg upgrade -y
# pkg install -y curl jq whois bind-utils geoip iproute2
# Optional (better results):
# pip install python-whois (if you want python parsing, not required)
# Export API keys (optional):
# export IPINFO_TOKEN="your_ipinfo_token"
# export SHODAN_API_KEY="your_shodan_api_key"
#
# USAGE:
# chmod +x HYPERINFO.sh
# ./HYPERINFO.sh
# The script will ask for the passcode (321) and then for an IP address or hostname.
#
# OUTPUT: Human-readable summary printed to STDOUT; also saves a timestamped report file
# named hyperinfo_<ip>_<YYYYMMDD_HHMMSS>.txt in the current directory.

set -euo pipefail
IFS=$'\n\t'

### Configuration
PASSCODE_EXPECTED="321"
REPORT_DIR=".hyperinfo_reports"
mkdir -p "$REPORT_DIR"

timestamp() { date +"%Y-%m-%d_%H%M%S"; }

echo "========================================"
echo "HYPERINFO — hypersenseindia"
echo "Developed by: MASTER S ASWIN"
echo "========================================"

# Simple passcode protection
read -rsp $'Enter run passcode: ' input_passcode
echo
if [[ "$input_passcode" != "$PASSCODE_EXPECTED" ]]; then
  echo "Incorrect passcode. Exiting." >&2
  exit 1
fi

# Prompt for target
read -rp "Enter IP address or hostname to investigate: " TARGET
if [[ -z "$TARGET" ]]; then
  echo "No target provided. Exiting." >&2
  exit 1
fi

REPORT_FILE="$REPORT_DIR/hyperinfo_${TARGET//[^a-zA-Z0-9._-]/_}_$(timestamp).txt"

# Helper: safe command existence
require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[WARN] Required command not found: $1" >&2
  fi
}

require_cmd whois
require_cmd dig
require_cmd curl
require_cmd jq || true
require_cmd geoiplookup || true

# Start building report
{
  echo "HYPERINFO Report"
  echo "Target: $TARGET"
  echo "Generated: $(date -u) UTC"
  echo "---"
} > "$REPORT_FILE"

# 1) Resolve IP if hostname
RESOLVED_IP="$TARGET"
if [[ "$TARGET" =~ [a-zA-Z] ]]; then
  # assume hostname, resolve
  ip_resolve=$(dig +short A "$TARGET" | head -n1 || true)
  if [[ -n "$ip_resolve" ]]; then
    RESOLVED_IP="$ip_resolve"
  else
    # try IPv6 AAAA
    ip_resolve=$(dig +short AAAA "$TARGET" | head -n1 || true)
    [[ -n "$ip_resolve" ]] && RESOLVED_IP="$ip_resolve"
  fi
fi

echo "Resolved IP: $RESOLVED_IP" | tee -a "$REPORT_FILE"

# 2) WHOIS / RIR
echo "\n[WHOIS / RIR]" | tee -a "$REPORT_FILE"
if command -v whois >/dev/null 2>&1; then
  whois_output=$(whois "$RESOLVED_IP" 2>/dev/null || true)
  echo "$whois_output" | tee -a "$REPORT_FILE"
else
  echo "whois not installed" | tee -a "$REPORT_FILE"
fi

# 3) ASN / ISP via ipinfo (optional) or ip-api fallback
echo "\n[ASN / ISP / Geolocation]" | tee -a "$REPORT_FILE"
if [[ -n "${IPINFO_TOKEN:-}" ]]; then
  ipinfo_json=$(curl -sS "https://ipinfo.io/${RESOLVED_IP}/json?token=${IPINFO_TOKEN}" || true)
  if [[ -n "$ipinfo_json" ]]; then
    echo "$ipinfo_json" | jq -r 'to_entries|map("\(.key): \(.value|tostring)")|.[]' | tee -a "$REPORT_FILE"
  fi
else
  # fallback to ip-api.com
  api_json=$(curl -sS "http://ip-api.com/json/${RESOLVED_IP}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query" || true)
  if [[ -n "$api_json" ]]; then
    echo "$api_json" | jq -r 'to_entries|map("\(.key): \(.value|tostring)")|.[]' | tee -a "$REPORT_FILE"
  else
    echo "No geolocation info available." | tee -a "$REPORT_FILE"
  fi
fi

# 4) Reverse DNS / PTR
echo "\n[Reverse DNS / PTR]" | tee -a "$REPORT_FILE"
if command -v dig >/dev/null 2>&1; then
  ptr=$(dig -x "$RESOLVED_IP" +short || true)
  echo "PTR: ${ptr:-(none)}" | tee -a "$REPORT_FILE"
else
  echo "dig not available" | tee -a "$REPORT_FILE"
fi

# 5) Passive banners & services (requires Shodan API key). Only if user provided key.
echo "\n[Passive Services / Banners]" | tee -a "$REPORT_FILE"
if [[ -n "${SHODAN_API_KEY:-}" ]]; then
  shodan_json=$(curl -sS "https://api.shodan.io/shodan/host/${RESOLVED_IP}?key=${SHODAN_API_KEY}" || true)
  if [[ -n "$shodan_json" ]]; then
    echo "$shodan_json" | jq -r 'to_entries|map("\(.key): \(.value|tostring)")|.[]' | tee -a "$REPORT_FILE"
    # extract banners
    echo "\nBanners:" | tee -a "$REPORT_FILE"
    echo "$shodan_json" | jq -r '.data[]?.banner // .data[]?.product // empty' 2>/dev/null | sed '/^$/d' | tee -a "$REPORT_FILE" || true
  else
    echo "Shodan query returned nothing or failed." | tee -a "$REPORT_FILE"
  fi
else
  echo "SHODAN_API_KEY not set. To enable passive banner lookups, export SHODAN_API_KEY. Skipping." | tee -a "$REPORT_FILE"
fi

# 6) Reputation hints
echo "\n[Reputation & Blacklists]" | tee -a "$REPORT_FILE"
# Check Spamhaus & AbuseIPDB could require API. We'll do a simple DNSBL check for common lists for the IP's last octet reversed if IPv4
if [[ "$RESOLVED_IP" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  I1=${BASH_REMATCH[1]}
  I2=${BASH_REMATCH[2]}
  I3=${BASH_REMATCH[3]}
  I4=${BASH_REMATCH[4]}
  rev_ip="$I4.$I3.$I2.$I1"
  dnsbls=("zen.spamhaus.org" "bl.spamcop.net" "dnsbl.sorbs.net")
  for bl in "${dnsbls[@]}"; do
    check=$(dig +short "$rev_ip.$bl" A || true)
    if [[ -n "$check" ]]; then
      echo "Listed on $bl: $check" | tee -a "$REPORT_FILE"
    else
      echo "Not listed on $bl" | tee -a "$REPORT_FILE"
    fi
  done
else
  echo "DNSBL checks skipped (not an IPv4 address)." | tee -a "$REPORT_FILE"
fi

# 7) Extract emails / contact hints from WHOIS & banners
echo "\n[Found Emails / Contact Hints (public sources only)]" | tee -a "$REPORT_FILE"
# Extract common email patterns from whois and shodan json
emails=$(echo "$whois_output" "$shodan_json" | grep -Eo "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}" || true)
if [[ -n "$emails" ]]; then
  echo "$emails" | sort -u | tee -a "$REPORT_FILE"
else
  echo "No obvious public emails found in WHOIS or Shodan output." | tee -a "$REPORT_FILE"
fi

# 8) Attempt passive domain associations (if PTR or cert data found)
echo "\n[Associated Domains / Passive DNS hints]" | tee -a "$REPORT_FILE"
# Use PTR if present
if [[ -n "${ptr:-}" ]]; then
  echo "From PTR: $ptr" | tee -a "$REPORT_FILE"
fi
# Try to pull TLS cert domains via OpenSSL (only if port 443 responds, we won't actively connect to unknown hosts if user hasn't approved)
if command -v timeout >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
  # attempt TLS cert retrieval but timeboxed and non-intrusive
  if timeout 5 bash -c "</dev/tcp/${RESOLVED_IP}/443" >/dev/null 2>&1; then
    cert_domains=$(echo | openssl s_client -connect "${RESOLVED_IP}:443" -servername "$TARGET" 2>/dev/null | openssl x509 -noout -text 2>/dev/null | grep -Eo "([A-Za-z0-9.-]+\.[A-Za-z]{2,6})" | sort -u || true)
    if [[ -n "$cert_domains" ]]; then
      echo "$cert_domains" | tee -a "$REPORT_FILE"
    else
      echo "No TLS SAN domains extracted." | tee -a "$REPORT_FILE"
    fi
  else
    echo "Port 443 not reachable or timed out; skipping cert check." | tee -a "$REPORT_FILE"
  fi
else
  echo "openssl/timeout not available; skipping TLS cert lookup." | tee -a "$REPORT_FILE"
fi

# 9) Accuracy & limits summary
cat >> "$REPORT_FILE" <<'EOF'

---
Accuracy & limits:
1) Geolocation limits: country-level is generally reliable; city-level or GPS coords can be imprecise and may point to the ISP/POP.
2) Network middlemen distort results: NAT, VPNs, proxies, datacenters, and carrier-grade NAT will show provider-level locations, not an end user.
3) DNS/WHOIS are operator-level: WHOIS and PTR show network/operator info and netblock registrant; they do not prove individual identity.
EOF

# 10) Final notes
cat >> "$REPORT_FILE" <<EOF

---
End of report. Remember: for subscriber identity, packet logs, or exact timestamps contact the ISP or law enforcement through legal process.
Report saved to: $REPORT_FILE
EOF

# Print quick summary to user (non-sensitive)
echo "\nSummary (non-sensitive):"
echo "Report saved to: $REPORT_FILE"
echo "Printed WHOIS, ASN/ISP, PTR, basic reputation checks, and any public emails found."

exit 0
