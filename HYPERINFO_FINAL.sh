#!/bin/bash
# HYPERINFO_FINAL.sh — HYPERINFO GUI OSINT (final)
# Project: hypersenseindia - Masterindustriesindia
# Developed by: MASTER S ASWIN
# Protect code (simple): 321
# Description: Terminal GUI OSINT tool for Termux that performs passive lookups
#              and attempts to extract public emails, phone numbers and social
#              media mentions associated with an IP or hostname using WHOIS,
#              Shodan (optional), TLS certs (crt.sh), and banner text.
# Important legal/ethical notice:
# - This tool performs only passive, publicly-available information gathering.
# - Do NOT use it to harass, stalk, or attempt to identify private individuals.
# - For subscriber identity or packet logs, contact the ISP or law enforcement.
# - Active intrusive scanning (beyond optional nmap) may be illegal without
#   permission. Use responsibly.

set -euo pipefail
IFS=$'\n\t'

PASSCODE_EXPECTED="321"
REPORT_DIR=".hyperinfo_reports"
mkdir -p "$REPORT_DIR"

# Optional API keys (set in environment for richer results)
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
HUNTER_API_KEY="${HUNTER_API_KEY:-}"
CLEARBITH_API_KEY="${CLEARBIT_API_KEY:-}"
# (You can export these in Termux: export SHODAN_API_KEY="your_key")

# Dependencies check helper
require_cmd(){
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[WARN] Missing command: $1" >&2
  fi
}

require_cmd dialog
require_cmd curl
require_cmd jq
require_cmd whois
require_cmd nslookup || require_cmd dig
require_cmd openssl
require_cmd grep

# Small utility regex extractors
extract_emails(){
  # input via stdin
  grep -Eio "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}" | sort -u
}
extract_phones(){
  # crude phone patterns: +country, spaces, dashes
  grep -Eo "\+?[0-9][0-9\-() ]{6,}[0-9]" | sed 's/[()]//g' | tr -s ' ' | sort -u
}
extract_socials(){
  # twitter, instagram, facebook, linkedin, github handles/domains
  grep -Eio "(twitter.com/[A-Za-z0-9_\-]+|instagram.com/[A-Za-z0-9_.\-]+|facebook.com/[A-Za-z0-9_.\-]+|linkedin.com/in/[A-Za-z0-9_\-]+|github.com/[A-Za-z0-9_\-]+)" | sort -u
}

# Prompt passcode (dialog input) and target
prompt_passcode(){
  PASS=$(dialog --title "HYPERINFO - MASTER S ASWIN" --insecure --inputbox "Enter tool passcode:" 8 50 3>&1 1>&2 2>&3 3>&-)
  if [[ "$PASS" != "$PASSCODE_EXPECTED" ]]; then
    dialog --msgbox "Incorrect passcode. Exiting." 6 40
    clear
    exit 1
  fi
}

prompt_target(){
  TARGET=$(dialog --title "HYPERINFO - MASTER S ASWIN" --inputbox "Enter IP address or hostname:" 8 50 3>&1 1>&2 2>&3 3>&-)
  if [[ -z "$TARGET" ]]; then
    dialog --msgbox "No target provided. Exiting." 6 40
    clear
    exit 1
  fi
}

# Build report header
start_report(){
  TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
  SAFE_TARGET=$(echo "$TARGET" | tr -c 'A-Za-z0-9._-' '_')
  REPORT_FILE="$REPORT_DIR/hyperinfo_${SAFE_TARGET}_$TIMESTAMP.txt"
  echo "HYPERINFO FINAL Report" > "$REPORT_FILE"
  echo "Target: $TARGET" >> "$REPORT_FILE"
  echo "Generated: $(date -u) UTC" >> "$REPORT_FILE"
  echo "----------------------------------------" >> "$REPORT_FILE"
}

append(){
  echo -e "$1" | tee -a "$REPORT_FILE"
}

# Passive collection functions
whois_lookup(){
  append "\n[WHOIS / RIR]"
  if command -v whois >/dev/null 2>&1; then
    whois "$TARGET" 2>/dev/null | tee -a "$REPORT_FILE"
  else
    append "whois not installed"
  fi
}

geoip_lookup(){
  append "\n[GeoIP - ipinfo / ip-api]"
  if [[ -n "${IPINFO_TOKEN:-}" ]]; then
    curl -sS "https://ipinfo.io/${TARGET}/json?token=${IPINFO_TOKEN}" | jq -r 'to_entries|map("\(.key): \(.value|tostring)")|.[]' | tee -a "$REPORT_FILE"
  else
    curl -sS "http://ip-api.com/json/${TARGET}?fields=status,country,regionName,city,zip,lat,lon,isp,org,as,query" | jq -r 'to_entries|map("\(.key): \(.value|tostring)")|.[]' | tee -a "$REPORT_FILE" || append "No geolocation info."
  fi
}

reverse_dns(){
  append "\n[Reverse DNS / PTR]"
  if command -v dig >/dev/null 2>&1; then
    dig -x "$TARGET" +short | tee -a "$REPORT_FILE"
  else
    nslookup "$TARGET" 2>/dev/null | tee -a "$REPORT_FILE"
  fi
}

shodan_lookup(){
  append "\n[Shodan]"
  if [[ -z "$SHODAN_API_KEY" ]]; then
    append "SHODAN_API_KEY not set. Skipping Shodan."
    return
  fi
  shodan_json=$(curl -sS "https://api.shodan.io/shodan/host/${TARGET}?key=${SHODAN_API_KEY}" || true)
  if [[ -z "$shodan_json" ]]; then
    append "Shodan returned no data or failed."
    return
  fi
  echo "$shodan_json" | jq -r 'to_entries|map("\(.key): \(.value|tostring)")|.[]' | tee -a "$REPORT_FILE"
  # Save raw
  echo "$shodan_json" > "${REPORT_FILE%.txt}_shodan.json"
}

crt_sh_lookup(){
  append "\n[TLS Certs - crt.sh]"
  # Query crt.sh for certificates mentioning the host
  crt_json=$(curl -sS "https://crt.sh/?q=%25${TARGET}&output=json" || true)
  if [[ -n "$crt_json" ]]; then
    echo "$crt_json" | jq -r '.[].name_value' | tr '\n' '\n' | sed '/^$/d' | sort -u | tee -a "$REPORT_FILE"
  else
    append "No cert entries or crt.sh query failed."
  fi
}

extract_contacts(){
  append "\n[Extracted Emails / Phones / Socials (public sources only)]"
  tmpfile=$(mktemp)
  # Collect WHOIS, shodan (if present), crt.sh, and certificate banners
  if command -v whois >/dev/null 2>&1; then whois "$TARGET" >> "$tmpfile" 2>/dev/null || true; fi
  if [[ -f "${REPORT_FILE%.txt}_shodan.json" ]]; then cat "${REPORT_FILE%.txt}_shodan.json" >> "$tmpfile" 2>/dev/null || true; fi
  if [[ -n "$crt_json" ]]; then echo "$crt_json" >> "$tmpfile"; fi
  # Try TLS cert SANs via openssl if port 443 open
  if timeout 5 bash -c "</dev/tcp/${TARGET}/443" >/dev/null 2>&1; then
    cert_text=$(echo | openssl s_client -connect "${TARGET}:443" -servername "$TARGET" 2>/dev/null | openssl x509 -noout -text 2>/dev/null || true)
    echo "$cert_text" >> "$tmpfile"
  fi
  # Extract emails
  emails=$(cat "$tmpfile" | extract_emails || true)
  phones=$(cat "$tmpfile" | extract_phones || true)
  socials=$(cat "$tmpfile" | extract_socials || true)
  if [[ -n "$emails" ]]; then
    append "Emails found:"
    echo "$emails" | tee -a "$REPORT_FILE"
  else
    append "No public emails found via passive sources."
  fi
  if [[ -n "$phones" ]]; then
    append "Phone patterns found:"
    echo "$phones" | tee -a "$REPORT_FILE"
  else
    append "No phone-like patterns found."
  fi
  if [[ -n "$socials" ]]; then
    append "Social profiles/domains found:"
    echo "$socials" | tee -a "$REPORT_FILE"
  else
    append "No obvious social profiles/domains found."
  fi
  rm -f "$tmpfile"
}

hunter_lookup(){
  # Optional Hunter.io email finder enrichment (requires API key)
  if [[ -z "$HUNTER_API_KEY" ]]; then
    append "\n[Hunter.io] API key not set. Skipping Hunter enrichment."
    return
  fi
  append "\n[Hunter.io - domain search]"
  # Try domain from PTR or target if hostname
  domain=$(echo "$TARGET" | sed -n 's/.*\.\([^.]*\.[^.]*\)$/\1/p')
  if [[ -z "$domain" ]]; then domain="$TARGET"; fi
  hunter_json=$(curl -sS "https://api.hunter.io/v2/domain-search?domain=${domain}&api_key=${HUNTER_API_KEY}" || true)
  if [[ -n "$hunter_json" ]]; then
    echo "$hunter_json" | jq -r '.data.emails[]? | "\(.value) - \(.type) - \(.confidence)"' | tee -a "$REPORT_FILE"
  else
    append "Hunter search failed or returned no results."
  fi
}

# Menu and orchestration
prompt_passcode
prompt_target
start_report

while true; do
  CHOICE=$(dialog --title "HYPERINFO FINAL - Menu" --menu "Target: $TARGET\nSelect action:" 20 70 12 \
    1 "Quick All (WHOIS + GeoIP + PTR + Certs + Shodan + Extract)" \
    2 "WHOIS only" \
    3 "GeoIP only" \
    4 "Reverse DNS (PTR)" \
    5 "TLS Certs (crt.sh + openssl)" \
    6 "Shodan (requires key)" \
    7 "Extract emails/phones/socials (passive)" \
    8 "Hunter.io enrich (requires key)" \
    9 "View report" \
    10 "Copy report to clipboard (termux)" \
    11 "Exit" 3>&1 1>&2 2>&3 3>&-)

  case $CHOICE in
    1)
      whois_lookup
      geoip_lookup
      reverse_dns
      crt_sh_lookup
      shodan_lookup
      extract_contacts
      dialog --msgbox "Quick All complete and saved to report." 6 60
      ;;
    2)
      whois_lookup
      dialog --msgbox "WHOIS saved." 6 40
      ;;
    3)
      geoip_lookup
      dialog --msgbox "GeoIP saved." 6 40
      ;;
    4)
      reverse_dns
      dialog --msgbox "Reverse DNS saved." 6 40
      ;;
    5)
      crt_sh_lookup
      dialog --msgbox "Cert lookup saved." 6 40
      ;;
    6)
      shodan_lookup
      dialog --msgbox "Shodan saved (if key valid)." 6 50
      ;;
    7)
      extract_contacts
      dialog --msgbox "Extraction complete." 6 50
      ;;
    8)
      hunter_lookup
      dialog --msgbox "Hunter enrichment attempted." 6 50
      ;;
    9)
      clear
      less "$REPORT_FILE"
      ;;
    10)
      if command -v termux-clipboard-set >/dev/null 2>&1; then
        cat "$REPORT_FILE" | termux-clipboard-set
        dialog --msgbox "Report copied to clipboard." 6 40
      else
        dialog --msgbox "termux-api not installed." 6 40
      fi
      ;;
    11)
      clear
      exit 0
      ;;
    *)
      dialog --msgbox "Invalid option" 5 30
      ;;
  esac

done
