#!/usr/bin/env bash
# =============================================================================
# logpush-to-s1.sh — stream the soledrop.co zone's security telemetry to
# SentinelOne's HEC-compatible ingest via Cloudflare Logpush.
#
# Datasets (chosen for signal, not noise):
#   - firewall_events : every WAF / rate-limit match — blocks AND our `log`
#                       rules (recon/exfil/login/concierge). Pure security
#                       signal, low volume -> pushed UNFILTERED.
#   - http_requests   : full request stream, FILTERED to host=shop.soledrop.co.
#                       The bot-swarm / JA4 / recon / cred-stuffing / exfil
#                       traffic PASSES the WAF, so it only appears here (never
#                       in firewall_events). Host filter keeps all the attack
#                       traffic and drops unrelated zone noise.
#
# Pushing is done by Cloudflare's edge directly to S1 — nothing egresses your
# machine, so local TLS-inspection proxies (Zscaler etc.) are irrelevant.
#
# Idempotent: matches Logpush jobs by name and PUTs updates; otherwise POSTs.
#
# Usage: fill .env.local, then:  bash logpush-to-s1.sh
#   Required: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID,
#             S1_HEC_INGEST_URL, S1_HEC_INGEST_TOKEN
#   Token scope (extra vs enable-detections.sh): Zone -> Logs: Edit
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }
step()    { echo -e "\n${BOLD}━━━ $* ━━━${RESET}"; }

command -v curl    >/dev/null 2>&1 || error "curl not found."
command -v python3 >/dev/null 2>&1 || error "python3 not found."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/.env.local" ]]; then set -a; source "$SCRIPT_DIR/.env.local"; set +a; fi

step "Validating environment"
: "${CLOUDFLARE_API_TOKEN:? Missing CLOUDFLARE_API_TOKEN — set it in .env.local}"
: "${CLOUDFLARE_ZONE_ID:?   Missing CLOUDFLARE_ZONE_ID   — set it in .env.local}"
: "${S1_HEC_INGEST_URL:?    Missing S1_HEC_INGEST_URL    — e.g. ingest.us1.sentinelone.net/services/collector/raw}"
: "${S1_HEC_INGEST_TOKEN:?  Missing S1_HEC_INGEST_TOKEN  — the SentinelOne HEC write token}"

# Tunables (override in .env.local if needed)
S1_HEC_SOURCETYPE="${S1_HEC_SOURCETYPE:-marketplace-cloudflare-latest}"
# Bare token by default: the native sentinelone:// connector prepends the auth
# scheme itself, so a "Bearer <token>" here becomes a double prefix and 401s.
# Set S1_HEC_AUTH_SCHEME=Bearer (or Splunk) only for a raw splunk:// HEC.
S1_HEC_AUTH_SCHEME="${S1_HEC_AUTH_SCHEME-}"
SHOP_HOST="${SHOP_HOST:-shop.soledrop.co}"

cf_api() {
  local method="$1" path="$2"; shift 2
  curl -s -X "$method" "https://api.cloudflare.com/client/v4$path" \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H "Content-Type: application/json" "$@"
}
cf_ok() { python3 -c "import sys,json; d=json.load(sys.stdin); print('ok') if d['success'] else print('err:'+str(d['errors']))"; }

# ── Verify token + zone up front ──────────────────────────────────────────────
ZONE_STATUS=$(cf_api GET "/zones/$CLOUDFLARE_ZONE_ID" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('ERROR:'+str(d['errors'])) if not d['success'] else print(d['result']['name'])
")
[[ "$ZONE_STATUS" == ERROR* ]] && error "Zone/token validation failed: $ZONE_STATUS"
success "Token valid — zone: $ZONE_STATUS"
[[ "$ZONE_STATUS" == "soledrop.co" ]] || warn "Zone is '$ZONE_STATUS', expected 'soledrop.co' — continuing anyway."

# ── Build the native SentinelOne destination string ───────────────────────────
# Matches Cloudflare's first-class SentinelOne Logpush connector (renders with
# the S1 logo, not Splunk). Unlike splunk://, it takes NO channel / skip-verify —
# just header_Authorization + sourcetype.
# strip any scheme the user may have included; keep host + path verbatim
HEC="${S1_HEC_INGEST_URL#*://}"
# header_Authorization = URL-encoded "<scheme> <token>", or just "<token>" when
# S1_HEC_AUTH_SCHEME is empty (the native sentinelone:// connector prepends the
# scheme itself, so a bare token is often what it wants).
AUTH_ENC=$(python3 -c "import urllib.parse,sys; s,t=sys.argv[1],sys.argv[2]; print(urllib.parse.quote((s+' '+t) if s else t))" \
             "$S1_HEC_AUTH_SCHEME" "$S1_HEC_INGEST_TOKEN")
build_dest() {
  echo "sentinelone://${HEC}?header_Authorization=${AUTH_ENC}&sourcetype=${S1_HEC_SOURCETYPE}"
}
info "Destination: sentinelone://${HEC}  (sourcetype=${S1_HEC_SOURCETYPE}, auth=${S1_HEC_AUTH_SCHEME} <token>)"

# ── Field sets (markers ride URL query + User-Agent — Cloudflare omits bodies) ─
FW_FIELDS="Action,ClientASN,ClientASNDescription,ClientCountry,ClientIP,ClientIPClass,ClientRequestHTTPHost,ClientRequestHTTPMethodName,ClientRequestHTTPProtocol,ClientRequestPath,ClientRequestQuery,ClientRequestScheme,ClientRequestUserAgent,Datetime,EdgeColoCode,EdgeResponseStatus,Kind,MatchIndex,Metadata,OriginResponseStatus,OriginatorRayName,RayName,RuleID,Ruleset,RulesetID,Source,WAFAttackScore,WAFSQLiAttackScore,WAFXSSAttackScore,WAFRCEAttackScore"
HTTP_FIELDS="BotScore,BotScoreSrc,BotTags,ClientASN,ClientCountry,ClientDeviceType,ClientIP,ClientIPClass,ClientRequestHost,ClientRequestMethod,ClientRequestPath,ClientRequestProtocol,ClientRequestReferer,ClientRequestScheme,ClientRequestSource,ClientRequestURI,ClientRequestUserAgent,ClientSSLProtocol,EdgeColoCode,EdgeResponseBytes,EdgeResponseContentType,EdgeResponseStatus,EdgeStartTimestamp,JA3Hash,JA4,OriginResponseStatus,RayID,SecurityAction,SecurityRuleDescription,SecurityRuleID,WAFAttackScore,WAFRCEAttackScore,WAFSQLiAttackScore,WAFXSSAttackScore"

# Host filter for http_requests only (firewall_events stays unfiltered)
HTTP_FILTER="{\"where\":{\"key\":\"ClientRequestHost\",\"operator\":\"eq\",\"value\":\"$SHOP_HOST\"}}"

build_body() {  # $1=mode(post|put) $2=name $3=dataset $4=fields $5=filter(json|"") $6=dest
  python3 - "$@" <<'PY'
import json, sys
mode, name, dataset, fields, filt, dest = sys.argv[1:7]
body = {
    "output_options": {"field_names": [f for f in fields.split(",") if f], "timestamp_format": "rfc3339"},
    "destination_conf": dest,
    "enabled": True,
}
if filt:
    body["filter"] = filt          # Cloudflare expects the filter as a JSON string
if mode == "post":                 # name + dataset are set on create only (immutable on update)
    body["name"] = name
    body["dataset"] = dataset
print(json.dumps(body))
PY
}

find_job_id() {  # $1 = name  ->  prints id | "" | "ERR"
  cf_api GET "/zones/$CLOUDFLARE_ZONE_ID/logpush/jobs" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if not d.get('success'): print('ERR')
else: print(next((str(j['id']) for j in (d.get('result') or []) if j.get('name')==sys.argv[1]), ''))
" "$1"
}

ensure_job() {  # $1=name $2=dataset $3=fields $4=filter(json|"")
  local name="$1" dataset="$2" fields="$3" filter="$4" dest id body R
  dest="$(build_dest)"
  id="$(find_job_id "$name")"
  [[ "$id" == ERR ]] && error "Could not list Logpush jobs — token likely missing 'Zone : Logs : Edit'."
  if [[ -n "$id" ]]; then
    body="$(build_body put "$name" "$dataset" "$fields" "$filter" "$dest")"
    R="$(cf_api PUT "/zones/$CLOUDFLARE_ZONE_ID/logpush/jobs/$id" --data "$body" | cf_ok)"
    [[ "$R" == ok ]] && success "updated '$name' (id $id, dataset=$dataset)" || warn "$name update: $R"
  else
    body="$(build_body post "$name" "$dataset" "$fields" "$filter" "$dest")"
    R="$(cf_api POST "/zones/$CLOUDFLARE_ZONE_ID/logpush/jobs" --data "$body" | cf_ok)"
    [[ "$R" == ok ]] && success "created '$name' (dataset=$dataset)" || warn "$name create: $R"
  fi
}

step "1/2  Logpush job: firewall_events  (unfiltered — pure security signal)"
ensure_job "soledrop-firewall-events" "firewall_events" "$FW_FIELDS" ""

step "2/2  Logpush job: http_requests  (filtered to host=$SHOP_HOST)"
ensure_job "soledrop-http-requests" "http_requests" "$HTTP_FIELDS" "$HTTP_FILTER"

step "Done"
success "Logpush → SentinelOne configured on $ZONE_STATUS."
echo -e "\n${BOLD}Notes:${RESET}"
echo "  • Cloudflare validated each destination by POSTing a test event to S1. If a job"
echo "    shows 'err:... invalid credentials/destination', check S1_HEC_INGEST_TOKEN and"
echo "    S1_HEC_AUTH_SCHEME (default Bearer — the S1 write-token scheme) and re-run."
echo "  • http_requests Logpush requires an Enterprise plan; firewall_events is available on"
echo "    all paid plans. WAFAttackScore / BotScore / JA4 only populate with the matching"
echo "    Enterprise entitlements (they log as null otherwise — harmless)."
echo "  • Verify: run the CTF, then in S1 search sourcetype=\"${S1_HEC_SOURCETYPE}\" — you should"
echo "    see firewall_events (blocks + our log rules) and http_requests (the bot swarm)."
echo "  • Undo: rollback.sh deletes the soledrop-* Logpush jobs it finds."
