#!/usr/bin/env bash
# =============================================================================
# enable-detections.sh — provision Cloudflare security controls on the SoleDrop
# CTF zone (shop.soledrop.co) via the Cloudflare API.
#
# Mixed action strategy: BLOCK high-confidence exploits (SQLi/XSS/traversal/RCE)
# for real "WAF stopped it" events; LOG behavioral traffic (recon, bot swarm,
# credential stuffing, concierge injection, exfil) so it flows through and drives
# the correlated detections + the shop's /status flip and /admin degradation.
# Blocked requests are still logged with full signals, so detections fire either way.
#
# Idempotent: Rulesets phase entrypoints are PUT (declarative replace).
#
# Usage:
#   1. Export the soledrop.co-account credentials (or source .env.local):
#        CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_ZONE_ID
#   2. bash cloudflare/enable-detections.sh
#
# NOTE: Logpush (Cloudflare -> SentinelOne) is intentionally NOT done here — see
# the summary at the end. Without it, Cloudflare enforces/scores these attacks
# but S1 receives no events, so the STAR rules won't fire until Logpush is wired.
# =============================================================================

set -euo pipefail

# ── Colours + status helpers (same as setup.sh) ──────────────────────────────
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

# Auto-load .env.local (if present) and export its vars, so you can just run
# `bash enable-detections.sh` after filling .env.local — no manual `export`.
if [[ -f "$SCRIPT_DIR/.env.local" ]]; then
  set -a; source "$SCRIPT_DIR/.env.local"; set +a
fi

# ── Env validation ───────────────────────────────────────────────────────────
step "Validating environment"
: "${CLOUDFLARE_API_TOKEN:?  Missing CLOUDFLARE_API_TOKEN — set it in .env.local}"
: "${CLOUDFLARE_ACCOUNT_ID:? Missing CLOUDFLARE_ACCOUNT_ID — set it in .env.local}"
: "${CLOUDFLARE_ZONE_ID:?    Missing CLOUDFLARE_ZONE_ID    — set it in .env.local}"

# ── CF API helpers (same as setup.sh) ────────────────────────────────────────
cf_api() {
  local method="$1" path="$2"
  shift 2
  curl -s -X "$method" "https://api.cloudflare.com/client/v4$path" \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    -H "Content-Type: application/json" \
    "$@"
}

cf_ok() {
  python3 -c "import sys,json; d=json.load(sys.stdin); print('ok') if d['success'] else print('err:'+str(d['errors']))"
}

# Verify token + zone up front
ZONE_STATUS=$(cf_api GET "/zones/$CLOUDFLARE_ZONE_ID" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if not d['success']: print('ERROR:' + str(d['errors']))
else: print(d['result']['status'] + ':' + d['result']['name'])
")
[[ "$ZONE_STATUS" == ERROR* ]] && error "Zone/token validation failed: $ZONE_STATUS"
ZONE_STATE="${ZONE_STATUS%%:*}"; ZONE_NAME="${ZONE_STATUS#*:}"
success "Token valid — zone: $ZONE_NAME (status: $ZONE_STATE)"
[[ "$ZONE_NAME" == "soledrop.co" ]] || warn "Zone is '$ZONE_NAME', expected 'soledrop.co' — continuing anyway."

# Cloudflare-provided managed ruleset IDs (stable, account-agnostic)
CF_MANAGED_RULESET="efb7b8c949ac4650a09736fc376e9aee"   # Cloudflare Managed Ruleset
OWASP_RULESET="4814384a9e5d4991b9815dcfc25d2f1f"        # Cloudflare OWASP Core Ruleset

# ── Step 1: WAF managed ruleset (managed coverage + WAF attack scoring) ───────
step "1/6  WAF managed ruleset (Cloudflare Managed + OWASP)"
MANAGED_BODY=$(python3 - "$CF_MANAGED_RULESET" "$OWASP_RULESET" <<'PY'
import json, sys
ids = [("Cloudflare Managed Ruleset", sys.argv[1]),
       ("Cloudflare OWASP Core Ruleset", sys.argv[2])]
rules = [{"action": "execute", "action_parameters": {"id": i},
          "expression": "true", "description": d, "enabled": True} for d, i in ids]
print(json.dumps({"rules": rules}))
PY
)
R=$(cf_api PUT "/zones/$CLOUDFLARE_ZONE_ID/rulesets/phases/http_request_firewall_managed/entrypoint" --data "$MANAGED_BODY" | cf_ok)
[[ "$R" == ok ]] && success "Managed ruleset deployed (WAFAttackScore will populate on Enterprise)" || warn "Managed ruleset: $R"

# ── Step 2: WAF custom rules + (disabled) managed challenge ───────────────────
step "2/6  WAF custom rules (block exploits, log behavioral) + challenge rule"
CUSTOM_BODY=$(python3 - "$SCRIPT_DIR/waf/rules.json" "$SCRIPT_DIR/waf/extra-custom-rules.json" <<'PY'
import json, sys
base  = json.load(open(sys.argv[1]))
extra = json.load(open(sys.argv[2]))
rules = []
for r in base["rules"]:
    f = base["filters"][r["filter_index"]]
    rules.append({"expression": f["expression"], "action": r["action"],
                  "description": r["description"], "enabled": True})
for e in extra:
    rules.append({"expression": e["expression"], "action": e["action"],
                  "description": e["description"], "enabled": e.get("enabled", True)})
print(json.dumps({"rules": rules}))
PY
)
R=$(cf_api PUT "/zones/$CLOUDFLARE_ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint" --data "$CUSTOM_BODY" | cf_ok)
[[ "$R" == ok ]] && success "Custom WAF rules deployed (SQLi/XSS/traversal/RCE=block; recon/exfil/login/chat=log)" || warn "Custom rules: $R"

# ── Step 3: Rate limiting (tuned high — real control, won't gate a demo) ──────
step "3/6  Rate limiting rules"
RL_BODY=$(python3 - "$SCRIPT_DIR/ratelimit/rules.json" <<'PY'
import json, sys
print(json.dumps({"rules": json.load(open(sys.argv[1]))}))
PY
)
R=$(cf_api PUT "/zones/$CLOUDFLARE_ZONE_ID/rulesets/phases/http_ratelimit/entrypoint" --data "$RL_BODY" | cf_ok)
[[ "$R" == ok ]] && success "Rate-limit rules deployed (checkout/cart + login; high thresholds)" || warn "Rate limiting: $R (needs Advanced Rate Limiting entitlement)"

# ── Step 4: Waiting Room (high threshold — won't queue normal traffic) ────────
step "4/6  Waiting Room"
R=$(cf_api POST "/zones/$CLOUDFLARE_ZONE_ID/waiting_rooms" --data @"$SCRIPT_DIR/waitingroom/config.json" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if d['success']: print('ok')
elif any(k in str(d.get('errors','')).lower() for k in ('already','duplicate','exists')): print('ok:exists')
else: print('err:'+str(d.get('errors')))
")
case "$R" in
  ok)        success "Waiting Room created (soledrop-drop-day)";;
  ok:exists) success "Waiting Room already exists — left as-is";;
  *)         warn "Waiting Room: $R (needs Waiting Room entitlement)";;
esac

# ── Step 5: Entitlement checks (cannot be enabled via API — verify + warn) ────
step "5/6  Entitlement checks (Bot Management / Firewall for AI)"
BM=$(cf_api GET "/zones/$CLOUDFLARE_ZONE_ID/bot_management" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if d.get('success'):
    r=d.get('result',{})
    print('ok:' + json.dumps({k:r.get(k) for k in ('fight_mode','using_latest_model','auto_update_model','ai_bots_protection') if k in r}))
else:
    print('err:'+str(d.get('errors')))
")
if [[ "$BM" == ok:* ]]; then success "Bot Management available — JA4 + BotScore will be emitted. ${BM#ok:}"
else warn "Bot Management not available (${BM#err:}). JA4/BotScore won't emit → Box 2 (polymorphic-JA4) needs this Enterprise add-on."; fi
info "Firewall for AI: enable per-zone in the Cloudflare dashboard (Security → Settings). No stable API toggle; FirewallForAIInjectionScore won't emit until it's on."

# ── Step 6: Summary + required follow-ups ─────────────────────────────────────
step "6/6  Summary"
success "Cloudflare security controls provisioned on $ZONE_NAME."
echo -e "\n${BOLD}Still required for the S1 detections to actually fire:${RESET}"
echo "  1. Logpush → SentinelOne (NOT automated here):"
echo "       Zone datasets: HTTP Requests + Firewall Events  →  S1 HEC (S1_HEC_INGEST_URL/TOKEN)"
echo "       Include fields: WAFAttackScore, WAFSQLiAttackScore, WAFXSSAttackScore, WAFRCEAttackScore,"
echo "       FirewallForAIInjectionScore, JA4, JA3Hash, BotScore, BotTags, ClientIP, ClientRequest*,"
echo "       OriginResponse*, EdgeResponse*, RayID, SecurityAction/RuleID/RuleDescription."
echo "  2. Deploy the OCSF parser (parsers/cloudflare-ocsf-parser/) + the STAR rules (detections/*) in S1,"
echo "       scoped to the site receiving this zone's Logpush."
echo -e "\n${BOLD}Verify now:${RESET} probe shop.soledrop.co with a SQLi query + scanner UA and check"
echo "  Cloudflare → Security → Events for a WAF block + a WAFAttackScore."
