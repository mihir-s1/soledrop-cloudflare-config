#!/usr/bin/env bash
# =============================================================================
# rollback.sh — undo enable-detections.sh, restoring the zone from the most
# recent snapshot under ./backups/ (written by enable-detections.sh before it
# changed anything).
#
# Restores the WAF-managed / WAF-custom / rate-limit phase entrypoints to their
# pre-run state, and deletes the Waiting Room only if this kit created it.
# Bot Management / Firewall for AI were never changed, so nothing to undo there.
#
# Usage:  bash rollback.sh   (reads the same .env.local as enable-detections.sh)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }
step()    { echo -e "\n${BOLD}━━━ $* ━━━${RESET}"; }

command -v curl >/dev/null 2>&1 || error "curl not found."
command -v python3 >/dev/null 2>&1 || error "python3 not found."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/.env.local" ]]; then set -a; source "$SCRIPT_DIR/.env.local"; set +a; fi

: "${CLOUDFLARE_API_TOKEN:?  Missing CLOUDFLARE_API_TOKEN — set it in .env.local}"
: "${CLOUDFLARE_ZONE_ID:?    Missing CLOUDFLARE_ZONE_ID    — set it in .env.local}"

cf_api() {
  local method="$1" path="$2"; shift 2
  curl -s -X "$method" "https://api.cloudflare.com/client/v4$path" \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H "Content-Type: application/json" "$@"
}
cf_ok() { python3 -c "import sys,json; d=json.load(sys.stdin); print('ok') if d['success'] else print('err:'+str(d['errors']))"; }

# ── Locate the latest backup ──────────────────────────────────────────────────
step "Finding latest backup"
LATEST="$(ls -1dt "$SCRIPT_DIR"/backups/*/ 2>/dev/null | head -1 || true)"
[[ -n "$LATEST" ]] || error "No backup found under backups/. enable-detections.sh writes one before it changes anything — nothing to restore."
LATEST="${LATEST%/}"
BZONE="$(cat "$LATEST/zone_id.txt" 2>/dev/null || echo '')"
[[ "$BZONE" == "$CLOUDFLARE_ZONE_ID" ]] || warn "Backup zone ($BZONE) != current CLOUDFLARE_ZONE_ID ($CLOUDFLARE_ZONE_ID) — restoring against the current zone anyway."
success "Using snapshot: ${LATEST#$SCRIPT_DIR/}"

# ── Restore each phase entrypoint from the snapshot ───────────────────────────
step "Restoring WAF + rate-limit phase entrypoints"
for phase in http_request_firewall_managed http_request_firewall_custom http_ratelimit; do
  SNAP="$LATEST/$phase.json"
  BODY="$(python3 - "$SNAP" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    rules = (d.get("result") or {}).get("rules") or []
except Exception:
    rules = []          # no prior entrypoint (404 snapshot) -> restore to empty
print(json.dumps({"rules": rules}))
PY
)"
  R="$(cf_api PUT "/zones/$CLOUDFLARE_ZONE_ID/rulesets/phases/$phase/entrypoint" --data "$BODY" | cf_ok)"
  [[ "$R" == ok ]] && success "restored $phase" || warn "$phase: $R"
done

# ── Waiting Room — delete only if this kit created it ─────────────────────────
step "Waiting Room"
PRE_HAD_IT="$(python3 - "$LATEST/waiting_rooms.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    names = [w.get("name") for w in (d.get("result") or [])]
except Exception:
    names = []
print("yes" if "soledrop-drop-day" in names else "no")
PY
)"
if [[ "$PRE_HAD_IT" == "yes" ]]; then
  info "'soledrop-drop-day' existed before enable ran — leaving it in place."
else
  WRID="$(cf_api GET "/zones/$CLOUDFLARE_ZONE_ID/waiting_rooms" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(next((w['id'] for w in (d.get('result') or []) if w.get('name')=='soledrop-drop-day'), ''))
")"
  if [[ -n "$WRID" ]]; then
    R="$(cf_api DELETE "/zones/$CLOUDFLARE_ZONE_ID/waiting_rooms/$WRID" | cf_ok)"
    [[ "$R" == ok ]] && success "deleted Waiting Room 'soledrop-drop-day'" || warn "Waiting Room delete: $R"
  else
    info "No 'soledrop-drop-day' Waiting Room found — nothing to delete."
  fi
fi

step "Done"
success "Rolled back to snapshot ${LATEST#$SCRIPT_DIR/}."
info "Bot Management / Firewall for AI were never modified by enable-detections.sh, so nothing to undo there."
