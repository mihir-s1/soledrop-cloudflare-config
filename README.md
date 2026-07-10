# SoleDrop — Cloudflare security provisioning

Idempotent script that provisions the Cloudflare security controls for the **SoleDrop** CTF target (`shop.soledrop.co`) via the Cloudflare API. It stands up WAF (managed + custom), rate limiting, and a drop-day Waiting Room, and verifies the Bot Management / Firewall for AI entitlements.

> Companion to the OneFlare ThreatOps CTF: the CTF fires attacks at `shop.soledrop.co`; this repo makes Cloudflare enforce/score them so they generate meaningful signals for SentinelOne.

## What it does

`enable-detections.sh` (Bearer-token, `curl` + `python3`, no `jq`):

1. **WAF managed ruleset** — deploys the Cloudflare Managed Ruleset + OWASP Core → managed coverage and `WAFAttackScore`.
2. **WAF custom rules** — a **mixed** action strategy:
   - **`block`** the high-confidence exploits: SQLi, XSS, path traversal, RCE/Log4Shell/Struts, SSRF (real "WAF stopped it" events).
   - **`log`** the behavioral traffic: recon/scanner probes, bulk exfil pulls, login POSTs, concierge prompt-injection — so it flows through and drives the correlated detections + the shop's `/status` flip and `/admin` degradation. (Blocked requests are still logged with full signals, so detections fire either way.)
   - A **managed-challenge** rule for `/chat` + `/login` ships **disabled** (enable for a real drop-day; off by default so it doesn't pre-empt the CTF boxes).
3. **Rate limiting** — checkout/cart/login rules, thresholds set **high** so normal demo traffic isn't gated (tighten for a real drop).
4. **Waiting Room** — `shop.soledrop.co`, high thresholds (won't queue normal traffic).
5. **Entitlement checks** — reports Bot Management (JA4 / BotScore) and notes Firewall for AI. These are Enterprise add-ons that **can't be enabled via API** — only verified.

Rulesets phase entrypoints are written with `PUT`, so re-runs are idempotent (declarative replace).

### Safety / rollback

The script **doesn't disable** any Cloudflare protection — it only adds rules (and the one managed-challenge rule ships disabled). Because the WAF/rate-limit phases use `PUT` (which replaces the whole rule list in that phase), the script **snapshots the current phase entrypoints + Waiting Rooms to `backups/<timestamp>/` before changing anything**. To undo:

```bash
bash rollback.sh
```

`rollback.sh` restores the three phase entrypoints from the latest snapshot, deletes the `soledrop-drop-day` Waiting Room **only if this kit created it**, and deletes the `soledrop-*` Logpush jobs. (`backups/` is gitignored.)

## Logpush → SentinelOne

`logpush-to-s1.sh` streams the zone's telemetry to SentinelOne's HEC-compatible ingest. Cloudflare's edge pushes directly to S1 — nothing egresses your machine (local TLS-inspection proxies don't apply). Two jobs, chosen for signal over noise:

- **`firewall_events`** — every WAF / rate-limit match (blocks **and** the `log` rules), **unfiltered**. Low volume, pure security signal.
- **`http_requests`** — **filtered to `host=shop.soledrop.co`**. The bot-swarm / JA4 / recon / cred-stuffing / exfil traffic *passes* the WAF, so it only appears here. The host filter keeps all attack traffic and drops unrelated zone noise.

```bash
# .env.local already has S1_HEC_INGEST_URL / S1_HEC_INGEST_TOKEN
bash logpush-to-s1.sh
```

Uses Cloudflare's native **`sentinelone://`** Logpush destination (renders with the SentinelOne logo, not Splunk). Idempotent (matches jobs by name → `PUT` update, else `POST`). If a job errors with invalid-credentials, check `S1_HEC_INGEST_TOKEN` / `S1_HEC_AUTH_SCHEME` (default `Bearer`) and re-run. `http_requests` Logpush needs Enterprise; `firewall_events` works on any paid plan. Score/JA4/bot fields populate only with the matching Enterprise entitlements (null otherwise — harmless).

## Usage

```bash
cp .env.example .env.local     # fill in CLOUDFLARE_API_TOKEN / ACCOUNT_ID / ZONE_ID (soledrop.co)
source .env.local
bash enable-detections.sh
```

**Token scopes:** Zone `Zone:Read`, `WAF:Edit`, `Waiting Room:Edit`; Account `Account Rulesets:Edit`; `Bot Management:Read`.

## Verify

Probe the zone with an exploit + scanner UA and check **Cloudflare → Security → Events**:

```bash
curl "https://shop.soledrop.co/search?q=%27%20OR%201=1--" -H "User-Agent: sqlmap/1.7"
```

You should see a WAF **block** with a populated `WAFAttackScore`. Re-running the script is safe (idempotent).

## Not done here (S1-side)

This repo handles the **Cloudflare enforcement/scoring + shipping** side. The only remaining piece is in your SentinelOne tenant:

- **S1 side**: deploy the Cloudflare→OCSF parser (`marketplace-cloudflare-latest`) and the STAR detection rules, scoped to the site receiving this zone's Logpush. Once events land (verify: `sourcetype="marketplace-cloudflare-latest"`), the detections fire.

## Files

```
enable-detections.sh        # provisions WAF / rate limiting / Waiting Room
logpush-to-s1.sh            # Logpush jobs: firewall_events + http_requests → S1 HEC
rollback.sh                 # restores WAF/RL/WR from snapshot; deletes soledrop-* Logpush jobs
waf/rules.json              # base custom rules (SQLi/XSS/traversal block; export/login log)
waf/extra-custom-rules.json # RCE/SSRF block, recon/concierge log, disabled managed-challenge
ratelimit/rules.json        # rate-limit rules (checkout/cart/login)
waitingroom/config.json     # drop-day Waiting Room
.env.example                # required env vars
```
