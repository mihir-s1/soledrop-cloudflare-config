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

## Not done here (required for end-to-end detection)

This repo handles the **Cloudflare enforcement/scoring** side only. For the SentinelOne STAR rules to actually fire you still need:

1. **Logpush → SentinelOne** (deferred): zone datasets **HTTP Requests** + **Firewall Events** → your S1 HEC (`S1_HEC_INGEST_URL` / `S1_HEC_INGEST_TOKEN`), including the score/JA4/bot fields. Not automated here yet.
2. **S1 side**: deploy the Cloudflare→OCSF parser and the STAR detection rules in your tenant, scoped to the site receiving this zone's Logpush.

## Files

```
enable-detections.sh        # the provisioning script
waf/rules.json              # base custom rules (SQLi/XSS/traversal block; export/login log)
waf/extra-custom-rules.json # RCE/SSRF block, recon/concierge log, disabled managed-challenge
ratelimit/rules.json        # rate-limit rules (checkout/cart/login)
waitingroom/config.json     # drop-day Waiting Room
.env.example                # required env vars
```
