# SoleDrop CTF — SentinelOne STAR Detections (PowerQuery)

Detection rule bodies — one per CTF box — for the Cloudflare Logpush data in
SentinelOne. Companion to [attacks-and-detections.md](attacks-and-detections.md).

> **✅ Verified against live data** (2026-07-10, `usea1-partners`, 7-day window,
> via the LRQ API). Every query below was run against the real
> `shop.soledrop.co` events and returned the attacker IPs. Field names, the WAF
> score direction, and thresholds are all confirmed — this is no longer a draft.

> **📌 Deployed** to the **OneFlare** site (`siteId 2433185103040607397`,
> account `Cloudflare - NFR`) as scheduled PowerQuery detections, 60/60 min,
> **Draft** status (enable after review). Rule IDs:
>
> | Rule | Severity | ID |
> |---|---|---|
> | Mihir - SoleDrop CTF Box 1: Recon / Vuln Scanning | Medium | `2520570388861806827` |
> | Mihir - SoleDrop CTF Box 2: Bot Swarm (constant JA3) | Medium | `2520570392250804583` |
> | Mihir - SoleDrop CTF Box 3a: AI Concierge Abuse | High | `2520570395614636482` |
> | Mihir - SoleDrop CTF Box 3b: Credential Stuffing | High | `2520570399037188688` |
> | Mihir - SoleDrop CTF Box 4: Breakout (exploit + exfil) | High | `2520570402317134417` |
>
> Enable: `PUT /web/api/v2.1/cloud-detection/rules/enable` with
> `{"filter":{"ids":[…],"siteIds":["2433185103040607397"]}}`.

---

## What discovery changed (read this first)

The parser is the S1 marketplace OCSF parser (`marketplace-cloudflare-latest`),
and reality differed from the first-draft guesses in five important ways:

1. **Scope by `dataSource.name='Cloudflare'`, not `sourcetype=…`.** The
   sourcetype filter returned 0 rows; the data lives under
   `dataSource.name='Cloudflare'`.
2. **Your account already has a Cloudflare Gateway / Zero-Trust integration**
   feeding the *same* `dataSource.name='Cloudflare'` (≈374k events/7d). Our shop
   Logpush is a small slice of that. **Every rule must filter
   `http_request.url.hostname='shop.soledrop.co'`** or it drowns in Gateway noise.
   The two shop datasets are `dataSource.cloudflare_dataset='HTTP Requests'` and
   `='Firewall events'`.
3. **Fields are OCSF, not Cloudflare PascalCase** (see map below).
4. **JA4 isn't queryable** — the parser stores it as `ja4_fingerprint_list[0].value`,
   and PQ can't address the `[0]` array element (bracket won't parse, dot-index
   returns null). Use **`tls.ja3_hash.value`** (a flat field) — functionally
   identical for "one fingerprint, many UAs." (JA4 is still in `raw_data` if you
   ever need to `parse` it out.)
5. **WAF scores are ingested as *strings*** → wrap in `number()` for math, and
   **lower = more malicious is confirmed**: SQLi attack requests scored
   `WAFSQLiAttackScore = 8–10` and blocked breakout requests scored `1`, vs `~97`
   for clean traffic. (The CTF script's ">90" comment is wrong.) Guard against
   `number(null)→0` with `score > 0 && score <= 20`.

### Verified field map

| Logical field | OCSF path | Notes |
|---|---|---|
| Source IP | `src_endpoint.ip` | client IP as Cloudflare sees it |
| Host | `http_request.url.hostname` | filter to `shop.soledrop.co` |
| Dataset | `dataSource.cloudflare_dataset` | `HTTP Requests` / `Firewall events` |
| Path | `http_request.url.path` | |
| Full URL | `http_request.url.url_string` | carries the query string (markers) |
| Method | `http_request.http_method` | |
| User-Agent | `http_request.user_agent` | |
| TLS fingerprint | `tls.ja3_hash.value` | JA3 (use instead of JA4) |
| Bot score | `unmapped.BotScore` | string |
| WAF action | `action` | `log` / `block` (Firewall events) |
| WAF rule | `firewall_rule.desc`, `firewall_rule.uid` | our rule names show here |
| RCE / SQLi score | `unmapped.WAFRCEAttackScore` / `unmapped.WAFSQLiAttackScore` | **string**, lower=worse |
| AI injection score | `unmapped.FirewallForAIInjectionScore` | string, higher=worse (100 seen) |
| Edge status | `unmapped.EdgeResponseStatus` | string |

---

## Rule 1 — Box 1: Recon / vulnerability scanning
**One source IP hitting many distinct paths and/or scanner User-Agents.**
MITRE **T1595.002** · single-pipeline (alert-safe)

```text
dataSource.name='Cloudflare' http_request.url.hostname='shop.soledrop.co' src_endpoint.ip=*
| group distinct_paths = estimate_distinct(http_request.url.path),
        scanner_hits   = count(http_request.user_agent matches 'nikto|nuclei|sqlmap|masscan|wpscan|dirsearch|dirbuster|gobuster|feroxbuster|libwww-perl|python-requests|curl/'),
        total          = count(),
        sample_uas     = array_agg_distinct(http_request.user_agent, 8)
  by src_endpoint.ip
| filter distinct_paths >= 12 || scanner_hits >= 5
| sort -distinct_paths
| limit 100
```

**Live result:** attacker IPs returned **41 paths / 144 scanner hits** and
**39 / 97**; benign traffic maxed at **4 paths / 0 scanners** → thresholds
(`12` paths / `5` scanners) separate them cleanly.

---

## Rule 2 — Box 2: Polymorphic bot swarm (constant fingerprint)
**One TLS (JA3) fingerprint appearing under many different User-Agents.**
MITRE **T1595 / T1036.005** · single-pipeline (alert-safe)

```text
dataSource.name='Cloudflare' dataSource.cloudflare_dataset='HTTP Requests' http_request.url.hostname='shop.soledrop.co' tls.ja3_hash.value=*
| group ua_variety = estimate_distinct(http_request.user_agent),
        requests    = count(),
        ip_spread   = estimate_distinct(src_endpoint.ip),
        sample_uas  = array_agg_distinct(http_request.user_agent, 20)
  by fp = tls.ja3_hash.value
| filter ua_variety >= 6
| sort -ua_variety
| limit 50
```

**Live result:** the swarm fingerprint `86dab2109182b6bbaa644647d7db2997` returned
**37 distinct User-Agents / 871 requests**; every other JA3 had **1–2** UAs →
threshold `6` is safe. Depends on the **Bot Management** entitlement (present).

---

## Rule 3 — Box 3: concierge injection + credential stuffing
Because STAR bodies **don't allow `union`/subqueries**, deploy this as **two
separate alert-safe rules**. (The combined `union` form at the bottom is for
ad-hoc hunting only.)

### Rule 3a — AI-concierge abuse
MITRE **ATLAS AML.T0051** · single-pipeline

```text
dataSource.name='Cloudflare' http_request.url.hostname='shop.soledrop.co' http_request.url.path='/api/v1/chat'
| let inj = number(unmapped.FirewallForAIInjectionScore)
| group chat_hits = count(),
        max_injection = max(inj),
        waf_blocks    = count(action='block')
  by src_endpoint.ip
| filter chat_hits >= 5
| sort -chat_hits
| limit 100
```

**Live result:** attacker `104.28.153.9` → **95 chat hits, `max_injection=100`,
52 WAF blocks**; second IP → 60 hits / 31 blocks. `FirewallForAIInjectionScore`
**is** populated (100 = injection), a bonus over the earlier "off" assumption.

### Rule 3b — credential stuffing
MITRE **T1110.004** · single-pipeline

```text
dataSource.name='Cloudflare' http_request.url.hostname='shop.soledrop.co' http_request.url.path='/login' http_request.http_method='POST'
| group login_posts = count(), last_seen = max(timestamp)
  by src_endpoint.ip
| filter login_posts >= 8
| sort -login_posts
| limit 100
```

**Live result:** attacker IPs returned **53** and **24** login POSTs → threshold
`8` clears realistic human retries.

---

## Rule 4 — Box 4: Breakout (exploit + correlated exfiltration)
**Same IP that triggered low-score WAF exploit hits is also doing bulk exfil
pulls.** MITRE **T1190 + T1119/T1020** · uses **`inner join`** (alert-safe).

```text
| inner join
  (
    // (A) exploit attempts — WAF attack score in the malicious band (1–20)
    dataSource.name='Cloudflare' dataSource.cloudflare_dataset='HTTP Requests' http_request.url.hostname='shop.soledrop.co'
    | let sqli = number(unmapped.WAFSQLiAttackScore), rce = number(unmapped.WAFRCEAttackScore)
    | filter (sqli > 0 && sqli <= 20) || (rce > 0 && rce <= 20)
    | group exploit_hits = count(), worst_sqli = min(sqli), worst_rce = min(rce),
            exploit_paths = array_agg_distinct(http_request.url.path, 6)
      by src_endpoint.ip
    | filter exploit_hits >= 2
  ),
  (
    // (B) bulk exfil pulls of sensitive endpoints
    dataSource.name='Cloudflare' http_request.url.hostname='shop.soledrop.co' http_request.url.path in ('/api/v1/customers','/api/v1/training-data','/api/v1/users','/api/v1/models')
    | group exfil_hits = count(), exfil_paths = array_agg_distinct(http_request.url.path, 5)
      by src_endpoint.ip
    | filter exfil_hits >= 3
  )
  on src_endpoint.ip
| sort -exploit_hits
| limit 100
```

**Live result:** both attacker IPs correlated — **`exploit_hits=52`,
`worst_sqli=worst_rce=1`** (score 1 = definite attack) *joined to* **113 and 77
exfil pulls** across `/customers`, `/training-data`, `/users`, `/models`. Neither
half alone is high-fidelity; the correlation is.

---

## Deploying as scheduled PowerQuery detections

Per the S1 detection-rule contract:

- Deploy via `POST /web/api/v2.1/cloud-detection/rules` with **`queryType:"scheduled"`,
  `queryLang:"2.0"`**, query string in **`data.scheduledParams.query`**.
- **Alert threshold** = `scheduledParams.threshold {value:0, operator:"Greater"}`
  ("fire if the query returns any row") — the in-query `| filter … >= N` is what
  defines a finding, so N is the effective threshold.
- **Alert-safe:** all bodies stay ≤ 100 rows / well under 1 MB; no `nolimit`,
  `compare`, `transpose`, or subqueries. Box 4 uses `inner join` (allowed);
  Box 3 is split because `union` is not.
- **Window:** 10 min (Boxes 1–3), 15 min (Box 4).
- **Scope** each rule to the site/account receiving the Logpush.
- If the POST reports Scheduled Detections aren't licensed/enabled, enable
  *Settings → Detection / SDL Add-Ons → Scheduled Detections* first (don't
  downgrade to S1QL).

## Note on the source IP
`src_endpoint.ip` is the client IP **as Cloudflare sees it**. In this lab the
attack traffic surfaced as a couple of high-volume IPs (a Cloudflare egress IP
and the attack host's real IP) rather than the cosmetic per-request "src" shown
in the CTF console. The detections key on **per-IP volume/variety**, so this is
exactly the right entity — one IP doing 40+ paths / 37 UAs / 52 exploits stands
far out from real shoppers.
