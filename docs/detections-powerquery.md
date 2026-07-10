# SoleDrop CTF — SentinelOne STAR Detections (PowerQuery)

Four STAR / Custom Detection rule bodies — **one per CTF box** — for the Cloudflare
Logpush data landing in SentinelOne under `sourcetype="marketplace-cloudflare-latest"`
(datasets `firewall_events` + `http_requests`). Companion to
[attacks-and-detections.md](attacks-and-detections.md), which explains *what* each
box does and *why* things block vs. log.

> These are **drafts pending field-name confirmation** — run **Step 0** first,
> then adjust the field map if your parser names things differently. Every rule
> references the map, so it's a one-place edit.

---

## Step 0 — confirm the field names (run this once)

The `marketplace-cloudflare-latest` parser decides whether Cloudflare's fields
keep their original names (`ClientIP`, `JA4`, …) or get mapped to OCSF
(`src.ip.address`, `unmapped.*`). Discover the real shape before deploying:

```text
sourcetype="marketplace-cloudflare-latest" ClientRequestHost="shop.soledrop.co"
| limit 5
```

Inspect the returned records (or run `powerquery_schema_discover` on the
sourcetype) and confirm the paths below. Also verify the **two discriminators**
that tell the datasets apart:

- **`http_requests`** rows have **`ClientRequestHost`** (+ `ClientRequestURI`, `JA4`, `EdgeResponseStatus`).
- **`firewall_events`** rows have **`ClientRequestHTTPHost`** (+ `Action`, `RuleID`, `Kind`).

### Field map (edit here if discovery differs)

| Logical field | Assumed path (http_requests) | Assumed path (firewall_events) | OCSF fallback to check |
|---|---|---|---|
| Source IP | `ClientIP` | `ClientIP` | `src.ip.address` |
| Host | `ClientRequestHost` | `ClientRequestHTTPHost` | `url.hostname` |
| Path | `ClientRequestPath` | `ClientRequestPath` | `url.path` |
| Method | `ClientRequestMethod` | `ClientRequestHTTPMethodName` | `http_request.http_method` |
| User-Agent | `ClientRequestUserAgent` | `ClientRequestUserAgent` | `http_request.user_agent` |
| TLS fingerprint | `JA4` | — | `unmapped.JA4` |
| Bot score | `BotScore` | — | `unmapped.BotScore` |
| WAF action | `SecurityAction` | `Action` | `unmapped.Action` |
| WAF rule id | `SecurityRuleID` | `RuleID` | `unmapped.RuleID` |
| RCE score | `WAFRCEAttackScore` | `WAFRCEAttackScore` | `unmapped.WAFRCEAttackScore` |
| SQLi score | `WAFSQLiAttackScore` | `WAFSQLiAttackScore` | `unmapped.WAFSQLiAttackScore` |

> **Sourcetype field:** HEC-ingested data usually keeps `sourcetype` addressable.
> If it doesn't resolve on your tenant, swap `sourcetype="…"` for the
> Cloudflare `dataSource.name` value discovery shows.

> ⚠️ **Cloudflare WAF Attack Score direction:** Cloudflare's native convention is
> **1–99 where a *lower* score = *more* likely an attack** (`<= 20` ≈ malicious).
> The CTF script's comments assume the opposite — **confirm the direction in your
> data** on a known-malicious Box 4 event before trusting the score threshold.
> The Box 4 rule below leans on `Action="block"` (unambiguous) and treats the
> score as secondary.

---

## Rule 1 — Box 1: Recon / vulnerability scanning
**One source IP enumerating many distinct paths and/or using scanner User-Agents.**

MITRE: **T1595.002** Active Scanning: Vulnerability Scanning
Dataset: `http_requests` · Window: **10 min** rolling · Fires if ≥1 row returns.

```text
sourcetype="marketplace-cloudflare-latest" ClientRequestHost="shop.soledrop.co" ClientIP=*
| group distinct_paths = estimate_distinct(ClientRequestPath),
        scanner_hits   = count(ClientRequestUserAgent matches "nikto|nuclei|sqlmap|masscan|wpscan|dirsearch|dirbuster|gobuster|feroxbuster|libwww-perl|python-requests|curl/"),
        total_requests = count(),
        sample_paths   = array_agg_distinct(ClientRequestPath, 25),
        sample_uas     = array_agg_distinct(ClientRequestUserAgent, 10),
        first_seen     = min(timestamp),
        last_seen      = max(timestamp)
  by ClientIP
| filter distinct_paths >= 15 || scanner_hits >= 5
| sort -distinct_paths
| limit 100
```

- **Why it works:** real shoppers hit a handful of paths; a scanner touches
  dozens. `scanner_hits` catches the honest-UA tools even below the path
  threshold.
- **Tuning:** raise `distinct_paths` if a legit crawler (your own monitoring)
  trips it; add its UA/IP to an allowlist filter.
- **Output columns:** `ClientIP`, `distinct_paths`, `scanner_hits`, `sample_paths`.

---

## Rule 2 — Box 2: Polymorphic bot swarm (constant JA4)
**One TLS fingerprint (`JA4`) appearing under many different User-Agents.**

MITRE: **T1595** Active Scanning / **T1036.005** Masquerading
Dataset: `http_requests` · Window: **10 min** rolling.

```text
sourcetype="marketplace-cloudflare-latest" ClientRequestHost="shop.soledrop.co" JA4=*
| group ua_variety   = estimate_distinct(ClientRequestUserAgent),
        requests      = count(),
        src_ip_spread = estimate_distinct(ClientIP),
        sample_uas    = array_agg_distinct(ClientRequestUserAgent, 20),
        worst_botscore = min(BotScore)
  by JA4
| filter ua_variety >= 8 && requests >= 20
| sort -ua_variety
| limit 100
```

- **Why it works:** a real client library ↔ browser pairing shows **one JA4 per
  UA family**. Eight-plus wildly different UAs (sneaker bots + SDKs + headless)
  sharing **one** JA4 is physically impossible for real users — it's the same
  tool wearing disguises.
- **Known CTF fingerprint (optional tightening):** add
  `&& JA4 == "t13d1812h1_85036bcba153_b26ce05bbdd6"` to pin the exact lab client,
  or leave it off to catch *any* polymorphic swarm.
- **Depends on:** the **Bot Management** entitlement (emits `JA4`/`BotScore`).
- **Output columns:** `JA4`, `ua_variety`, `requests`, `src_ip_spread`.

---

## Rule 3 — Box 3: AI-concierge abuse + credential stuffing
**A burst of `/api/v1/chat` POSTs and/or a burst of `/login` POSTs from few IPs.**

MITRE: **ATLAS AML.T0051** LLM Prompt Injection / **T1110.004** Credential Stuffing
Dataset: `http_requests` (+ `firewall_events` for WAF-flagged chat) · Window: **10 min**.

> **Body-omission caveat:** Cloudflare logs **do not contain request bodies**, so
> the actual injection *prompt text* is **not** in this data — we detect the
> **behavioral shape** (abnormal volume to the concierge/login endpoints) plus any
> WAF block on `/api/v1/chat`. Deterministic prompt scoring needs **Firewall for
> AI** (`FirewallForAIInjectionScore`, currently off) or app-side logging.

```text
| union
  (
    // Concierge abuse: abnormal volume of chat POSTs from one IP
    sourcetype="marketplace-cloudflare-latest" ClientRequestHost="shop.soledrop.co" ClientRequestPath="/api/v1/chat" ClientRequestMethod="POST"
    | group hits = count(), last_seen = max(timestamp) by ClientIP
    | filter hits >= 4
    | columns signal = "concierge-abuse", ClientIP, hits, last_seen
  ),
  (
    // WAF already flagged a chat request as an attack (injection-like payload)
    sourcetype="marketplace-cloudflare-latest" ClientRequestHTTPHost="shop.soledrop.co" ClientRequestPath="/api/v1/chat" Action="block"
    | group hits = count(), last_seen = max(timestamp) by ClientIP
    | filter hits >= 1
    | columns signal = "concierge-waf-block", ClientIP, hits, last_seen
  ),
  (
    // Credential stuffing: burst of login POSTs from one IP
    sourcetype="marketplace-cloudflare-latest" ClientRequestHost="shop.soledrop.co" ClientRequestPath="/login" ClientRequestMethod="POST"
    | group hits = count(), last_seen = max(timestamp) by ClientIP
    | filter hits >= 10
    | columns signal = "credential-stuffing", ClientIP, hits, last_seen
  )
| sort -hits
| limit 100
```

- **Why it works:** the concierge/login endpoints are low-traffic for real users;
  automated abuse spikes the per-IP rate. The middle branch promotes any
  managed-WAF chat block straight to a finding.
- **Tuning:** the `/login` threshold (10) is the main knob — set it just above a
  human's realistic retry count.
- **Output columns:** `signal`, `ClientIP`, `hits`, `last_seen`.

---

## Rule 4 — Box 4: Breakout (exploit + correlated exfiltration)
**Same IP that triggered WAF *blocks* is also doing bulk pulls of sensitive endpoints.**

MITRE: **T1190** Exploit Public-Facing App + **T1119/T1020** Automated Collection & Exfiltration
Datasets: `firewall_events` (blocks) ⋈ `http_requests` (exfil) · Window: **15 min**.

```text
| join
  (
    // (A) exploit attempts — WAF block events (RCE/SQLi/traversal/SSRF)
    sourcetype="marketplace-cloudflare-latest" ClientRequestHTTPHost="shop.soledrop.co" Action="block" ClientIP=*
    | group block_hits  = count(),
            rule_ids     = array_agg_distinct(RuleID, 10),
            worst_rce    = min(WAFRCEAttackScore),
            worst_sqli   = min(WAFSQLiAttackScore)
      by ClientIP
    | filter block_hits >= 2
  ),
  (
    // (B) bulk exfil pulls of sensitive endpoints
    sourcetype="marketplace-cloudflare-latest" ClientRequestHost="shop.soledrop.co" ClientRequestPath in ("/api/v1/customers","/api/v1/training-data","/api/v1/users","/api/v1/models")
    | group exfil_hits  = count(),
            exfil_paths  = array_agg_distinct(ClientRequestPath, 5)
      by ClientIP
    | filter exfil_hits >= 3
  )
  on ClientIP
| sort -block_hits
| limit 100
```

- **Why it works:** either half alone is noisy (blocks happen; data endpoints get
  hit). The **correlation** — the *same source* both attacking locks and hauling
  data — is the high-fidelity breakout signal.
- **Score note:** `worst_rce`/`worst_sqli` use `min()` on the assumption
  **lower = worse** (see the ⚠️ in Step 0). Flip to `max()` if your data inverts
  it. The rule fires on `Action="block"` regardless, so it's robust either way.
- **Output columns:** `ClientIP`, `block_hits`, `rule_ids`, `exfil_hits`, `exfil_paths`.

---

## Deploying as STAR / Custom Detection rules

- Paste each body into **Detections → Custom Rules** (or a PowerQuery Alert).
- **Scope** each rule to the site/account receiving this zone's Logpush.
- **Window:** set the rule's rolling window to the value noted per rule (10–15 min).
- **Rule fires when the query returns ≥1 row** — the in-query `filter` thresholds
  define a "finding," so each returned row is one alert-worthy source.
- **Stay within alert limits:** each keeps output ≤ 100 rows / well under 1 MB, no
  `nolimit` / `compare` / `transpose` — all alert-safe.
- **Map alert fields** to the output columns (`ClientIP` as the entity, `last_seen`
  as timestamp, etc.).

## Validate before trusting

1. Run the CTF against `shop.soledrop.co`.
2. Run each body **as an ad-hoc PowerQuery** over the last 30 min (LRQ API or the
   Purple MCP) and confirm it returns the offending IP/JA4.
3. Only then promote to a scheduled detection — tune thresholds against a clean
   window so you know the false-positive floor.
