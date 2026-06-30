# Honeypot Indicator Analysis

Honeypot Indicator Analysis Dashboard & Reports generated from a personal Dionaea honeypot, written to practice and demonstrate SOC analyst tradecraft: raw source validation, IOC enrichment, MITRE ATT&CK mapping, and detection gap analysis.

## About

This repo holds a dashboard (/docs) and finished analysis from a honeypot I run in AWS. Each report starts from raw sensor data, gets enriched with open source threat intel, and ends with an assessment and concrete detection recommendations. The goal is not to collect alerts. The goal is to show I can take a hit from first contact to a decision a SOC would actually use.

Every report follows the same structure so they read consistently and so the methodology stays repeatable. Enrichment is automated by a Python pipeline (see Enrichment Pipeline below) so the manual analysis can focus on assessment instead of lookups.

## Lab Architecture

```
Internet  ->  Dionaea honeypot (AWS EC2)
                  |
                  |  sqlite (ground truth)   +   JSON log
                  |
                  v
            Wazuh agent  ->  Wazuh manager (decoders + rules)
                                  |
                                  v
                        OpenSearch Dashboards (DQL hunting)
                                  |
                                  v
                        enrich_ips.py  ->  enriched_YYYYMMDD.csv
```

Dionaea writes connection data two ways: directly to a sqlite database at the moment of connection, and to a JSON log that the Wazuh agent tails. The sqlite database is treated as ground truth. The Wazuh and OpenSearch path is the SIEM view. Comparing the two is part of the process, not an afterthought.

The enrichment pipeline runs on the analysis box. It pulls unique source IPs from OpenSearch and attaches threat intel to each one.

## Methodology

Each report works the same seven steps. This keeps the analysis disciplined and makes every report comparable to the last.

1. Pivot on the indicator in raw source (sqlite) for ground truth count, protocol, transport, and time window.
2. Check for payloads (downloads table) to confirm whether anything was dropped or staged.
3. Enrich the source IP: reverse DNS, ASN and org, geolocation, AbuseIPDB, GreyNoise, and WHOIS abuse contact.
4. Characterize the behavior: connection rate, single port versus sweep, steady versus bursty.
5. Map MITRE ATT&CK from observed behavior, not from assumed intent.
6. Note detection gaps: confirm whether the expected rule fired and why or why not.
7. Write a BLUF and a recommendation a SOC can act on.

Step 3 is automated by the enrichment pipeline. It produces a dated CSV of AbuseIPDB and GreyNoise results that each report draws from.

## Enrichment Pipeline

`enrich_ips.py` automates source IP enrichment so every report starts from consistent, pre-collected threat intel instead of manual lookups.

### What it does

1. Query OpenSearch for unique source IPs over the last 24 hours.
2. Check a local SQLite cache before any API call.
3. On cache miss, query AbuseIPDB and GreyNoise.
4. Write results to cache with a 24 hour TTL.
5. Flatten all results to `enriched_YYYYMMDD.csv`.

### Fields added

| Source | Field added | Purpose |
|---|---|---|
| AbuseIPDB | abuse score, report count, country, ISP | Reputation and abuse history |
| GreyNoise | classification, actor name | Mass scanner vs targeted threat |

### Setup

```
python3 -m venv .venv
source .venv/bin/activate
pip install requests opensearch-py
```

Create a `.env` file in the repo root. It is gitignored and never committed.

```
ABUSEIPDB_KEY=your_key
GREYNOISE_KEY=your_key
OPENSEARCH_URL=https://localhost:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASS=your_pass
```

The script auto-loads `.env` on every run.

### Run

```
.venv/bin/python enrich_ips.py
```

### Schedule

Daily cron on the analysis box:

```
0 6 * * * cd /home/ssm-user/honeypot-reports && .venv/bin/python enrich_ips.py >> cron.log 2>&1
```

### Known limits

- GreyNoise community tier caps near 50 lookups per day. Excess returns HTTP 429. Gaps self-heal on the next day's run via the cache.
- AbuseIPDB free tier allows 1000 lookups per day, enough for current volume.
- The script throttles 1.5 seconds per uncached IP to stay under rate limits.
- The analysis box must be running at the scheduled time for cron to fire.

### Configuration

Two values at the top of `enrich_ips.py` match the environment:

- `INDEX = "wazuh-alerts-4.x-*"`
- `SRC_IP_FIELD = "data.src_ip"`

## Reports

| Date | Source IP | Activity | Disposition |
|---|---|---|---|
| 2026-06-26 | 61.230.69.104 | SMB reconnaissance on TCP/445 | No malware. Assessed as automated scanning (T1595.001). [Report](./smb-recon-61.230.69.104.md) |

## Tooling

| Function | Tool |
|---|---|
| Honeypot | Dionaea |
| SIEM | Wazuh |
| Search and dashboards | OpenSearch Dashboards (DQL) |
| Raw data analysis | sqlite3, Python, pandas |
| IP enrichment | enrich_ips.py (AbuseIPDB, GreyNoise), IPinfo, APNIC WHOIS |
| Cache | SQLite |
| Framework | MITRE ATT&CK |

## Notes

Infrastructure specifics (internal addressing, instance details, credentials) are intentionally left out of these reports. Attacker indicators are retained because they are the subject of the analysis. Timestamps are normalized to UTC.

These are personal lab reports. The activity described hit a honeypot built to attract it. Nothing here reflects a production environment.
