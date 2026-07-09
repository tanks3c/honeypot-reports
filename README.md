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

## Sample Enrichment Pipeline

`enrich_samples.py` is the malware-side sibling of `enrich_ips.py`. Where the IP
pipeline turns an attacker IP into a reputation verdict, this turns a captured
Dionaea sample (MD5) into a malware verdict: `ELF/Mirai, 41/64 AV detections,
first seen 2026-06`. It closes the gap where the pipeline saw connections but
never the payloads Dionaea actually captured.

### What it does

1. Pull the distinct MD5 hashes Dionaea captured over the last 24 hours from the
   indexer (matches on the presence of a hash field, since captures are a
   different event shape than accept events).
2. Check the shared `ip_cache.db` (`samples` table) before any API call.
3. On cache miss, query MalwareBazaar and, if a key is present, VirusTotal.
4. Write results to cache with per-source TTLs (MalwareBazaar 7 days, VirusTotal
   24 hours), then flatten to `samples_YYYYMMDD.csv`.

`wazuh_daily_report.py` reads the `samples` table to render the "Malware
captured" panel. Missing keys, missing rows, or an absent table degrade to `-`;
they never fail the report.

### Fields added

| Source | Field added | Purpose |
|---|---|---|
| MalwareBazaar | signature (family), file type, tags, first seen, sha256 | Sample identity and lineage |
| VirusTotal | AV malicious / total ratio | Cross-engine detection confidence |

### Setup

Add to the same `.env` (both optional; each degrades gracefully if absent):

```
MB_AUTH_KEY=your_malwarebazaar_key
VT_KEY=your_virustotal_key
```

### Run

```
.venv/bin/python enrich_samples.py
.venv/bin/python enrich_samples.py --hash <md5>   # one hash, skips the indexer
```

### Schedule

Daily cron on the analysis box, after `enrich_ips.py` so the report has both:

```
0 6 * * * cd /home/ssm-user/honeypot-reports && .venv/bin/python enrich_samples.py >> cron.log 2>&1
```

### Known limits

- VirusTotal free tier is 4 lookups per minute; the script throttles 15 seconds
  per uncached hash and trips a per-run circuit breaker on HTTP 429.
- MalwareBazaar now requires a free `Auth-Key`. Without `MB_AUTH_KEY`, family /
  file type / tags render as `-`; the rest of the report is unaffected.
- The candidate hash-field paths in `_MD5_FIELDS` (shared with the report) are a
  best-effort superset. Confirm the live indexer's real field name and prune to
  it once verified.

## Capture Source (sqlite ground truth)

The Wazuh indexer carries only `accept` connections, not Dionaea download
events, so captured malware never reaches the SIEM. Captures live only in the
honeypot's sqlite (`/opt/dionaea/data/dionaea.sqlite`, `downloads` table).

`dionaea_downloads.py` reads that table directly over SSM (`send-command`,
read-only query, nothing written on the honeypot) and emits
`captures_YYYYMMDD.json` in the shape the report renders. The honeypot has no
outbound internet (egress locked to the SIEM + SSM endpoints), so SSM is the
only channel in; whoever runs it needs `ssm:SendCommand` to the honeypot (the
`honeymike` profile has it).

```
python3 dionaea_downloads.py
python3 wazuh_daily_report.py --captures-json captures_$(date -u +%Y%m%d).json
python3 enrich_samples.py     --captures-json captures_$(date -u +%Y%m%d).json
```

`--captures-json` is the real capture path; without it the report/enricher fall
back to the indexer, which returns zero download events.

### Scheduling

`capture_pipeline.sh` chains pull -> enrich -> embed -> commit and runs on
homebase via a systemd user timer (`deploy/honeypot-capture.{service,timer}`,
every 6h). Homebase is the right host: it has the `honeymike` profile and
outbound, while the honeypot has neither and the report host has no honeymike
creds. It commits `captures_latest.json` to the repo; the analysis-box report
picks it up on its next `git pull` and renders it via `--captures-json`.

```
cp deploy/honeypot-capture.* ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now honeypot-capture.timer
```

Keys are read from SSM (`/spamtrap/abusech-key`, `/spamtrap/virustotal-key`)
via the `honeymike` profile, so no secrets live in the repo or the timer. On a
host that uses an instance role instead of a named profile, set
`AWS_KEY_PROFILE=` (empty) in the environment.

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
| Sample enrichment | enrich_samples.py (MalwareBazaar, VirusTotal) |
| Cache | SQLite |
| Framework | MITRE ATT&CK |

## Notes

Infrastructure specifics (internal addressing, instance details, credentials) are intentionally left out of these reports. Attacker indicators are retained because they are the subject of the analysis. Timestamps are normalized to UTC.

These are personal lab reports. The activity described hit a honeypot built to attract it. Nothing here reflects a production environment.
