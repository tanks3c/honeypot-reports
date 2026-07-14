#!/usr/bin/env python3
"""
enrich_ips.py: collector side of the one-engine enrichment architecture.

This script no longer enriches anything itself. The central intel-enrich
engine (homebase) is the sole IP enrichment source: it owns the AbuseIPDB,
GreyNoise, and bulk-feed lookups, and it publishes verdicts for every IP
seen fleet-wide in the last 30 days. This script's whole job is the
exchange with that engine over the S3 bus:

  1. Pull the day's attacker IPs from the Wazuh indexer, with per-IP hit
     counts and first/last timestamps for the window.
  2. Upload them to s3://$ENRICH_BUCKET/enrichment/wazuh-ips.json so the
     engine knows what to enrich.
  3. Download the engine's enrichment/verdicts.json and save it as
     verdicts_cache.json in the repo root, so the page generators that
     make no network calls still get current verdicts.

ip_cache.db stays on disk as a read-only fallback for the report when the
central verdicts are unreachable. Its tables are never dropped here, and
its gn/abuse columns are no longer refreshed by anything in this repo.
"""

import os
import json
import sqlite3

from pathlib import Path

REPO = Path(__file__).resolve().parent

_env = REPO / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

from datetime import datetime, timezone
from opensearchpy import OpenSearch

# --- Config ---
OS_URL = os.environ.get("OPENSEARCH_URL", "https://localhost:9200")
OS_USER = os.environ.get("OPENSEARCH_USER", "admin")
OS_PASS = os.environ["OPENSEARCH_PASS"]

INDEX = "wazuh-alerts-4.x-*"
SRC_IP_FIELD = "data.src_ip"
LOOKBACK = "now-24h"
CACHE_DB = REPO / "ip_cache.db"
VERDICTS_CACHE = REPO / "verdicts_cache.json"


# ---------------------------------------------------------------------------
# Legacy cache, read only. The report falls back to these rows when the
# central verdicts are unreachable, so the DB must survive; nothing in this
# repo writes to it anymore.
# ---------------------------------------------------------------------------
def cache_lookup(ip):
    """Read one IP's last-known reputation row from ip_cache.db, or None."""
    if not CACHE_DB.exists():
        return None
    con = sqlite3.connect(CACHE_DB)
    try:
        r = con.execute(
            "SELECT abuse_score,abuse_reports,country,isp,"
            "gn_classification,gn_name FROM ips WHERE ip=?", (ip,)).fetchone()
    finally:
        con.close()
    if not r:
        return None
    return {"abuse_score": r[0], "abuse_reports": r[1], "country": r[2],
            "isp": r[3], "gn_classification": r[4], "gn_name": r[5]}


# ---------------------------------------------------------------------------
# S3 bus helpers. boto3 when installed, aws-cli otherwise, so the script
# works on both the analysis box and a bare admin shell.
# ---------------------------------------------------------------------------
def _s3_put(bucket, key, body: bytes):
    try:
        import boto3
        boto3.client("s3").put_object(
            Bucket=bucket, Key=key, Body=body,
            ContentType="application/json")
    except ImportError:
        import subprocess
        subprocess.run(["aws", "s3", "cp", "-", f"s3://{bucket}/{key}"],
                       input=body, check=True, capture_output=True)


def _s3_get(bucket, key) -> bytes:
    try:
        import boto3
        return boto3.client("s3").get_object(
            Bucket=bucket, Key=key)["Body"].read()
    except ImportError:
        import subprocess
        return subprocess.run(
            ["aws", "s3", "cp", f"s3://{bucket}/{key}", "-"],
            check=True, capture_output=True).stdout


# --- Pull IPs + per-IP stats from OpenSearch ---
def get_ip_stats():
    """One aggregation query returns everything the engine needs per IP:
    hit count plus first/last event timestamp inside the lookback window
    (ISO 8601, straight from the indexer's date fields)."""
    client = OpenSearch(
        OS_URL, http_auth=(OS_USER, OS_PASS),
        verify_certs=False, ssl_show_warn=False)
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": LOOKBACK}}},
        "aggs": {"ips": {
            "terms": {"field": SRC_IP_FIELD, "size": 1000},
            "aggs": {
                "first": {"min": {"field": "@timestamp"}},
                "last":  {"max": {"field": "@timestamp"}},
            },
        }},
    }
    resp = client.search(index=INDEX, body=body)
    stats = {}
    for b in resp["aggregations"]["ips"]["buckets"]:
        stats[b["key"]] = {
            "count": b["doc_count"],
            "first": b["first"].get("value_as_string"),
            "last":  b["last"].get("value_as_string"),
        }
    return stats


def upload_ip_list(stats):
    """Publish the day's distinct attacker IPs (with per-IP stats) to the
    S3 enrichment bus so the central intel-enrich engine can enrich them.
    Best-effort: never fails the run."""
    bucket = os.environ.get("ENRICH_BUCKET")
    if not bucket:
        print("[warn] ENRICH_BUCKET not set, skipping IP-list upload")
        return
    body = json.dumps({
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "generated": datetime.now(timezone.utc).isoformat(),
        "source": "wazuh-dionaea",
        "ips": sorted(stats),
        "stats": stats,
    })
    try:
        _s3_put(bucket, "enrichment/wazuh-ips.json", body.encode())
        print(f"[+] Uploaded {len(stats)} IPs to enrichment/wazuh-ips.json")
    except Exception as e:
        print(f"[warn] enrichment IP-list upload failed: {e}")


def refresh_verdicts_cache():
    """Pull the engine's verdicts.json to verdicts_cache.json in the repo
    root. The no-network page generators (malware_page.py, and the report
    when S3 is down) read this local copy. Gitignored: it is data, not
    code, and must never be committed. Best-effort: a failed download
    keeps the previous cache in place."""
    bucket = os.environ.get("ENRICH_BUCKET")
    if not bucket:
        print("[warn] ENRICH_BUCKET not set, skipping verdicts download")
        return
    try:
        body = _s3_get(bucket, "enrichment/verdicts.json")
        json.loads(body)  # refuse to clobber a good cache with junk
        VERDICTS_CACHE.write_bytes(body)
        print(f"[+] verdicts_cache.json refreshed ({len(body)} bytes)")
    except Exception as e:
        print(f"[warn] verdicts download failed: {e}")


# --- Main ---
def main():
    stats = get_ip_stats()
    print(f"[*] {len(stats)} unique IPs pulled")
    upload_ip_list(stats)
    refresh_verdicts_cache()


if __name__ == "__main__":
    main()
