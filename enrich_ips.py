#!/usr/bin/env python3

import os
import csv
import json
import time
import sqlite3
import requests

from pathlib import Path
_env = Path(__file__).parent / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

from datetime import datetime, timezone
from opensearchpy import OpenSearch

# --- Config ---
ABUSE_KEY = os.environ["ABUSEIPDB_KEY"]
GN_KEY = os.environ["GREYNOISE_KEY"]
OS_URL = os.environ.get("OPENSEARCH_URL", "https://localhost:9200")
OS_USER = os.environ.get("OPENSEARCH_USER", "admin")
OS_PASS = os.environ["OPENSEARCH_PASS"]

INDEX = "wazuh-alerts-4.x-*"
SRC_IP_FIELD = "data.src_ip"
LOOKBACK = "now-24h"
CACHE_DB = "ip_cache.db"
CACHE_TTL = 86400
OUT_CSV = f"enriched_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"

# --- Rate-limit circuit breaker (module-level, per run) ---
# Once either API returns 429, stop calling it for the rest of this run.
_LIMITED = {"abuse": False, "gn": False}


class RateLimited(Exception):
    """Raised when an API returns 429."""
    pass


# ---------------------------------------------------------------------------
# Cache: per-source freshness, not per-row.
#
# Why: the two APIs fail independently (different providers, different rate
# limit windows). If GreyNoise is rate-limited but AbuseIPDB isn't, we still
# want to cache the good AbuseIPDB result immediately, not throw it away and
# re-query it (and burn its own limit) on the next run just because GreyNoise
# had a bad day. abuse_ts and gn_ts track freshness independently per IP.
# ---------------------------------------------------------------------------
def init_cache():
    con = sqlite3.connect(CACHE_DB)
    con.execute("""CREATE TABLE IF NOT EXISTS ips (
        ip TEXT PRIMARY KEY,
        abuse_score INTEGER,
        abuse_reports INTEGER,
        country TEXT,
        isp TEXT,
        abuse_ts INTEGER,
        gn_classification TEXT,
        gn_name TEXT,
        gn_ts INTEGER
    )""")
    # Migration path: older DBs (single `ts` column) get upgraded in place.
    cols = {row[1] for row in con.execute("PRAGMA table_info(ips)").fetchall()}
    if "ts" in cols and "abuse_ts" not in cols:
        con.execute("ALTER TABLE ips ADD COLUMN abuse_ts INTEGER")
        con.execute("ALTER TABLE ips ADD COLUMN gn_ts INTEGER")
        con.execute("UPDATE ips SET abuse_ts = ts, gn_ts = ts WHERE abuse_ts IS NULL")
    con.commit()
    return con


def _row(con, ip):
    return con.execute(
        "SELECT abuse_score,abuse_reports,country,isp,abuse_ts,"
        "gn_classification,gn_name,gn_ts FROM ips WHERE ip=?", (ip,)).fetchone()


def cache_get_abuse(con, ip):
    r = _row(con, ip)
    if r and r[4] is not None and (time.time() - r[4]) < CACHE_TTL:
        return {"abuse_score": r[0], "abuse_reports": r[1], "country": r[2], "isp": r[3]}
    return None


def cache_get_gn(con, ip):
    r = _row(con, ip)
    if r and r[7] is not None and (time.time() - r[7]) < CACHE_TTL:
        return {"gn_classification": r[5], "gn_name": r[6]}
    return None


def cache_put_abuse(con, ip, fields):
    con.execute("""
        INSERT INTO ips (ip, abuse_score, abuse_reports, country, isp, abuse_ts)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
            abuse_score=excluded.abuse_score,
            abuse_reports=excluded.abuse_reports,
            country=excluded.country,
            isp=excluded.isp,
            abuse_ts=excluded.abuse_ts
    """, (ip, fields["abuse_score"], fields["abuse_reports"],
          fields["country"], fields["isp"], int(time.time())))
    con.commit()


def cache_put_gn(con, ip, fields):
    con.execute("""
        INSERT INTO ips (ip, gn_classification, gn_name, gn_ts)
        VALUES (?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
            gn_classification=excluded.gn_classification,
            gn_name=excluded.gn_name,
            gn_ts=excluded.gn_ts
    """, (ip, fields["gn_classification"], fields["gn_name"], int(time.time())))
    con.commit()


# --- Pull IPs from OpenSearch ---
def get_unique_ips():
    client = OpenSearch(
        OS_URL, http_auth=(OS_USER, OS_PASS),
        verify_certs=False, ssl_show_warn=False)
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": LOOKBACK}}},
        "aggs": {"ips": {"terms": {"field": SRC_IP_FIELD, "size": 1000}}},
    }
    resp = client.search(index=INDEX, body=body)
    return [b["key"] for b in resp["aggregations"]["ips"]["buckets"]]


# --- API calls ---
def query_abuseipdb(ip):
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSE_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=15)
    if r.status_code == 429:
        raise RateLimited("abuseipdb")
    r.raise_for_status()
    d = r.json()["data"]
    return {
        "abuse_score": d.get("abuseConfidenceScore"),
        "abuse_reports": d.get("totalReports"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
    }


def query_greynoise(ip):
    r = requests.get(
        f"https://api.greynoise.io/v3/community/{ip}",
        headers={"key": GN_KEY, "Accept": "application/json"}, timeout=15)
    if r.status_code == 429:
        raise RateLimited("greynoise")
    if r.status_code == 404:
        return {"gn_classification": "unknown", "gn_name": ""}
    r.raise_for_status()
    d = r.json()
    return {
        "gn_classification": d.get("classification", "unknown"),
        "gn_name": d.get("name", ""),
    }


def enrich(con, ip):
    """
    Resolve one IP's reputation. AbuseIPDB and GreyNoise are handled and
    cached fully independently: a rate limit or error on one never blocks
    caching a good result from the other, and never forces a re-query of
    a source that already succeeded within CACHE_TTL.

    Returns (record, abuse_limited_now, gn_limited_now).
    """
    rec = {"ip": ip}
    abuse_limited_now = False
    gn_limited_now = False

    cached_abuse = cache_get_abuse(con, ip)
    if cached_abuse:
        rec.update(cached_abuse)
    elif _LIMITED["abuse"]:
        rec.update({"abuse_score": None, "abuse_reports": None,
                    "country": None, "isp": None})
    else:
        try:
            fields = query_abuseipdb(ip)
            rec.update(fields)
            cache_put_abuse(con, ip, fields)
        except RateLimited:
            _LIMITED["abuse"] = True
            abuse_limited_now = True
            rec.update({"abuse_score": None, "abuse_reports": None,
                        "country": None, "isp": None})
        except Exception as e:
            print(f"    [warn] abuseipdb error for {ip}: {e}")
            rec.update({"abuse_score": None, "abuse_reports": None,
                        "country": None, "isp": None})

    cached_gn = cache_get_gn(con, ip)
    if cached_gn:
        rec.update(cached_gn)
    elif _LIMITED["gn"]:
        rec.update({"gn_classification": None, "gn_name": None})
    else:
        try:
            fields = query_greynoise(ip)
            rec.update(fields)
            cache_put_gn(con, ip, fields)
        except RateLimited:
            _LIMITED["gn"] = True
            gn_limited_now = True
            rec.update({"gn_classification": None, "gn_name": None})
        except Exception as e:
            print(f"    [warn] greynoise error for {ip}: {e}")
            rec.update({"gn_classification": None, "gn_name": None})

    # Rate-limit path only: rest here since success paths already slept
    # is unnecessary; keep a light pace on the happy path only.
    if not (abuse_limited_now or gn_limited_now):
        time.sleep(0.3)

    return rec, abuse_limited_now, gn_limited_now


# --- Main ---
def main():
    con = init_cache()
    ips = get_unique_ips()
    print(f"[*] {len(ips)} unique IPs pulled")

    fields = ["ip", "abuse_score", "abuse_reports", "country",
              "isp", "gn_classification", "gn_name"]

    abuse_fresh = abuse_cached = abuse_skipped = 0
    gn_fresh = gn_cached = gn_skipped = 0

    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for i, ip in enumerate(ips, 1):
            rec, a_lim, g_lim = enrich(con, ip)
            w.writerow({k: rec.get(k) for k in fields})

            if a_lim:
                print(f"[{i}/{len(ips)}] RATE LIMIT: abuseipdb. Stopping abuseipdb "
                      f"calls for this run, cached results still used, "
                      f"uncached IPs retry next run.")
            if g_lim:
                print(f"[{i}/{len(ips)}] RATE LIMIT: greynoise. Stopping greynoise "
                      f"calls for this run, cached results still used, "
                      f"uncached IPs retry next run.")

            if rec.get("abuse_score") is None and not cache_get_abuse(con, ip):
                abuse_skipped += 1
            print(f"[{i}/{len(ips)}] {ip} "
                  f"abuse={rec.get('abuse_score')} "
                  f"gn={rec.get('gn_classification')}")

            if _LIMITED["abuse"] and _LIMITED["gn"]:
                remaining = ips[i:]
                for rip in remaining:
                    w.writerow({k: (rip if k == "ip" else None) for k in fields})
                print(f"[*] Both APIs rate-limited. {len(remaining)} remaining IPs "
                      f"written as unresolved, will retry next scheduled run.")
                break

    print(f"[+] Wrote {OUT_CSV}")


if __name__ == "__main__":
    main()
