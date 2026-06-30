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

INDEX = "wazuh-alerts-4.x-*"          # adjust to your honeypot index
SRC_IP_FIELD = "data.src_ip"       # adjust to your field name
LOOKBACK = "now-24h"              # how far back to pull IPs
CACHE_DB = "ip_cache.db"
CACHE_TTL = 86400                 # re-query an IP only after 24h
OUT_CSV = f"enriched_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"


# --- Cache ---
def init_cache():
    con = sqlite3.connect(CACHE_DB)
    con.execute("""CREATE TABLE IF NOT EXISTS ips (
        ip TEXT PRIMARY KEY,
        abuse_score INTEGER,
        abuse_reports INTEGER,
        country TEXT,
        isp TEXT,
        gn_classification TEXT,
        gn_name TEXT,
        ts INTEGER
    )""")
    con.commit()
    return con


def cache_get(con, ip):
    row = con.execute(
        "SELECT abuse_score,abuse_reports,country,isp,gn_classification,gn_name,ts "
        "FROM ips WHERE ip=?", (ip,)).fetchone()
    if row and (time.time() - row[6]) < CACHE_TTL:
        return {
            "ip": ip, "abuse_score": row[0], "abuse_reports": row[1],
            "country": row[2], "isp": row[3],
            "gn_classification": row[4], "gn_name": row[5],
        }
    return None


def cache_put(con, rec):
    con.execute(
        "INSERT OR REPLACE INTO ips VALUES (?,?,?,?,?,?,?,?)",
        (rec["ip"], rec["abuse_score"], rec["abuse_reports"], rec["country"],
         rec["isp"], rec["gn_classification"], rec["gn_name"], int(time.time())))
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


# --- Enrichment ---
def query_abuseipdb(ip):
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSE_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=15)
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
    if r.status_code == 404:
        return {"gn_classification": "unknown", "gn_name": ""}
    r.raise_for_status()
    d = r.json()
    return {
        "gn_classification": d.get("classification", "unknown"),
        "gn_name": d.get("name", ""),
    }


def enrich(con, ip):
    cached = cache_get(con, ip)
    if cached:
        return cached
    rec = {"ip": ip}
    try:
        rec.update(query_abuseipdb(ip))
    except Exception as e:
        rec.update({"abuse_score": None, "abuse_reports": None,
                    "country": None, "isp": f"error:{e}"})
    try:
        rec.update(query_greynoise(ip))
    except Exception as e:
        rec.update({"gn_classification": f"error:{e}", "gn_name": ""})
    cache_put(con, rec)
    time.sleep(1.5)   # stay under free rate limits
    return rec


# --- Main ---
def main():
    con = init_cache()
    ips = get_unique_ips()
    print(f"[*] {len(ips)} unique IPs pulled")

    fields = ["ip", "abuse_score", "abuse_reports", "country",
              "isp", "gn_classification", "gn_name"]
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for i, ip in enumerate(ips, 1):
            rec = enrich(con, ip)
            w.writerow({k: rec.get(k) for k in fields})
            print(f"[{i}/{len(ips)}] {ip} "
                  f"abuse={rec.get('abuse_score')} "
                  f"gn={rec.get('gn_classification')}")
    print(f"[+] Wrote {OUT_CSV}")


if __name__ == "__main__":
    main()
