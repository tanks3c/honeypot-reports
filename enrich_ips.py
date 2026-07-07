#!/usr/bin/env python3

import os
import csv
import gzip
import json
import time
import ipaddress
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


# --- Local bulk-feed layer (shared design with the spamtrap pipeline) ---
# Downloads free/already-keyed reputation feeds into the local cache DB so
# most IPs are resolved locally (known-bad + ASN/country) with no per-IP API
# call. Refreshed roughly daily.
FEED_TTL = 20 * 3600


def _ensure_feed_schema(con):
    con.executescript("""
    CREATE TABLE IF NOT EXISTS feed_bad_ips (ip TEXT, source TEXT,
        PRIMARY KEY(ip, source));
    CREATE INDEX IF NOT EXISTS idx_fbi ON feed_bad_ips(ip);
    CREATE TABLE IF NOT EXISTS feed_netblocks (start_int INTEGER,
        end_int INTEGER, source TEXT);
    CREATE INDEX IF NOT EXISTS idx_fnb ON feed_netblocks(start_int);
    CREATE TABLE IF NOT EXISTS asn_ranges (start_int INTEGER, end_int INTEGER,
        asn INTEGER, country TEXT, org TEXT);
    CREATE INDEX IF NOT EXISTS idx_asr ON asn_ranges(start_int);
    CREATE TABLE IF NOT EXISTS feed_meta (source TEXT PRIMARY KEY,
        updated REAL, count INTEGER);
    """)


def _mark(con, source, count):
    con.execute("INSERT INTO feed_meta VALUES (?,?,?) ON CONFLICT(source) DO "
                "UPDATE SET updated=excluded.updated, count=excluded.count",
                (source, time.time(), count))
    print(f"[+] feed {source}: {count}")


def _load_bad(con, source, ips):
    con.execute("DELETE FROM feed_bad_ips WHERE source=?", (source,))
    con.executemany("INSERT OR IGNORE INTO feed_bad_ips VALUES (?,?)",
                    [(ip, source) for ip in ips])
    _mark(con, source, len(ips))


def sync_feeds(con):
    _ensure_feed_schema(con)
    row = con.execute("SELECT MIN(updated) FROM feed_meta").fetchone()
    if row and row[0] and time.time() - row[0] < FEED_TTL:
        print("[*] feeds fresh, skipping download")
        return
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/blacklist",
                         headers={"Key": ABUSE_KEY, "Accept": "application/json"},
                         params={"confidenceMinimum": 75, "limit": 10000},
                         timeout=60)
        r.raise_for_status()
        _load_bad(con, "abuseipdb",
                  [x["ipAddress"] for x in r.json().get("data", []) if x.get("ipAddress")])
    except Exception as e:
        print("[warn] abuseipdb blacklist:", e)
    try:
        r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                         timeout=60)
        r.raise_for_status()
        _load_bad(con, "feodo",
                  [x["ip_address"] for x in r.json() if x.get("ip_address")])
    except Exception as e:
        print("[warn] feodo:", e)
    try:
        r = requests.get("https://www.spamhaus.org/drop/drop.txt", timeout=60)
        r.raise_for_status()
        rows = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            try:
                net = ipaddress.ip_network(line.split(";")[0].strip(), strict=False)
            except ValueError:
                continue
            rows.append((int(net.network_address), int(net.broadcast_address),
                         "spamhaus-drop"))
        con.execute("DELETE FROM feed_netblocks WHERE source='spamhaus-drop'")
        con.executemany("INSERT INTO feed_netblocks VALUES (?,?,?)", rows)
        _mark(con, "spamhaus-drop", len(rows))
    except Exception as e:
        print("[warn] drop:", e)
    try:
        r = requests.get("https://iptoasn.com/data/ip2asn-v4.tsv.gz", timeout=120)
        r.raise_for_status()
        rows = []
        for line in gzip.decompress(r.content).decode("utf-8", "replace").splitlines():
            p = line.split("\t")
            if len(p) < 5 or p[2] == "0":
                continue
            try:
                rows.append((int(ipaddress.ip_address(p[0])),
                             int(ipaddress.ip_address(p[1])), int(p[2]), p[3], p[4]))
            except ValueError:
                continue
        con.execute("DELETE FROM asn_ranges")
        con.executemany("INSERT INTO asn_ranges VALUES (?,?,?,?,?)", rows)
        _mark(con, "iptoasn", len(rows))
    except Exception as e:
        print("[warn] iptoasn:", e)
    con.commit()


def local_ip(con, ip):
    out = {"known_bad": 0, "bad_sources": None, "asn": None,
           "country": None, "org": None}
    srcs = [r[0] for r in con.execute(
        "SELECT source FROM feed_bad_ips WHERE ip=?", (ip,)).fetchall()]
    try:
        n = int(ipaddress.ip_address(ip))
    except ValueError:
        return out
    nb = con.execute("SELECT source FROM feed_netblocks WHERE start_int<=? "
                     "AND end_int>=? LIMIT 1", (n, n)).fetchone()
    if nb:
        srcs.append(nb[0])
    if srcs:
        out["known_bad"] = 1
        out["bad_sources"] = ",".join(sorted(set(srcs)))
    a = con.execute("SELECT asn, country, org FROM asn_ranges WHERE start_int<=? "
                    "AND end_int>=? ORDER BY start_int DESC LIMIT 1",
                    (n, n)).fetchone()
    if a:
        out["asn"], out["country"], out["org"] = a
    return out


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

    lo = local_ip(con, ip)
    rec.update({"known_bad": lo["known_bad"], "bad_sources": lo["bad_sources"],
                "asn": lo["asn"], "org": lo["org"]})

    cached_abuse = cache_get_abuse(con, ip)
    if cached_abuse:
        rec.update(cached_abuse)
    elif lo["known_bad"]:
        # a local feed already flagged this IP; skip AbuseIPDB, use local geo
        rec.update({"abuse_score": None, "abuse_reports": None,
                    "country": lo["country"], "isp": None})
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
    if not rec.get("country"):
        rec["country"] = lo["country"]

    if not (abuse_limited_now or gn_limited_now):
        time.sleep(0.3)

    return rec, abuse_limited_now, gn_limited_now


# --- Main ---
def main():
    con = init_cache()
    sync_feeds(con)
    ips = get_unique_ips()
    print(f"[*] {len(ips)} unique IPs pulled")

    fields = ["ip", "known_bad", "bad_sources", "asn", "org",
              "abuse_score", "abuse_reports", "country",
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
