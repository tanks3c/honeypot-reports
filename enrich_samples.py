#!/usr/bin/env python3
"""
enrich_samples.py
=================
Sample (captured-malware hash) enrichment. Sibling of enrich_ips.py.

Where enrich_ips.py turns an attacker IP into a reputation verdict, this turns
a captured Dionaea sample (MD5) into a malware verdict:
  "ELF/Mirai, 41/64 AV detections, first seen 2026-06."

It pulls the distinct MD5 hashes Dionaea captured over the lookback window from
the indexer, enriches each against MalwareBazaar (family / file type / tags /
first seen) and, if a key is present, VirusTotal (AV detection ratio), and
writes the results into the same ip_cache.db the daily report reads (samples
table) plus a samples_YYYYMMDD.csv.

Design mirrors enrich_ips.py deliberately:
  - .env auto-load
  - per-source cache freshness (mb_ts, vt_ts as independent TTLs), so a
    VirusTotal rate-limit never throws away a good MalwareBazaar result
  - a 429 circuit breaker per source (stop calling it for the rest of the run)
  - graceful degradation when a key is missing or a source is unavailable

Auth (all optional, read from env or .env):
  OPENSEARCH_URL / OPENSEARCH_USER / OPENSEARCH_PASS  - indexer (to pull hashes)
  MB_AUTH_KEY   - MalwareBazaar Auth-Key (free; MB now requires it). Absent =>
                  MalwareBazaar is skipped, not fatal.
  VT_KEY        - VirusTotal API key. Absent => VirusTotal is skipped.

Usage:
      python3 enrich_samples.py
      python3 enrich_samples.py --hours 48
      python3 enrich_samples.py --hash <md5>      # enrich one hash, no indexer
"""

import os
import csv
import sys
import json
import time
import sqlite3
import argparse
import subprocess
import requests

from pathlib import Path
from datetime import datetime, timezone

# --- .env auto-load (same pattern as enrich_ips.py) ---
_env = Path(__file__).parent / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

# Reuse the report's field-path candidates so the two stay in lockstep. If the
# import fails for any reason, fall back to a local copy of the same lists.
try:
    from wazuh_daily_report import _MD5_FIELDS, _dig, _first
except Exception:  # pragma: no cover - defensive only
    _MD5_FIELDS = ["data.md5_hash", "data.md5hash", "data.md5",
                   "data.download.md5", "data.dionaea.md5_hash"]

    def _dig(src, dotted):
        cur = src
        for part in dotted.split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur

    def _first(src, fields):
        for f in fields:
            v = _dig(src, f)
            if v not in (None, "", []):
                return v
        return None

# --- Config ---
OS_URL = os.environ.get("OPENSEARCH_URL", "https://localhost:9200")
OS_USER = os.environ.get("OPENSEARCH_USER", "admin")
INDEX = os.environ.get("WZ_INDEX", "wazuh-alerts-4.x-*")
RULE_GROUP = os.environ.get("WZ_GROUP", "dionaea")
CACHE_DB = os.environ.get("SAMPLE_CACHE_DB", "ip_cache.db")

MB_TTL = 7 * 86400        # family/type/first-seen are ~immutable; refresh weekly
VT_TTL = 24 * 3600        # AV detections grow over time; refresh daily
VT_THROTTLE = 15          # free tier is 4 req/min => >=15s between calls
OUT_CSV = f"samples_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"

# Secret resolution. Env var wins; else an SSM SecureString param. abuse.ch
# uses ONE unified Auth-Key across MalwareBazaar / ThreatFox / URLhaus, and
# intel-enrich already stores it at /spamtrap/abusech-key, so reuse it rather
# than duplicating the secret. VT key sits alongside it.
#
# AWS_KEY_PROFILE selects the profile for the SSM read: default "honeymike"
# works from homebase; set it EMPTY on the analysis box so the instance role
# (already in the honeypot account) is used instead of a named profile.
MB_KEY_SSM_PARAM = os.environ.get("MB_KEY_SSM_PARAM", "/spamtrap/abusech-key")
VT_KEY_SSM_PARAM = os.environ.get("VT_KEY_SSM_PARAM", "/spamtrap/virustotal-key")
AWS_KEY_PROFILE  = os.environ.get("AWS_KEY_PROFILE", "honeymike")
AWS_KEY_REGION   = os.environ.get("AWS_KEY_REGION", "us-east-1")
_KEY_CACHE = {}


def _ssm_secret(param):
    """Decrypt an SSM SecureString via aws-cli. None on any failure."""
    args = ["aws"]
    if AWS_KEY_PROFILE:
        args += ["--profile", AWS_KEY_PROFILE]
    args += ["--region", AWS_KEY_REGION, "ssm", "get-parameter", "--name",
             param, "--with-decryption", "--query", "Parameter.Value",
             "--output", "text"]
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=20)
        if p.returncode == 0 and p.stdout.strip() and p.stdout.strip() != "None":
            return p.stdout.strip()
    except Exception:
        pass
    return None


def _mb_key():
    """abuse.ch Auth-Key: env MB_AUTH_KEY, else SSM. Cached; None => MB '-'."""
    if os.environ.get("MB_AUTH_KEY"):
        return os.environ["MB_AUTH_KEY"]
    if "mb" not in _KEY_CACHE:
        _KEY_CACHE["mb"] = _ssm_secret(MB_KEY_SSM_PARAM)
    return _KEY_CACHE["mb"]


def _vt_key():
    """VirusTotal key: env VT_KEY, else SSM. Cached; None => VT skipped."""
    if os.environ.get("VT_KEY"):
        return os.environ["VT_KEY"]
    if "vt" not in _KEY_CACHE:
        _KEY_CACHE["vt"] = _ssm_secret(VT_KEY_SSM_PARAM)
    return _KEY_CACHE["vt"]


# --- Rate-limit circuit breaker (per run) ---
_LIMITED = {"mb": False, "vt": False}


class RateLimited(Exception):
    """Raised when an API returns 429."""
    pass


# ---------------------------------------------------------------------------
# Cache: samples table in the shared ip_cache.db. Per-source freshness columns
# (mb_ts, vt_ts) mirror the ips table's abuse_ts/gn_ts split for the same
# reason: MalwareBazaar and VirusTotal fail independently.
# ---------------------------------------------------------------------------
def init_cache():
    con = sqlite3.connect(CACHE_DB)
    con.execute("""CREATE TABLE IF NOT EXISTS samples (
        md5 TEXT PRIMARY KEY,
        sha256 TEXT,
        family TEXT,
        file_type TEXT,
        tags TEXT,
        first_seen TEXT,
        mb_ts INTEGER,
        av_malicious INTEGER,
        av_total INTEGER,
        vt_ts INTEGER
    )""")
    # Migration path for any older single-ts schema, mirroring enrich_ips.py.
    cols = {row[1] for row in con.execute("PRAGMA table_info(samples)").fetchall()}
    if "ts" in cols and "mb_ts" not in cols:
        con.execute("ALTER TABLE samples ADD COLUMN mb_ts INTEGER")
        con.execute("ALTER TABLE samples ADD COLUMN vt_ts INTEGER")
        con.execute("UPDATE samples SET mb_ts = ts, vt_ts = ts WHERE mb_ts IS NULL")
    con.commit()
    return con


def _row(con, md5):
    return con.execute(
        "SELECT sha256, family, file_type, tags, first_seen, mb_ts, "
        "av_malicious, av_total, vt_ts FROM samples WHERE md5=?", (md5,)).fetchone()


def cache_get_mb(con, md5):
    r = _row(con, md5)
    if r and r[5] is not None and (time.time() - r[5]) < MB_TTL:
        return {"sha256": r[0], "family": r[1], "file_type": r[2],
                "tags": r[3], "first_seen": r[4]}
    return None


def cache_get_vt(con, md5):
    r = _row(con, md5)
    if r and r[8] is not None and (time.time() - r[8]) < VT_TTL:
        return {"av_malicious": r[6], "av_total": r[7]}
    return None


def cache_put_mb(con, md5, f):
    con.execute("""
        INSERT INTO samples (md5, sha256, family, file_type, tags, first_seen, mb_ts)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(md5) DO UPDATE SET
            sha256=excluded.sha256, family=excluded.family,
            file_type=excluded.file_type, tags=excluded.tags,
            first_seen=excluded.first_seen, mb_ts=excluded.mb_ts
    """, (md5, f.get("sha256"), f.get("family"), f.get("file_type"),
          f.get("tags"), f.get("first_seen"), int(time.time())))
    con.commit()


def cache_put_vt(con, md5, f):
    con.execute("""
        INSERT INTO samples (md5, av_malicious, av_total, vt_ts)
        VALUES (?,?,?,?)
        ON CONFLICT(md5) DO UPDATE SET
            av_malicious=excluded.av_malicious,
            av_total=excluded.av_total, vt_ts=excluded.vt_ts
    """, (md5, f.get("av_malicious"), f.get("av_total"), int(time.time())))
    con.commit()


# ---------------------------------------------------------------------------
# Pull distinct captured hashes from the indexer.
# ---------------------------------------------------------------------------
def get_hashes_from_json(path: str) -> list:
    """Distinct MD5s from a captures_YYYYMMDD.json produced by
    dionaea_downloads.py. This is the real source: the indexer has no
    download events. Missing/unreadable file -> empty list."""
    from pathlib import Path as _Path
    p = _Path(path)
    if not p.exists():
        print(f"[warn] captures file not found: {path}", file=sys.stderr)
        return []
    try:
        doc = json.loads(p.read_text())
    except (ValueError, OSError) as e:
        print(f"[warn] captures file unreadable: {e}", file=sys.stderr)
        return []
    return sorted({str(c["md5"]).lower() for c in doc.get("captures", [])
                   if c.get("md5")})


def get_unique_hashes(hours: int) -> list:
    """Distinct MD5 hashes Dionaea captured in the window. Best-effort: any
    indexer error returns an empty list rather than aborting the run."""
    try:
        from opensearchpy import OpenSearch
    except ImportError:
        print("[warn] opensearchpy not installed; cannot pull hashes", file=sys.stderr)
        return []
    pw = os.environ.get("OPENSEARCH_PASS") or os.environ.get("WZ_PW")
    if not pw:
        print("[warn] OPENSEARCH_PASS/WZ_PW not set; cannot pull hashes", file=sys.stderr)
        return []
    client = OpenSearch(OS_URL, http_auth=(OS_USER, pw),
                        verify_certs=False, ssl_show_warn=False)
    body = {
        "size": 1000,
        "_source": [f.split(".", 1)[0] for f in _MD5_FIELDS] + ["data"],
        "query": {"bool": {
            "must": [{"match": {"rule.groups": RULE_GROUP}}],
            "should": [{"exists": {"field": f}} for f in _MD5_FIELDS],
            "minimum_should_match": 1,
            "filter": [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}],
        }},
    }
    try:
        resp = client.search(index=INDEX, body=body)
    except Exception as e:
        print(f"[warn] indexer hash query failed: {e}", file=sys.stderr)
        return []
    hashes = set()
    for h in resp.get("hits", {}).get("hits", []):
        md5 = _first(h.get("_source", {}), _MD5_FIELDS)
        if md5:
            hashes.add(str(md5).lower())
    return sorted(hashes)


# ---------------------------------------------------------------------------
# API calls. Each returns a dict of the fields it owns, or raises RateLimited.
# ---------------------------------------------------------------------------
def query_malwarebazaar(md5: str):
    """MalwareBazaar get_info. Returns family/file_type/tags/first_seen/sha256,
    or None when the hash is unknown to MB. Raises RateLimited on 429."""
    headers = {}
    key = _mb_key()
    if key:
        headers["Auth-Key"] = key
    r = requests.post("https://mb-api.abuse.ch/api/v1/",
                      data={"query": "get_info", "hash": md5},
                      headers=headers, timeout=20)
    if r.status_code == 429:
        raise RateLimited("malwarebazaar")
    if r.status_code in (401, 403):
        raise RuntimeError(f"MalwareBazaar auth rejected (HTTP {r.status_code}); "
                           f"set MB_AUTH_KEY")
    r.raise_for_status()
    body = r.json()
    status = body.get("query_status")
    if status != "ok":
        # hash_not_found / illegal_hash / no_results: known-good "no data".
        return None
    data = (body.get("data") or [{}])[0]
    tags = data.get("tags") or []
    return {
        "family": data.get("signature") or "",
        "file_type": data.get("file_type") or "",
        "tags": ",".join(tags) if isinstance(tags, list) else str(tags),
        "first_seen": (data.get("first_seen") or "")[:10],
        "sha256": data.get("sha256_hash") or "",
    }


def query_virustotal(md5: str):
    """VirusTotal file report. Returns av_malicious/av_total, or None when the
    hash is unknown to VT. Raises RateLimited on 429."""
    key = _vt_key()
    if not key:
        return None
    r = requests.get(f"https://www.virustotal.com/api/v3/files/{md5}",
                     headers={"x-apikey": key}, timeout=20)
    if r.status_code == 429:
        raise RateLimited("virustotal")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    stats = (r.json().get("data", {}).get("attributes", {})
             .get("last_analysis_stats", {}))
    if not stats:
        return None
    total = sum(v for v in stats.values() if isinstance(v, int))
    return {"av_malicious": stats.get("malicious", 0), "av_total": total}


def enrich(con, md5):
    """Resolve one hash. MalwareBazaar and VirusTotal handled and cached fully
    independently. Returns (record, mb_limited_now, vt_limited_now)."""
    rec = {"md5": md5, "sha256": None, "family": None, "file_type": None,
           "tags": None, "first_seen": None,
           "av_malicious": None, "av_total": None}
    mb_lim = vt_lim = False

    cached_mb = cache_get_mb(con, md5)
    if cached_mb:
        rec.update(cached_mb)
    elif _mb_key() is None and os.environ.get("MB_ALLOW_NOKEY") is None:
        pass  # no key: skip MB, degrade to '-'
    elif _LIMITED["mb"]:
        pass
    else:
        try:
            fields = query_malwarebazaar(md5)
            if fields:
                rec.update(fields)
                cache_put_mb(con, md5, fields)
        except RateLimited:
            _LIMITED["mb"] = True
            mb_lim = True
        except Exception as e:
            print(f"    [warn] malwarebazaar error for {md5}: {e}")

    cached_vt = cache_get_vt(con, md5)
    if cached_vt:
        rec.update(cached_vt)
    elif not _vt_key():
        pass  # no key: skip VT
    elif _LIMITED["vt"]:
        pass
    else:
        try:
            fields = query_virustotal(md5)
            if fields:
                rec.update(fields)
                cache_put_vt(con, md5, fields)
            time.sleep(VT_THROTTLE)  # free tier 4/min
        except RateLimited:
            _LIMITED["vt"] = True
            vt_lim = True
        except Exception as e:
            print(f"    [warn] virustotal error for {md5}: {e}")

    return rec, mb_lim, vt_lim


FIELDS = ["md5", "sha256", "family", "file_type", "tags", "first_seen",
          "av_malicious", "av_total"]


def main():
    ap = argparse.ArgumentParser(description="Enrich captured Dionaea sample hashes.")
    ap.add_argument("--hours", type=int, default=24,
                    help="Lookback window for pulling captured hashes (default 24)")
    ap.add_argument("--hash", help="Enrich a single MD5 and exit (no indexer query)")
    ap.add_argument("--captures-json", default=None,
                    help="Read hashes from captures_YYYYMMDD.json "
                         "(dionaea_downloads.py). Preferred: the indexer has no "
                         "download events.")
    ap.add_argument("--embed", action="store_true",
                    help="With --captures-json: write enrichment back into that "
                         "JSON as a `samples` map so the report can read it "
                         "without the shared cache DB.")
    args = ap.parse_args()

    con = init_cache()

    if args.hash:
        hashes = [args.hash.lower()]
    elif args.captures_json:
        hashes = get_hashes_from_json(args.captures_json)
    else:
        hashes = get_unique_hashes(args.hours)
    print(f"[*] {len(hashes)} distinct hash(es) to enrich")
    if not _mb_key():
        print("[*] no abuse.ch key (env or SSM): MalwareBazaar skipped "
              "(family/type/tags '-')")
    if not _vt_key():
        print("[*] no VirusTotal key (env or SSM): VirusTotal skipped (AV '-')")

    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for i, md5 in enumerate(hashes, 1):
            rec, m_lim, v_lim = enrich(con, md5)
            w.writerow({k: rec.get(k) for k in FIELDS})
            if m_lim:
                print(f"[{i}/{len(hashes)}] RATE LIMIT: malwarebazaar. Cached "
                      f"results still used; uncached hashes retry next run.")
            if v_lim:
                print(f"[{i}/{len(hashes)}] RATE LIMIT: virustotal. Cached "
                      f"results still used; uncached hashes retry next run.")
            print(f"[{i}/{len(hashes)}] {md5} "
                  f"family={rec.get('family') or '-'} "
                  f"type={rec.get('file_type') or '-'} "
                  f"av={rec.get('av_malicious')}/{rec.get('av_total')}")

    print(f"[+] Wrote {OUT_CSV}")

    if args.embed and args.captures_json:
        embed_into_captures(con, args.captures_json, hashes)


def embed_into_captures(con, path, hashes):
    """Write the enrichment for `hashes` into the captures JSON as a top-level
    `samples` map {md5: {family, file_type, tags, av_malicious, av_total,
    first_seen}}. Lets the report read sample intel straight from the file, so
    the pull+enrich can run on a different host than the report with no shared
    cache DB."""
    from pathlib import Path as _Path
    p = _Path(path)
    try:
        doc = json.loads(p.read_text())
    except (ValueError, OSError) as e:
        print(f"[warn] cannot embed into {path}: {e}", file=sys.stderr)
        return
    samples = {}
    for md5 in hashes:
        r = _row(con, md5)
        if not r:
            continue
        samples[md5] = {"family": r[1] or "", "file_type": r[2] or "",
                        "tags": r[3] or "", "first_seen": r[4] or "",
                        "av_malicious": r[6], "av_total": r[7]}
    doc["samples"] = samples
    p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"[+] embedded {len(samples)} sample record(s) into {path}")


if __name__ == "__main__":
    main()
