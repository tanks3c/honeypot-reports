#!/usr/bin/env python3
"""
wazuh_daily_report.py
=====================
Indexer-fed version of the Dionaea daily report.

Runs on the wazuh-analysis box. Queries the Wazuh indexer (OpenSearch) on
localhost:9200 for the last N hours of accepted Dionaea connections, then
reuses the original report's aggregation and HTML render layer unchanged.

Why this exists:
  The original dionaea_daily_report.py reads /opt/dionaea/log/dionaea.json
  directly on the honeypot. The honeypot has no outbound internet, so it
  cannot publish. This version pulls the same data from the indexer instead,
  so the whole pipeline (query, render, publish) lives on the analysis box,
  which already holds the indexer and has outbound 443.

Data source swap only. classify_events() and build_html() are identical to
the original. The honeypot is never touched.

Auth:
  Reads the indexer password from the WZ_PW environment variable. Never
  hardcode it. Example:
      read -rs WZ_PW; export WZ_PW
      python3 wazuh_daily_report.py --hours 24 --out daily-report.html

Usage:
      python3 wazuh_daily_report.py
      python3 wazuh_daily_report.py --hours 48
      python3 wazuh_daily_report.py --url https://localhost:9200 --index 'wazuh-alerts-*'
"""

import os
import ssl
import sys
import json
import base64
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# Config (all env-overridable; password is required at runtime)
# ---------------------------------------------------------------------------
INDEXER_URL   = os.environ.get("WZ_URL",   "https://localhost:9200")
INDEX_PATTERN = os.environ.get("WZ_INDEX", "wazuh-alerts-*")
INDEXER_USER  = os.environ.get("WZ_USER",  "admin")
RULE_GROUP    = os.environ.get("WZ_GROUP", "dionaea")
DEFAULT_OUT   = "wazuh_daily_report.html"
DEFAULT_HOURS = 24
SCROLL_TTL    = "2m"
PAGE_SIZE     = 1000


def _password() -> str:
    pw = os.environ.get("WZ_PW")
    if not pw:
        print("[ERROR] WZ_PW not set. Load it first, e.g.:", file=sys.stderr)
        print("        read -rs WZ_PW; export WZ_PW", file=sys.stderr)
        sys.exit(2)
    return pw


# ---------------------------------------------------------------------------
# Indexer client (stdlib only: urllib + ssl, no pip dependencies)
# ---------------------------------------------------------------------------
def _ssl_ctx() -> ssl.SSLContext:
    # The indexer ships a self-signed cert. Skip verification on localhost.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _indexer_request(path: str, body=None, method: str = "POST") -> dict:
    url = INDEXER_URL.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    token = base64.b64encode(f"{INDEXER_USER}:{_password()}".encode()).decode()
    req.add_header("Authorization", "Basic " + token)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        print(f"[ERROR] Indexer HTTP {exc.code}: {detail}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"[ERROR] Cannot reach indexer at {url}: {exc.reason}", file=sys.stderr)
        print("        Check: systemctl is-active wazuh-indexer", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Timestamp parsing + hit adapter
# ---------------------------------------------------------------------------
def _parse_ts(raw):
    """Parse Dionaea (naive) or Wazuh (tz-aware) ISO timestamps to UTC."""
    if not raw or not isinstance(raw, str):
        return None
    s = raw.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        ts = datetime.fromisoformat(s)
    except ValueError:
        # Handle +0000 style offsets that lack the colon.
        if len(s) >= 5 and s[-5] in "+-" and s[-3] != ":":
            try:
                ts = datetime.fromisoformat(s[:-2] + ":" + s[-2:])
            except ValueError:
                return None
        else:
            return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def adapt_hit(hit: dict):
    """
    Remap one indexer hit into the flat event shape classify_events() expects.
    Wazuh nests the original Dionaea fields under _source.data.
    Returns None for anything that is not a usable accept event.
    """
    src  = hit.get("_source", {})
    d    = src.get("data", {})
    conn = d.get("connection", {})
    if conn.get("type") != "accept":
        return None
    ts = _parse_ts(d.get("timestamp") or src.get("timestamp"))
    if ts is None:
        return None
    try:
        port = int(d.get("dst_port"))
    except (TypeError, ValueError):
        port = 0
    return {
        "_ts":        ts,
        "src_ip":     d.get("src_ip", "unknown"),
        "dst_port":   port,
        "connection": {"type": conn.get("type"),
                       "protocol": conn.get("protocol", "unknown")},
    }


def fetch_events(hours: int) -> list:
    """
    Pull every accepted Dionaea connection in the window via the scroll API.
    Scroll handles arbitrary volume, so the report never silently truncates.
    """
    query = {
        "size": PAGE_SIZE,
        "sort": ["_doc"],
        "_source": ["timestamp", "data.timestamp", "data.src_ip",
                    "data.dst_port", "data.connection.protocol",
                    "data.connection.type"],
        "query": {"bool": {
            "must": [
                {"match": {"rule.groups": RULE_GROUP}},
                {"match": {"data.connection.type": "accept"}},
            ],
            "filter": [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}],
        }},
    }

    page = _indexer_request(f"/{INDEX_PATTERN}/_search?scroll={SCROLL_TTL}", query)
    scroll_id = page.get("_scroll_id")
    hits = page.get("hits", {}).get("hits", [])
    events = []
    try:
        while hits:
            for h in hits:
                ev = adapt_hit(h)
                if ev:
                    events.append(ev)
            page = _indexer_request(
                "/_search/scroll",
                {"scroll": SCROLL_TTL, "scroll_id": scroll_id},
            )
            scroll_id = page.get("_scroll_id", scroll_id)
            hits = page.get("hits", {}).get("hits", [])
    finally:
        if scroll_id:
            try:
                _indexer_request("/_search/scroll",
                                 {"scroll_id": [scroll_id]}, method="DELETE")
            except SystemExit:
                pass
    return events


# ---------------------------------------------------------------------------
# Dionaea capture (malware download) ingestion
#
# Accept events use connection.type=accept. Download events do NOT: Dionaea
# emits them via its incident system (dionaea.download.complete), so they are
# indexed under a different shape. The exact Wazuh field paths depend on the
# decoder mapping and have NOT been confirmed against the live indexer here
# (that probe is a reviewed action). So rather than hardcode one guessed path,
# the adapter matches against a list of candidate paths and uses whichever is
# actually present. Once field discovery confirms the real names, prune these
# lists to the single true path per field.
# ---------------------------------------------------------------------------
_MD5_FIELDS = ["data.md5_hash", "data.md5hash", "data.md5",
               "data.download.md5", "data.dionaea.md5_hash",
               "data.virustotal.md5"]
_URL_FIELDS = ["data.url", "data.download.url", "data.dionaea.url",
               "data.uri"]
_SHA256_FIELDS = ["data.sha256_hash", "data.sha256", "data.download.sha256"]
_SIZE_FIELDS = ["data.size", "data.download.size", "data.filesize"]


def _dig(src, dotted):
    """Walk a dotted path through nested dicts. Returns None if any hop is
    missing or a non-dict is encountered."""
    cur = src
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _first(src, fields):
    """First non-empty value among the candidate dotted paths."""
    for f in fields:
        v = _dig(src, f)
        if v not in (None, "", []):
            return v
    return None


def adapt_download(hit: dict):
    """
    Remap one indexer hit into the flat capture shape the report expects.
    A hit is a usable capture only if it carries an MD5 hash. Returns None
    otherwise. Returns:
        {_ts, src_ip, dst_port, transport, protocol, url, md5, size, sha256}
    """
    src = hit.get("_source", {})
    md5 = _first(src, _MD5_FIELDS)
    if not md5:
        return None
    ts = _parse_ts(_dig(src, "data.timestamp") or src.get("timestamp"))
    if ts is None:
        return None
    d = src.get("data", {}) if isinstance(src.get("data"), dict) else {}
    conn = d.get("connection", {}) if isinstance(d.get("connection"), dict) else {}
    try:
        port = int(d.get("dst_port") or conn.get("local_port") or 0)
    except (TypeError, ValueError):
        port = 0
    try:
        size = int(_first(src, _SIZE_FIELDS) or 0)
    except (TypeError, ValueError):
        size = 0
    sha256 = _first(src, _SHA256_FIELDS)
    return {
        "_ts":       ts,
        "src_ip":    d.get("src_ip", "unknown"),
        "dst_port":  port,
        "transport": conn.get("transport") or conn.get("type") or "",
        "protocol":  conn.get("protocol", "unknown"),
        "url":       _first(src, _URL_FIELDS) or "",
        "md5":       str(md5).lower(),
        "size":      size,
        "sha256":    str(sha256).lower() if sha256 else None,
    }


def fetch_downloads(hours: int) -> list:
    """
    Pull every Dionaea download (captured sample) in the window via scroll.
    Mirrors fetch_events but matches on the presence of a hash field rather
    than connection.type=accept, because captures are a different event shape.
    Best-effort: a mapping mismatch yields zero captures, never an exception
    that would kill the whole report.
    """
    query = {
        "size": PAGE_SIZE,
        "sort": ["_doc"],
        "query": {"bool": {
            "must": [{"match": {"rule.groups": RULE_GROUP}}],
            "should": [{"exists": {"field": f}} for f in _MD5_FIELDS],
            "minimum_should_match": 1,
            "filter": [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}],
        }},
    }
    try:
        page = _indexer_request(
            f"/{INDEX_PATTERN}/_search?scroll={SCROLL_TTL}", query)
    except SystemExit:
        print("[WARN] download query failed; report renders with no captures",
              file=sys.stderr)
        return []
    scroll_id = page.get("_scroll_id")
    hits = page.get("hits", {}).get("hits", [])
    captures = []
    try:
        while hits:
            for h in hits:
                cap = adapt_download(h)
                if cap:
                    captures.append(cap)
            page = _indexer_request(
                "/_search/scroll",
                {"scroll": SCROLL_TTL, "scroll_id": scroll_id})
            scroll_id = page.get("_scroll_id", scroll_id)
            hits = page.get("hits", {}).get("hits", [])
    finally:
        if scroll_id:
            try:
                _indexer_request("/_search/scroll",
                                 {"scroll_id": [scroll_id]}, method="DELETE")
            except SystemExit:
                pass
    return captures


def _defang(url: str) -> str:
    """Neutralize a URL so it can't be accidentally clicked/fetched from the
    rendered HTML report. http->hxxp, . -> [.]"""
    if not url:
        return ""
    out = url.replace("https://", "hxxps://").replace("http://", "hxxp://")
    return out.replace(".", "[.]")


# ---------------------------------------------------------------------------
# Sample (hash) enrichment reader. Reads the samples table populated by
# enrich_samples.py; makes no API calls itself. Missing DB / table / rows are
# non-fatal: family/type/AV columns render as '-'.
# Schema: md5, sha256, family, file_type, tags, av_malicious, av_total,
#         first_seen, mb_ts, vt_ts
# ---------------------------------------------------------------------------
def load_sample_enrichment(db_path: str, hashes) -> dict:
    """Look up cached sample intel for the given MD5 hashes.
    Returns {md5: {family, file_type, tags, av_malicious, av_total, first_seen}}.
    """
    import sqlite3
    from pathlib import Path as _Path

    out = {}
    md5s = [h for h in set(hashes) if h]
    if not md5s:
        return out
    if not _Path(db_path).exists():
        print(f"[WARN] sample enrichment cache not found: {db_path} "
              f"(malware panel shows '-' for family/type/AV)", file=sys.stderr)
        return out
    try:
        con = sqlite3.connect(db_path)
        placeholders = ",".join("?" for _ in md5s)
        try:
            rows = con.execute(
                f"SELECT md5, family, file_type, tags, av_malicious, "
                f"av_total, first_seen FROM samples WHERE md5 IN "
                f"({placeholders})", md5s).fetchall()
        except sqlite3.OperationalError:
            con.close()
            return out  # samples table not created yet
        for md5, fam, ftype, tags, av_m, av_t, first_seen in rows:
            out[md5] = {
                "family": fam or "",
                "file_type": ftype or "",
                "tags": tags or "",
                "av_malicious": av_m,
                "av_total": av_t,
                "first_seen": first_seen or "",
            }
        con.close()
    except sqlite3.Error as exc:
        print(f"[WARN] sample enrichment read failed: {exc}", file=sys.stderr)
    return out


# ---------------------------------------------------------------------------
# IP reputation enrichment (reads the existing cache only, makes no API
# calls itself). Cache is built/refreshed separately by enrich_ips.py.
# Schema: ip, abuse_score, abuse_reports, country, isp,
#         gn_classification, gn_name, ts
# ---------------------------------------------------------------------------
def load_enrichment(db_path: str, ips) -> dict:
    """
    Look up cached IP reputation for the given IPs. Missing DB or missing
    rows are not fatal: the report renders with '-' for those fields.
    Returns {ip: {abuse_score, country, gn_classification, gn_name}}.
    """
    import sqlite3
    from pathlib import Path as _Path

    out = {}
    if not _Path(db_path).exists():
        print(f"[WARN] enrichment cache not found: {db_path} "
              f"(report will show '-' for reputation columns)", file=sys.stderr)
        return out

    try:
        con = sqlite3.connect(db_path)
        ip_list = list(set(ips))
        if not ip_list:
            return out
        placeholders = ",".join("?" for _ in ip_list)
        rows = con.execute(
            f"SELECT ip, abuse_score, country, gn_classification, gn_name "
            f"FROM ips WHERE ip IN ({placeholders})", ip_list).fetchall()
        for ip, score, country, gn_class, gn_name in rows:
            out[ip] = {
                "abuse_score": score,
                "country": country or "",
                "gn_classification": gn_class or "unknown",
                "gn_name": gn_name or "",
            }
        # feed-layer fields (known-bad + ASN) from the same cache DB, written by
        # enrich_ips.py's local bulk-feed layer. Absent tables are non-fatal.
        import ipaddress as _ipa
        for ip in ip_list:
            try:
                srcs = [r[0] for r in con.execute(
                    "SELECT source FROM feed_bad_ips WHERE ip=?", (ip,)).fetchall()]
                asn = org = None
                try:
                    n = int(_ipa.ip_address(ip))
                    nb = con.execute("SELECT source FROM feed_netblocks WHERE "
                                     "start_int<=? AND end_int>=? LIMIT 1",
                                     (n, n)).fetchone()
                    if nb:
                        srcs.append(nb[0])
                    a = con.execute("SELECT asn, org FROM asn_ranges WHERE "
                                    "start_int<=? AND end_int>=? ORDER BY "
                                    "start_int DESC LIMIT 1", (n, n)).fetchone()
                    if a:
                        asn, org = a
                except ValueError:
                    pass
                if not (srcs or asn):
                    continue
                entry = out.setdefault(ip, {"abuse_score": None, "country": "",
                                            "gn_classification": "unknown",
                                            "gn_name": ""})
                entry["asn"], entry["org"] = asn, org
                if srcs:
                    entry["known_bad"] = 1
                    entry["bad_sources"] = ",".join(sorted(set(srcs)))
            except sqlite3.Error:
                break  # feed tables not present yet; skip feed enrichment
        con.close()
    except sqlite3.Error as exc:
        print(f"[WARN] enrichment cache read failed: {exc} "
              f"(report will show '-' for reputation columns)", file=sys.stderr)
    return out


def overlay_verdicts(enrichment, ips) -> None:
    """
    Overlay central verdicts (enrichment/verdicts.json on the S3 bus,
    written by the homebase intel-enrich engine) onto the local cache
    data. Fully best-effort: no bucket config, no boto3/aws-cli, or no
    object yet means the report simply renders from ip_cache.db alone.
    """
    from pathlib import Path as _Path
    bucket = os.environ.get("ENRICH_BUCKET")
    if not bucket:  # same untracked .env the enricher uses
        env = _Path(__file__).parent / ".env"
        if env.exists():
            for line in env.read_text().splitlines():
                if line.startswith("ENRICH_BUCKET="):
                    bucket = line.split("=", 1)[1].strip()
    if not bucket:
        return
    try:
        try:
            import boto3
            body = boto3.client("s3").get_object(
                Bucket=bucket, Key="enrichment/verdicts.json")["Body"].read()
        except ImportError:
            import subprocess
            body = subprocess.run(
                ["aws", "s3", "cp",
                 f"s3://{bucket}/enrichment/verdicts.json", "-"],
                capture_output=True, check=True).stdout
        verdicts = json.loads(body).get("ips", {})
    except Exception as exc:
        print(f"[WARN] central verdicts unavailable: {exc}", file=sys.stderr)
        return
    n = 0
    for ip in ips:
        v = verdicts.get(ip)
        if not v:
            continue
        e = enrichment.setdefault(ip, {"abuse_score": None, "country": "",
                                       "gn_classification": "unknown",
                                       "gn_name": ""})
        f = v.get("facts", {})
        e["verdict"] = v.get("verdict")
        e["confidence"] = v.get("confidence")
        e["rationale"] = v.get("rationale") or {}
        e["klass"] = f.get("class")
        e["open_ports"] = f.get("open_ports") or []
        e["vulns"] = f.get("vulns") or []
        if f.get("asn") and not e.get("asn"):
            e["asn"], e["org"] = f["asn"], f.get("org")
        if f.get("country") and not e.get("country"):
            e["country"] = f["country"]
        n += 1
    print(f"[+] central verdicts overlaid on {n} IPs")



# ===========================================================================
# Below: protocol map, drill-down JS, classify_events, and build_html.
# Copied unchanged from the original dionaea_daily_report.py render layer.
# ===========================================================================

# Map Dionaea protocol strings to human-readable labels and MITRE techniques
PROTOCOL_MAP = {
    "smbd":    ("SMB",    "T1210", "#E5484D"),
    "mysqld":  ("MySQL",  "T1190", "#7DD3C0"),
    "httpd":   ("HTTP",   "T1190", "#46B6C4"),
    "ftpd":    ("FTP",    "T1190", "#F5A623"),
    "mssqld":  ("MSSQL",  "T1190", "#A78BFA"),
    "sipd":    ("SIP",    "T1190", "#93A7B8"),
}

# Ports mapped to expected protocol (for sanity-check)
PORT_MAP = {
    21:   "FTP",
    80:   "HTTP",
    443:  "HTTPS",
    445:  "SMB",
    1433: "MSSQL",
    3306: "MySQL",
}

# Drill-down behavior script. Plain string (NOT an f-string) so JS braces are
# literal. Data is injected via .replace("__DRILL_DATA__", ...). Uses string
# concatenation instead of template literals on purpose, to stay brace-safe.
_DRILL_SCRIPT_TEMPLATE = """
const DRILL = __DRILL_DATA__;
const DRILL_META = {
  unique:   { title: 'Unique attacker IPs' },
  highfreq: { title: 'High-frequency IPs (5+ hits)' },
  scanners: { title: 'Probable scanners (50+ hits)' }
};
let drillCat = null;

function openDrill(cat) {
  if (!DRILL[cat]) return;
  drillCat = cat;
  document.getElementById('drill-title').textContent = DRILL_META[cat].title;
  document.getElementById('drill-filter').value = '';
  renderDrill();
  document.getElementById('drill-overlay').style.display = 'flex';
  document.body.style.overflow = 'hidden';
  setTimeout(function () { document.getElementById('drill-filter').focus(); }, 30);
}

function closeDrill() {
  document.getElementById('drill-overlay').style.display = 'none';
  document.body.style.overflow = '';
}

function renderDrill() {
  const rows = DRILL[drillCat] || [];
  const q = document.getElementById('drill-filter').value.trim().toLowerCase();
  const f = q
    ? rows.filter(function (r) {
        return (r.ip + ' ' + r.proto + ' ' + r.risk).toLowerCase().indexOf(q) !== -1;
      })
    : rows;
  const badge = { high: 'badge-high', med: 'badge-med', low: 'badge-low' };
  let out = '';
  for (let i = 0; i < f.length; i++) {
    const r = f[i];
    out += '<tr>'
      + '<td style="font-family:monospace;font-size:12px">' + r.ip + '</td>'
      + '<td style="text-align:right;font-weight:600;font-size:12px">' + r.hits + '</td>'
      + '<td style="font-size:12px;color:#93a7b8">' + r.proto + '</td>'
      + '<td style="font-size:11px;color:#93a7b8;font-family:monospace">' + r.first + '</td>'
      + '<td style="font-size:11px;color:#93a7b8;font-family:monospace">' + r.last + '</td>'
      + '<td><span class="' + badge[r.risk] + '">' + r.risk + '</span></td>'
      + '<td style="font-size:11px;color:#93a7b8;text-align:center">' + r.country + '</td>'
      + '<td style="font-size:11px;font-weight:600;text-align:right">' + r.abuse + '</td>'
      + '<td style="font-size:11px;color:#93a7b8">' + r.gn + '</td>'
      + '</tr>';
  }
  document.getElementById('drill-rows').innerHTML = out;
  document.getElementById('drill-sub').textContent = f.length + ' of ' + rows.length + ' shown';
  const emptyEl = document.getElementById('drill-empty');
  if (rows.length === 0) {
    emptyEl.textContent = 'No IPs in this category for this window.';
    emptyEl.style.display = 'block';
  } else if (f.length === 0) {
    emptyEl.textContent = 'No matches for that filter.';
    emptyEl.style.display = 'block';
  } else {
    emptyEl.style.display = 'none';
  }
}

document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') closeDrill();
});
"""


def classify_events(events: list[dict], captures: list[dict] | None = None) -> dict:
    """
    Build all aggregations needed for the report panels.

    `captures` (optional) is the list of Dionaea download events from
    fetch_downloads(). It is aggregated alongside the accept-event stats
    without touching any existing return key, so this stays backward
    compatible with callers that pass events only.
    """
    # Filter to accepted inbound connections only
    accepted = [e for e in events if e.get("connection", {}).get("type") == "accept"]

    total          = len(accepted)
    src_ip_counts  = Counter(e.get("src_ip", "unknown") for e in accepted)
    protocol_counts = Counter(
        e.get("connection", {}).get("protocol", "unknown") for e in accepted
    )
    port_counts    = Counter(e.get("dst_port", 0) for e in accepted)

    # Hourly bucketing
    hourly = Counter()
    for e in accepted:
        ts: datetime = e["_ts"]
        bucket = ts.strftime("%Y-%m-%d %H:00")
        hourly[bucket] += 1

    # High-frequency IPs (5+ connections = probable scanner/bot)
    high_freq_ips = {ip: c for ip, c in src_ip_counts.items() if c >= 5}

    # Per-IP protocol breakdown
    ip_protocols: dict[str, Counter] = defaultdict(Counter)
    for e in accepted:
        ip = e.get("src_ip", "unknown")
        proto = e.get("connection", {}).get("protocol", "unknown")
        ip_protocols[ip][proto] += 1

    # Per-IP first/last seen (dwell window within the lookback)
    ip_first_seen: dict[str, datetime] = {}
    ip_last_seen:  dict[str, datetime] = {}
    for e in accepted:
        ip = e.get("src_ip", "unknown")
        ts = e["_ts"]
        if ip not in ip_first_seen or ts < ip_first_seen[ip]:
            ip_first_seen[ip] = ts
        if ip not in ip_last_seen or ts > ip_last_seen[ip]:
            ip_last_seen[ip] = ts

    # Capture (malware download) aggregation. Non-invasive: new keys only.
    caps = captures or []
    captures_by_ip: dict[str, list] = defaultdict(list)
    for c in caps:
        captures_by_ip[c.get("src_ip", "unknown")].append(c)

    return {
        "total":           total,
        "unique_ips":      len(src_ip_counts),
        "protocol_counts": protocol_counts,
        "port_counts":     port_counts,
        "src_ip_counts":   src_ip_counts,
        "hourly":          hourly,
        "high_freq_ips":   high_freq_ips,
        "ip_protocols":    ip_protocols,
        "ip_first_seen":   ip_first_seen,
        "ip_last_seen":    ip_last_seen,
        "raw_accepted":    accepted,
        "captures":        caps,
        "captures_by_ip":  captures_by_ip,
        "capture_count":   len(caps),
        "unique_hashes":   sorted({c["md5"] for c in caps if c.get("md5")}),
    }


def build_html(data: dict, hours: int, log_path: str, enrichment: dict = None,
               sample_enrichment: dict = None) -> str:
    now    = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)
    enrichment = enrichment or {}
    sample_enrichment = sample_enrichment or {}

    total       = data["total"]
    unique_ips  = data["unique_ips"]
    high_freq   = len(data["high_freq_ips"])
    proto_counts = data["protocol_counts"]
    ip_counts   = data["src_ip_counts"]
    hourly      = data["hourly"]
    captures       = data.get("captures", [])
    captures_by_ip = data.get("captures_by_ip", {})
    capture_count  = data.get("capture_count", 0)

    def _esc(s):
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    # Top 10 IPs
    top_ips = ip_counts.most_common(10)

    # Protocol bar rows
    max_proto_count = max(proto_counts.values(), default=1)
    proto_rows = ""
    for proto, count in proto_counts.most_common(8):
        label, mitre, color = PROTOCOL_MAP.get(proto, (proto.upper(), "T1190", "#93A7B8"))
        pct = round(count / max_proto_count * 100)
        proto_rows += f"""
        <tr>
          <td style="width:70px;font-size:12px;color:#93a7b8">{label}</td>
          <td style="padding:4px 8px">
            <div style="background:#223344;border-radius:3px;height:10px;overflow:hidden">
              <div style="background:{color};width:{pct}%;height:100%;border-radius:3px"></div>
            </div>
          </td>
          <td style="width:40px;font-size:12px;text-align:right">{count}</td>
          <td style="width:70px;font-size:11px;color:#5e7385;padding-left:8px">{mitre}</td>
        </tr>"""

    # Top IP table rows
    ip_rows = ""
    for ip, count in top_ips:
        top_proto = data["ip_protocols"][ip].most_common(1)
        proto_str = PROTOCOL_MAP.get(top_proto[0][0], (top_proto[0][0].upper(), "", "#93A7B8"))[0] if top_proto else "?"
        flag = "🔴" if count >= 50 else ("🟡" if count >= 10 else "🟢")
        rep = enrichment.get(ip, {})
        abuse = rep.get("abuse_score")
        abuse_str = f"{abuse}%" if abuse is not None else "-"
        abuse_color = "#e5484d" if (abuse or 0) >= 75 else ("#f5a623" if (abuse or 0) >= 25 else "#93a7b8")
        country = rep.get("country") or "-"
        gn = rep.get("gn_classification", "-")
        gn_color = {"malicious": "#e5484d", "benign": "#7dd3c0"}.get(gn, "#93a7b8")
        kb = rep.get("known_bad")
        kb_cell = (f'<span style="color:#ff6b6b;font-weight:600" title="{rep.get("bad_sources","")}">BAD</span>'
                   if kb else '<span style="color:#5e7385">-</span>')
        asn = rep.get("asn")
        asn_cell = f"AS{asn}" if asn else "-"
        vd = rep.get("verdict")
        vd_color = {"malicious": "#e5484d", "suspicious": "#f5a623",
                    "benign-scanner": "#46b6c4"}.get(vd, "#5e7385")
        ports = ",".join(str(p) for p in rep.get("open_ports", [])[:6])
        rat = rep.get("rationale", {})
        tip_lines = [rat.get("rule", "")]
        for ev in rat.get("evidence", []):
            tip_lines.append(f"- {ev.get('detail', '')}")
        if rat.get("confidence_basis"):
            tip_lines.append(f"confidence = {rat['confidence_basis']}")
        if ports:
            tip_lines.append(f"open ports: {ports}")
        # NOTE: build_html uses a local var named `html`, which shadows the
        # html module here, so escape manually rather than html.escape().
        vd_tip = ("\n".join(l for l in tip_lines if l)
                  .replace("&", "&amp;").replace("<", "&lt;")
                  .replace(">", "&gt;").replace('"', "&quot;"))
        vd_cell = (f'<span style="color:{vd_color};font-weight:600;cursor:help" '
                   f'title="{vd_tip}">{vd}</span>'
                   if vd else '<span style="color:#5e7385">-</span>')
        # Malware flag: this IP dropped a captured sample in-window.
        ip_caps = captures_by_ip.get(ip, [])
        mal_flag = (f' <span title="{len(ip_caps)} sample(s) captured" '
                    f'style="color:#e5484d;font-weight:700">&#9763;</span>'
                    if ip_caps else "")
        ip_rows += f"""
        <tr>
          <td style="font-family:monospace;font-size:12px">{ip}{mal_flag}</td>
          <td style="text-align:center;font-size:14px">{flag}</td>
          <td style="text-align:right;font-size:12px;font-weight:600">{count}</td>
          <td style="font-size:12px;color:#93a7b8">{proto_str}</td>
          <td style="font-size:11px">{vd_cell}</td>
          <td style="font-size:11px;text-align:center">{kb_cell}</td>
          <td style="font-size:12px;color:#93a7b8;text-align:center">{country}</td>
          <td style="font-size:11px;color:#5e7385;font-family:monospace">{asn_cell}</td>
          <td style="font-size:12px;font-weight:600;text-align:right;color:{abuse_color}">{abuse_str}</td>
          <td style="font-size:11px;color:{gn_color}">{gn}</td>
        </tr>"""

    # Hourly chart (last 24 buckets)
    sorted_hours = sorted(hourly.items())[-24:]
    max_h = max((c for _, c in sorted_hours), default=1)
    bar_data = json.dumps([{"h": h, "c": c} for h, c in sorted_hours])

    # Recent event log (last 20)
    recent = sorted(data["raw_accepted"], key=lambda e: e["_ts"], reverse=True)[:20]
    event_rows = ""
    for e in recent:
        ts_str = e["_ts"].strftime("%H:%M:%S")
        proto  = e.get("connection", {}).get("protocol", "?")
        label  = PROTOCOL_MAP.get(proto, (proto.upper(), "", "#93A7B8"))[0]
        color  = PROTOCOL_MAP.get(proto, ("", "", "#93A7B8"))[2]
        src    = e.get("src_ip", "?")
        port   = e.get("dst_port", "?")
        event_rows += f"""
        <tr>
          <td style="font-size:11px;color:#93a7b8;font-family:monospace">{ts_str}</td>
          <td style="font-size:11px;font-family:monospace">{src}</td>
          <td><span style="background:{color}22;color:{color};padding:1px 6px;border-radius:3px;font-size:11px;font-weight:600">{label}</span></td>
          <td style="font-size:11px;color:#93a7b8">{port}</td>
        </tr>"""

    # ---- Drill-down datasets (power the clickable metric cards) ----
    scanner_count = sum(1 for c in ip_counts.values() if c >= 50)

    def _ip_record(ip, count):
        tp = data["ip_protocols"][ip].most_common(1)
        proto_str = (PROTOCOL_MAP.get(tp[0][0], (tp[0][0].upper(), "", "#93A7B8"))[0]) if tp else "?"
        first = data["ip_first_seen"].get(ip)
        last  = data["ip_last_seen"].get(ip)
        risk  = "high" if count >= 50 else ("med" if count >= 10 else "low")
        rep = enrichment.get(ip, {})
        return {
            "ip":    ip,
            "hits":  count,
            "proto": proto_str,
            "first": first.strftime("%m-%d %H:%M") if first else "",
            "last":  last.strftime("%m-%d %H:%M") if last else "",
            "risk":  risk,
            "country": rep.get("country") or "-",
            "abuse":   rep.get("abuse_score") if rep.get("abuse_score") is not None else "-",
            "gn":      rep.get("gn_classification", "-"),
            "known_bad": rep.get("known_bad", 0),
            "asn":     f"AS{rep.get('asn')}" if rep.get("asn") else "-",
        }

    unique_records   = [_ip_record(ip, c) for ip, c in ip_counts.most_common()]
    highfreq_records = [_ip_record(ip, c) for ip, c in sorted(data["high_freq_ips"].items(), key=lambda x: -x[1])]
    scanner_records  = [_ip_record(ip, c) for ip, c in ip_counts.most_common() if c >= 50]

    drill_data = json.dumps({
        "unique":   unique_records,
        "highfreq": highfreq_records,
        "scanners": scanner_records,
    })
    DRILL_SCRIPT = _DRILL_SCRIPT_TEMPLATE.replace("__DRILL_DATA__", drill_data)

    # ---- Malware captured panel ----
    capture_rows = ""
    for c in sorted(captures, key=lambda x: x["_ts"], reverse=True):
        md5 = c.get("md5", "")
        se = sample_enrichment.get(md5, {})
        proto = c.get("protocol", "?")
        proto_label = PROTOCOL_MAP.get(proto, (proto.upper(), "", "#93A7B8"))[0]
        url = _defang(c.get("url", ""))
        url_cell = _esc(url) if url else '<span style="color:#5e7385">-</span>'
        fam = se.get("family") or "-"
        fam_color = "#e5484d" if fam not in ("-", "") else "#5e7385"
        ftype = se.get("file_type") or "-"
        av_m, av_t = se.get("av_malicious"), se.get("av_total")
        if av_m is not None and av_t:
            av_ratio = f"{av_m}/{av_t}"
            av_color = "#e5484d" if av_m >= av_t * 0.5 else "#f5a623"
        else:
            av_ratio, av_color = "-", "#5e7385"
        capture_rows += f"""
        <tr>
          <td style="font-size:11px;color:#93a7b8;font-family:monospace">{c['_ts'].strftime('%m-%d %H:%M:%S')}</td>
          <td style="font-size:11px;font-family:monospace">{_esc(c.get('src_ip','?'))}</td>
          <td style="font-size:11px;color:#93a7b8">{proto_label}</td>
          <td style="font-size:11px;font-family:monospace;color:#f5a623;word-break:break-all;max-width:220px">{url_cell}</td>
          <td style="font-size:11px;font-family:monospace" title="{_esc(md5)}">{_esc(md5[:16])}&hellip;</td>
          <td style="font-size:11px;font-weight:600;color:{fam_color}">{_esc(fam)}</td>
          <td style="font-size:11px;color:#93a7b8">{_esc(ftype)}</td>
          <td style="font-size:11px;font-weight:600;text-align:right;color:{av_color}">{av_ratio}</td>
        </tr>"""
    if not capture_rows:
        capture_rows = ('<tr><td colspan="8" style="text-align:center;'
                        'color:#5e7385;font-size:12px;padding:16px">'
                        'No samples captured in this window.</td></tr>')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dionaea Daily Report - {now.strftime('%Y-%m-%d')}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: "IBM Plex Sans", system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: #0d1620; color: #e7eef4; padding: 2rem; }}
  h1   {{ font-size: 20px; font-weight: 600; margin-bottom: 4px; }}
  h2   {{ font-size: 13px; font-weight: 500; color: #93a7b8; margin: 1.5rem 0 .75rem; text-transform: uppercase; letter-spacing: .05em; }}
  .meta  {{ font-size: 12px; color: #5e7385; margin-bottom: 1.5rem; }}
  .grid4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 1.5rem; }}
  .grid5 {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 1.5rem; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 1.5rem; }}
  .card  {{ background: #13202c; border-radius: 10px; padding: 1rem 1.25rem; border: 1px solid #223344; }}
  .metric-label {{ font-size: 11px; color: #93a7b8; text-transform: uppercase; letter-spacing: .05em; margin-bottom: 4px; }}
  .metric-value {{ font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 28px; font-weight: 600; }}
  .danger {{ color: #e5484d; }}
  .warn   {{ color: #f5a623; }}
  .info   {{ color: #46b6c4; }}
  table   {{ width: 100%; border-collapse: collapse; }}
  th      {{ font-size: 11px; color: #93a7b8; font-weight: 500; padding: 4px 6px; text-align: left; border-bottom: 1px solid #223344; }}
  td      {{ font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 12.5px; padding: 5px 6px; border-bottom: 1px solid #1a2937; vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  .timeline {{ position: relative; height: 80px; display: flex; align-items: flex-end; gap: 2px; }}
  .tl-bar  {{ flex: 1; background: #46b6c4; border-radius: 2px 2px 0 0; opacity: .6;
               min-height: 2px; transition: opacity .15s; }}
  .tl-bar:hover {{ opacity: 1; }}
  footer   {{ font-size: 11px; color: #5e7385; margin-top: 2rem; text-align: center; }}
  .badge-high {{ background:rgba(229,72,77,.15);color:#ff6b6b;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600 }}
  .badge-med  {{ background:rgba(245,166,35,.15);color:#f5a623;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600 }}
  .badge-low  {{ background:rgba(70,182,196,.15);color:#7dd3c0;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600 }}

  /* Clickable metric cards */
  .card-click {{ cursor:pointer; position:relative; transition: border-color .12s, box-shadow .12s, transform .12s; }}
  .card-click:hover {{ border-color:#46b6c4; box-shadow:0 4px 14px rgba(0,0,0,.35); transform:translateY(-1px); }}
  .card-click:focus-visible {{ outline:2px solid #46b6c4; outline-offset:2px; }}
  .drill-hint {{ font-size:10px; color:#5e7385; margin-top:8px; font-weight:600; letter-spacing:.04em; text-transform:uppercase; }}
  .card-click:hover .drill-hint {{ color:#46b6c4; }}

  /* Drill-down modal */
  .drill-overlay {{ display:none; position:fixed; inset:0; background:rgba(5,10,15,.7);
                    z-index:50; align-items:flex-start; justify-content:center; padding:6vh 16px; }}
  .drill-modal {{ background:#13202c; border-radius:12px; width:100%; max-width:680px; max-height:84vh;
                  display:flex; flex-direction:column; box-shadow:0 20px 60px rgba(0,0,0,.5);
                  border:1px solid #223344; overflow:hidden; }}
  .drill-head {{ display:flex; align-items:flex-start; justify-content:space-between;
                 padding:18px 20px 14px; border-bottom:1px solid #223344; }}
  .drill-title {{ font-size:15px; font-weight:600; color:#e7eef4; }}
  .drill-sub {{ font-size:11px; color:#93a7b8; margin-top:3px; }}
  .drill-x {{ background:none; border:none; font-size:24px; line-height:1; color:#93a7b8;
              cursor:pointer; padding:0 4px; }}
  .drill-x:hover {{ color:#e5484d; }}
  .drill-filter {{ margin:14px 20px 0; padding:9px 12px; border:1px solid #223344; border-radius:7px;
                   background:#0d1620; color:#e7eef4;
                   font-size:13px; font-family:"IBM Plex Mono", ui-monospace, monospace; outline:none; }}
  .drill-filter:focus {{ border-color:#46b6c4; }}
  .drill-body {{ overflow-y:auto; padding:8px 20px 12px; }}
  .drill-table thead th {{ position:sticky; top:0; background:#13202c; z-index:1; }}
  .drill-empty {{ padding:24px 20px; text-align:center; color:#5e7385; font-size:13px; }}
  @media (max-width: 640px) {{
    body {{ padding: 1rem; }}
    .grid4 {{ grid-template-columns: 1fr 1fr; }}
    .grid5 {{ grid-template-columns: 1fr 1fr; }}
    .grid2 {{ grid-template-columns: 1fr; }}
    table {{ display: block; overflow-x: auto; white-space: nowrap; }}
    .drill-modal {{ max-width: 94vw; }}
  }}
</style>
</head>
<body>

<h1>🍯 Dionaea Honeypot - Daily Probable Positives</h1>
<div class="meta">
  Window: {cutoff.strftime('%Y-%m-%d %H:%M UTC')} &rarr; {now.strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp;
  Source: {log_path} &nbsp;|&nbsp;
  Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}
</div>

<!-- METRIC ROW -->
<div class="grid5">
  <div class="card">
    <div class="metric-label">Total connections</div>
    <div class="metric-value">{total:,}</div>
  </div>
  <div class="card card-click" role="button" tabindex="0"
       onclick="openDrill('unique')"
       onkeydown="if(event.key==='Enter'||event.key===' '){{event.preventDefault();openDrill('unique')}}">
    <div class="metric-label">Unique attacker IPs</div>
    <div class="metric-value info">{unique_ips:,}</div>
    <div class="drill-hint">inspect &rsaquo;</div>
  </div>
  <div class="card card-click" role="button" tabindex="0"
       onclick="openDrill('highfreq')"
       onkeydown="if(event.key==='Enter'||event.key===' '){{event.preventDefault();openDrill('highfreq')}}">
    <div class="metric-label">High-freq IPs (5+ hits)</div>
    <div class="metric-value warn">{high_freq:,}</div>
    <div class="drill-hint">inspect &rsaquo;</div>
  </div>
  <div class="card card-click" role="button" tabindex="0"
       onclick="openDrill('scanners')"
       onkeydown="if(event.key==='Enter'||event.key===' '){{event.preventDefault();openDrill('scanners')}}">
    <div class="metric-label">Probable scanners (50+ hits)</div>
    <div class="metric-value danger">{scanner_count:,}</div>
    <div class="drill-hint">inspect &rsaquo;</div>
  </div>
  <div class="card">
    <div class="metric-label">Samples captured</div>
    <div class="metric-value {'danger' if capture_count else ''}">{capture_count:,}</div>
  </div>
</div>

<!-- PROTOCOL + TIMELINE -->
<div class="grid2">
  <div class="card">
    <h2>Protocol targeting</h2>
    <table>{proto_rows}</table>
  </div>
  <div class="card">
    <h2>Hourly volume (last {min(len(sorted_hours), 24)}h)</h2>
    <div class="timeline" id="tl"></div>
    <div style="display:flex;justify-content:space-between;font-size:10px;color:#5e7385;margin-top:4px">
      <span>{sorted_hours[0][0].split(' ')[1] if sorted_hours else ''}</span>
      <span>{sorted_hours[-1][0].split(' ')[1] if sorted_hours else ''}</span>
    </div>
  </div>
</div>

<!-- TOP IPs + RECENT EVENTS -->
<div class="grid2">
  <div class="card">
    <h2>Top attacker IPs</h2>
    <table>
      <tr><th>IP</th><th>Risk</th><th>Hits</th><th>Protocol</th><th>Verdict</th><th>Bad</th><th>Country</th><th>ASN</th><th>Abuse%</th><th>GreyNoise</th></tr>
      {ip_rows}
    </table>
    <div style="font-size:10px;color:#5e7385;margin-top:8px">🔴 ≥50 hits &nbsp; 🟡 ≥10 hits &nbsp; 🟢 &lt;10 hits</div>
  </div>
  <div class="card">
    <h2>Recent events (last 20)</h2>
    <table>
      <tr><th>Time</th><th>Src IP</th><th>Protocol</th><th>Port</th></tr>
      {event_rows}
    </table>
  </div>
</div>

<!-- MALWARE CAPTURED -->
<div class="card" style="margin-bottom:1.5rem">
  <h2>Malware captured ({capture_count})</h2>
  <table>
    <tr><th>Time (UTC)</th><th>Src IP</th><th>Protocol</th><th>URL (defanged)</th><th>MD5</th><th>Family</th><th>File type</th><th>AV</th></tr>
    {capture_rows}
  </table>
  <div style="font-size:10px;color:#5e7385;margin-top:8px">Family / file type / AV ratio from enrich_samples.py (MalwareBazaar + VirusTotal). URLs are defanged for safe rendering.</div>
</div>

<!-- MITRE MAPPING -->
<div class="card" style="margin-bottom:1.5rem">
  <h2>MITRE ATT&amp;CK mapping</h2>
  <table>
    <tr><th>Technique</th><th>Name</th><th>Observed via</th><th>Event count</th></tr>
    <tr>
      <td style="font-family:monospace;font-size:12px">T1046</td>
      <td style="font-size:12px">Network Service Discovery</td>
      <td style="font-size:12px">Any inbound connection</td>
      <td style="font-size:12px">{total:,}</td>
    </tr>
    <tr>
      <td style="font-family:monospace;font-size:12px">T1190</td>
      <td style="font-size:12px">Exploit Public-Facing Application</td>
      <td style="font-size:12px">HTTP, FTP, MySQL, MSSQL</td>
      <td style="font-size:12px">{sum(c for p, c in proto_counts.items() if p in ('httpd','ftpd','mysqld','mssqld')):,}</td>
    </tr>
    <tr>
      <td style="font-family:monospace;font-size:12px">T1210</td>
      <td style="font-size:12px">Exploitation of Remote Services</td>
      <td style="font-size:12px">SMB</td>
      <td style="font-size:12px">{proto_counts.get('smbd', 0):,}</td>
    </tr>
    <tr>
      <td style="font-family:monospace;font-size:12px">T1595</td>
      <td style="font-size:12px">Active Scanning</td>
      <td style="font-size:12px">High-frequency source IPs</td>
      <td style="font-size:12px">{high_freq:,} IPs</td>
    </tr>
    <tr>
      <td style="font-family:monospace;font-size:12px">T1105</td>
      <td style="font-size:12px">Ingress Tool Transfer</td>
      <td style="font-size:12px">Captured malware downloads</td>
      <td style="font-size:12px">{capture_count:,}</td>
    </tr>
  </table>
</div>

<footer>
  Honeylab Detection Lab &nbsp;|&nbsp; Mike Holzheimer &nbsp;|&nbsp;
  github.com/PumpkinEscobar &nbsp;|&nbsp;
  Generated by dionaea_daily_report.py
</footer>

<!-- DRILL-DOWN MODAL -->
<div id="drill-overlay" class="drill-overlay" onclick="if(event.target===this)closeDrill()">
  <div class="drill-modal" role="dialog" aria-modal="true" aria-labelledby="drill-title">
    <div class="drill-head">
      <div>
        <div id="drill-title" class="drill-title">IPs</div>
        <div id="drill-sub" class="drill-sub"></div>
      </div>
      <button class="drill-x" onclick="closeDrill()" aria-label="Close">&times;</button>
    </div>
    <input id="drill-filter" class="drill-filter" type="text" placeholder="Filter by IP, protocol, or risk..." oninput="renderDrill()">
    <div class="drill-body">
      <table class="drill-table">
        <thead>
          <tr>
            <th>IP</th>
            <th style="text-align:right">Hits</th>
            <th>Top proto</th>
            <th>First seen (UTC)</th>
            <th>Last seen (UTC)</th>
            <th>Risk</th>
            <th>Country</th>
            <th>Abuse%</th>
            <th>GreyNoise</th>
          </tr>
        </thead>
        <tbody id="drill-rows"></tbody>
      </table>
      <div id="drill-empty" class="drill-empty" style="display:none"></div>
    </div>
  </div>
</div>

<script>
{DRILL_SCRIPT}
</script>

<script>
const bars = {bar_data};
const max  = Math.max(...bars.map(b => b.c), 1);
const tl   = document.getElementById('tl');
bars.forEach(b => {{
  const d  = document.createElement('div');
  d.className = 'tl-bar';
  d.style.height = Math.max(4, Math.round(b.c / max * 76)) + 'px';
  if (b.c === max) d.style.background = '#e5484d';
  d.title = b.h + ' - ' + b.c + ' connections';
  tl.appendChild(d);
}});
</script>
</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    global INDEXER_URL, INDEX_PATTERN

    parser = argparse.ArgumentParser(
        description="Daily Dionaea threat report, sourced from the Wazuh indexer."
    )
    parser.add_argument("--hours", type=int, default=DEFAULT_HOURS,
                        help="Lookback window in hours (default 24)")
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help="Output HTML file path")
    parser.add_argument("--url", default=INDEXER_URL,
                        help="Indexer base URL (default https://localhost:9200)")
    parser.add_argument("--index", default=INDEX_PATTERN,
                        help="Index pattern (default wazuh-alerts-*)")
    parser.add_argument("--enrich-db", default="ip_cache.db",
                        help="Path to the IP reputation cache built by "
                             "enrich_ips.py (default ip_cache.db). Missing "
                             "or stale entries render as '-', non-fatal.")
    args = parser.parse_args()

    INDEXER_URL   = args.url
    INDEX_PATTERN = args.index

    print(f"[*] Indexer:     {INDEXER_URL}  index={INDEX_PATTERN}")
    print(f"[*] Time window: last {args.hours} hours")

    events = fetch_events(args.hours)
    print(f"[*] Accept events pulled: {len(events)}")

    captures = fetch_downloads(args.hours)
    print(f"[*] Capture (download) events pulled: {len(captures)}")

    data = classify_events(events, captures)
    print(f"[*] Accepted connections: {data['total']}")
    print(f"[*] Unique IPs:           {data['unique_ips']}")
    print(f"[*] High-frequency IPs:   {len(data['high_freq_ips'])}")
    print(f"[*] Samples captured:     {data['capture_count']} "
          f"({len(data['unique_hashes'])} unique hashes)")

    enrichment = load_enrichment(args.enrich_db, data["src_ip_counts"].keys())
    print(f"[*] IPs with cached reputation: {len(enrichment)}/{data['unique_ips']}")
    overlay_verdicts(enrichment, data["src_ip_counts"].keys())

    sample_enrichment = load_sample_enrichment(args.enrich_db, data["unique_hashes"])
    print(f"[*] Hashes with cached intel: {len(sample_enrichment)}/"
          f"{len(data['unique_hashes'])}")

    source_label = f"Wazuh indexer ({INDEX_PATTERN})"
    html = build_html(data, args.hours, source_label, enrichment, sample_enrichment)

    from pathlib import Path
    out_path = Path(args.out)
    out_path.write_text(html, encoding="utf-8")
    print(f"[+] Report written: {out_path.resolve()}")


if __name__ == "__main__":
    main()
