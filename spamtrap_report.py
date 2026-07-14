#!/usr/bin/env python3
"""Render the spamtrap intel page from the S3 export.

Pulls exports/latest.json (written hourly by the spamtrap box), renders
docs/spamtrap.html to match the site theme, defangs every indicator
(emails, domains, IPs, URLs), and commits + pushes only when content
changed. Runs from a systemd user timer on homebase.
"""
import html
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent


def _conf(key):
    for line in (REPO / ".spamtrap.conf").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line.split("=", 1)[0] == key:
            return line.split("=", 1)[1].strip()
    return os.environ[key]


PROFILE = _conf("PROFILE")
BUCKET = _conf("BUCKET")
KEY = "exports/latest.json"
PAGE = REPO / "docs" / "spamtrap.html"


def defang(s):
    if not s:
        return ""
    return str(s).replace(".", "[.]").replace("@", "[@]").replace("http", "hxxp")


def esc(s):
    return html.escape(str(s if s is not None else ""))


def dz(s):
    """defang then escape, the only safe order"""
    return esc(defang(s))


def table(headers, rows):
    if not rows:
        return '<p class="dim">nothing yet</p>'
    h = "".join(f"<th>{esc(x)}</th>" for x in headers)
    b = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>"
                for r in rows)
    return f'<div class="tw"><table><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table></div>'


VCOLOR = {"malicious": "#ff6b6b", "suspicious": "#f5a623",
          "benign-scanner": "#46b6c4", "no-adverse-data": "#93a7b8"}


def vtip(v):
    """Plain-text audit trail for the hover tooltip: the rule, the
    confidence math, every checkable piece of evidence, and the engine's
    cross-sensor sightings history when the ledger knows this IP."""
    r = v.get("rationale") or {}
    lines = [r.get("rule", ""), ""]
    for e in r.get("evidence", []):
        detail = e.get("detail", "")
        ref = e.get("ref")
        lines.append(f"- {detail}" + (f" [{ref}]" if ref else ""))
    if r.get("confidence_basis"):
        lines += ["", f"confidence = {r['confidence_basis']}"]
    sg = v.get("sightings") or {}
    if sg.get("first_seen"):
        hits = sg.get("total_hits")
        line = (f"first seen ever {sg['first_seen']} "
                f"(all sensors, ledger since 2026-07-08)")
        if sg.get("days_seen"):
            line += (f"; {hits if hits is not None else '?'} hits over "
                     f"{sg['days_seen']} day(s)")
        if sg.get("sensors"):
            line += f"; sensors: {', '.join(sg['sensors'])}"
        lines += ["", line]
    return "\n".join(lines).strip()


def vcell(v):
    if not v:
        return '<span class="dim">-</span>'
    col = VCOLOR.get(v["verdict"], "#93a7b8")
    tip = esc(vtip(v))
    return (f'<span title="{tip}" style="cursor:help">'
            f'<b style="color:{col}">{esc(v["verdict"])}</b> '
            f'<span class="dim">{esc(v["confidence"])}%</span></span>')


def render(d, verdicts):
    t = d["totals"]
    camp_rows = [[esc(c["kind"]), dz(c["ckey"]), esc(c["member_count"]),
                  esc(c["distinct_addrs"]),
                  ", ".join(dz(a) for a in c["sample_addrs"]),
                  esc((c["last_seen"] or "")[:10])]
                 for c in d["campaigns"]]
    young_rows = [[dz(x["domain"]), esc((x["registered"] or "")[:10]),
                   esc(x["age_days"]),
                   "yes" if x["disposable"] else "no", esc(x["msg_count"])]
                  for x in d["young_domains"]]
    def badflag(x):
        if x["known_bad"]:
            return ('<b style="color:#ff6b6b">BAD</b> '
                    f'<span class="dim">{esc(x["bad_sources"] or "")}</span>')
        return '<span class="dim">-</span>'
    def iprow(x):
        v = verdicts.get(x["ip"])
        f = (v or {}).get("facts", {})
        ports = ",".join(str(p) for p in (f.get("open_ports") or [])[:8])
        return [dz(x["ip"]), vcell(v), badflag(x),
                esc(f.get("class") or ""),
                esc(x["abuse_score"]), esc(x["country"]),
                esc(f'AS{x["asn"]} {x["org"]}') if x.get("asn") else "",
                esc(ports), esc(x["dnsbl"] or ""), esc(x["msg_count"])]
    ip_rows = [iprow(x) for x in d["top_ips"]]
    url_rows = [[dz(u["url"]), esc(u["threat"]), esc(u["tags"] or "")]
                for u in d.get("flagged_urls", [])]
    recent_rows = [[esc((m["ingested_at"] or "")[:16]), dz(m["from_addr"]),
                    esc(m["from_display"]), esc((m["subject"] or "")[:70]),
                    esc(m["spf"]), esc(m["dkim"]), esc(m["dmarc"]),
                    esc(m["spam_verdict"])]
                   for m in d["recent"]]

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>spamtrap // email threat intel</title>
<meta name="description" content="A spamtrap catch-all domain feeding an email threat intel pipeline. Sender families, newly registered domains, and source IP reputation. All indicators defanged.">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{{--bg:#0d1620;--bg-raised:#13202c;--line:#223344;--ink:#e7eef4;
    --ink-dim:#93a7b8;--link:#46b6c4;--signal:#f5a623;--maxw:980px}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--ink);
    font-family:"IBM Plex Sans",system-ui,sans-serif;line-height:1.55}}
  .wrap{{max-width:var(--maxw);margin:0 auto;padding:24px}}
  .mono{{font-family:"IBM Plex Mono",ui-monospace,monospace}}
  a{{color:var(--link);text-decoration:none}}
  a:hover{{text-decoration:underline}}
  h1{{font-size:1.6rem;margin:.2em 0}} h2{{font-size:1.1rem;margin-top:2em;
    color:var(--signal)}}
  .dim{{color:var(--ink-dim)}}
  .stats{{display:flex;gap:16px;flex-wrap:wrap;margin:20px 0}}
  .stat{{background:var(--bg-raised);border:1px solid var(--line);
    border-radius:6px;padding:12px 18px;min-width:110px}}
  .stat b{{display:block;font-size:1.5rem}}
  .tw{{overflow-x:auto}}
  table{{border-collapse:collapse;width:100%;font-size:.85rem;
    font-family:"IBM Plex Mono",monospace}}
  th,td{{border:1px solid var(--line);padding:6px 9px;text-align:left;
    vertical-align:top}}
  th{{background:var(--bg-raised);color:var(--ink-dim);font-weight:500}}
  @media (max-width: 640px) {{
    .wrap {{ padding: 14px; }}
    .stat {{ min-width: calc(50% - 8px); }}
  }}
</style>
</head>
<body><div class="wrap">
<p class="mono dim"><a href="index.html">&larr; honeylab</a></p>
<h1>spamtrap // email threat intel</h1>
<p class="dim">A catch-all spamtrap domain feeding an automated pipeline:
SES inbound &rarr; parser &rarr; enrichment (bulk reputation feeds,
RDAP domain age, Spamhaus DNSBL, ASN/geo, Shodan InternetDB,
AbuseIPDB, URLhaus) &rarr; central verdict engine (multi-source
corroboration, research scanners excluded) &rarr; sender-family
clustering. All indicators on this page are defanged.
Generated {esc(d["generated"])}.</p>
<div class="stats">
<div class="stat"><b>{esc(t["messages"])}</b>messages</div>
<div class="stat"><b>{esc(t["last7d"])}</b>last 7 days</div>
<div class="stat"><b>{esc(t["campaigns"])}</b>campaigns</div>
<div class="stat"><b>{esc(t["domains"])}</b>domains seen</div>
<div class="stat"><b>{esc(t["ips"])}</b>source IPs</div>
<div class="stat"><b>{esc(t.get("known_bad_ips", 0))}</b>known-bad IPs</div>
<div class="stat"><b>{esc(t.get("flagged_urls", 0))}</b>flagged URLs</div>
</div>
<h2>campaigns (sender families)</h2>
{table(["kind", "family key", "msgs", "addrs", "sample senders", "last seen"], camp_rows)}
<h2>young sender domains (&le;90 days old)</h2>
{table(["domain", "registered", "age (days)", "disposable", "msgs"], young_rows)}
<h2>source IP reputation</h2>
<p class="dim" style="font-size:.85rem">Every verdict is auditable: hover the
verdict for the rule that fired, the confidence arithmetic, and each source
with a link to verify it independently. Research scanners are classified
separately and never counted as malicious.</p>
{table(["ip", "verdict", "known bad", "class", "abuse score", "cc", "asn / org", "open ports", "dnsbl", "msgs"], ip_rows)}
<h2>flagged URLs (URLhaus)</h2>
{table(["url", "threat", "tags"], url_rows)}
<h2>recent messages</h2>
{table(["ingested (utc)", "from", "display name", "subject", "spf", "dkim", "dmarc", "ses verdict"], recent_rows)}
<p class="dim mono" style="margin-top:2.5em">indicators defanged: [.] = dot,
[@] = at, hxxp = http. machine-readable feed (real IOCs, STIX 2.1):
<a href="stix-bundle.json">stix-bundle.json</a>. pipeline is young; volume
grows as trap addresses get seeded.</p>
</div></body></html>
"""


def main():
    r = subprocess.run(
        ["aws", "s3", "cp", f"s3://{BUCKET}/{KEY}", "-",
         "--profile", PROFILE],
        capture_output=True, check=True)
    data = json.loads(r.stdout)
    try:
        v = subprocess.run(
            ["aws", "s3", "cp", f"s3://{BUCKET}/enrichment/verdicts.json",
             "-", "--profile", PROFILE], capture_output=True, check=True)
        verdicts = json.loads(v.stdout).get("ips", {})
    except Exception:
        verdicts = {}  # central engine output missing; page degrades
    out = render(data, verdicts)
    if PAGE.exists() and PAGE.read_text() == out:
        print("no change")
        return
    PAGE.write_text(out)
    # stage the STIX bundle too: the chained stix step regenerates it and a
    # dirty tree breaks the pull --rebase below
    subprocess.run(["git", "-C", str(REPO), "add", "docs/spamtrap.html",
                    "docs/stix-bundle.json"], check=True)
    r = subprocess.run(["git", "-C", str(REPO), "diff", "--cached",
                        "--quiet"])
    if r.returncode == 0:
        print("no staged change")
        return
    subprocess.run(["git", "-C", str(REPO), "commit", "-m",
                    f"Spamtrap report update {data['generated']}"],
                   check=True)
    # the wazuh box pushes to this repo too; rebase before pushing
    subprocess.run(["git", "-C", str(REPO), "pull", "--rebase"], check=True)
    subprocess.run(["git", "-C", str(REPO), "push"], check=True)
    print("published")


if __name__ == "__main__":
    sys.exit(main())
