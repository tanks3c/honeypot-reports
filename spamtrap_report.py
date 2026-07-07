#!/usr/bin/env python3
"""Render the spamtrap intel page from the S3 export.

Pulls exports/latest.json (written hourly by the spamtrap box), renders
docs/spamtrap.html to match the site theme, defangs every indicator
(emails, domains, IPs, URLs), and commits + pushes only when content
changed. Runs from a systemd user timer on homebase.
"""
import html
import json
import subprocess
import sys
from pathlib import Path

import boto3

PROFILE = "honeymike"
BUCKET = "spamtrap-mail-REDACTED-ACCT"
KEY = "exports/latest.json"
REPO = Path(__file__).resolve().parent
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


def render(d):
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
    ip_rows = [[dz(x["ip"]), esc(x["abuse_score"]), esc(x["total_reports"]),
                esc(x["country"]), esc(x["isp"]), esc(x["msg_count"])]
               for x in d["top_ips"]]
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
</style>
</head>
<body><div class="wrap">
<p class="mono dim"><a href="index.html">&larr; honeylab</a></p>
<h1>spamtrap // email threat intel</h1>
<p class="dim">A catch-all spamtrap domain feeding an automated pipeline:
SES inbound &rarr; parser &rarr; enrichment (RDAP domain age, disposable
detection, AbuseIPDB) &rarr; sender-family clustering. All indicators on
this page are defanged. Generated {esc(d["generated"])}.</p>
<div class="stats">
<div class="stat"><b>{esc(t["messages"])}</b>messages</div>
<div class="stat"><b>{esc(t["last7d"])}</b>last 7 days</div>
<div class="stat"><b>{esc(t["campaigns"])}</b>campaigns</div>
<div class="stat"><b>{esc(t["domains"])}</b>domains seen</div>
<div class="stat"><b>{esc(t["ips"])}</b>source IPs</div>
</div>
<h2>campaigns (sender families)</h2>
{table(["kind", "family key", "msgs", "addrs", "sample senders", "last seen"], camp_rows)}
<h2>young sender domains (&le;90 days old)</h2>
{table(["domain", "registered", "age (days)", "disposable", "msgs"], young_rows)}
<h2>source IP reputation</h2>
{table(["ip", "abuse score", "reports", "cc", "isp", "msgs"], ip_rows)}
<h2>recent messages</h2>
{table(["ingested (utc)", "from", "display name", "subject", "spf", "dkim", "dmarc", "ses verdict"], recent_rows)}
<p class="dim mono" style="margin-top:2.5em">indicators defanged: [.] = dot,
[@] = at, hxxp = http. pipeline is young; volume grows as trap addresses
get seeded.</p>
</div></body></html>
"""


def main():
    s3 = boto3.Session(profile_name=PROFILE).client("s3")
    data = json.loads(s3.get_object(Bucket=BUCKET, Key=KEY)["Body"].read())
    out = render(data)
    if PAGE.exists() and PAGE.read_text() == out:
        print("no change")
        return
    PAGE.write_text(out)
    subprocess.run(["git", "-C", str(REPO), "add", "docs/spamtrap.html"],
                   check=True)
    r = subprocess.run(["git", "-C", str(REPO), "diff", "--cached",
                        "--quiet"])
    if r.returncode == 0:
        print("no staged change")
        return
    subprocess.run(["git", "-C", str(REPO), "commit", "-m",
                    f"Spamtrap report update {data['generated']}"],
                   check=True)
    subprocess.run(["git", "-C", str(REPO), "push"], check=True)
    print("published")


if __name__ == "__main__":
    sys.exit(main())
