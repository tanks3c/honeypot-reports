#!/usr/bin/env python3
"""
Local analyst review UI for captured malware samples.

Loopback-only (127.0.0.1:8787) web front-end over sample_reviews.json:
  /              list of all captured samples with review-status badges
  /sample/<md5>  detail view: capture events, auto enrichment, editable
                 family / file type / MITRE / notes, and Verify / Save /
                 Reopen actions
Verify/Save/Reopen update the ledger via review_samples.py's helpers and
(when "publish" is checked) regenerate docs/malware.html and git
commit + pull --rebase + push, same as `review_samples.py verify --commit`.

Stdlib only. Runs on homebase as a systemd user service
(honeypot-review.service). Never bind this off loopback: it has no auth
and it can push to the public repo.
"""

import html
import json
import subprocess
import sys
import urllib.parse
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))
import review_samples as rs  # noqa: E402  (ledger helpers)

HOST, PORT = "127.0.0.1", 8787

STYLE = """
:root{--bg:#0d1620;--bg-raised:#13202c;--line:#223344;--ink:#e7eef4;
  --ink-dim:#93a7b8;--ink-faint:#5e7385;--link:#46b6c4;--signal:#f5a623;
  --bad:#e5484d;--ok:#3dd68c;--maxw:980px}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:"IBM Plex Sans",system-ui,sans-serif;line-height:1.55}
.wrap{max-width:var(--maxw);margin:0 auto;padding:24px}
.mono{font-family:"IBM Plex Mono",ui-monospace,monospace}
a{color:var(--link);text-decoration:none} a:hover{text-decoration:underline}
h1{font-size:1.4rem;margin:.2em 0} .dim{color:var(--ink-dim)}
table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;
  vertical-align:top}
th{background:var(--bg-raised);color:var(--ink-dim);font-weight:500}
tr.rowlink{cursor:pointer} tr.rowlink:hover td{background:var(--bg-raised)}
.badge{display:inline-block;padding:1px 9px;border-radius:3px;
  font-family:"IBM Plex Mono",monospace;font-size:.72rem;letter-spacing:.05em}
.b-pend{color:var(--signal);border:1px solid var(--signal)}
.b-ok{color:var(--ok);border:1px solid var(--ok)}
form{background:var(--bg-raised);border:1px solid var(--line);
  border-radius:8px;padding:18px 20px;margin:18px 0}
label{display:block;font-family:"IBM Plex Mono",monospace;font-size:.75rem;
  letter-spacing:.08em;text-transform:uppercase;color:var(--ink-faint);
  margin:14px 0 4px}
input[type=text],textarea{width:100%;background:var(--bg);color:var(--ink);
  border:1px solid var(--line);border-radius:4px;padding:8px 10px;
  font-family:"IBM Plex Mono",monospace;font-size:.85rem}
textarea{min-height:90px;resize:vertical}
.btn{display:inline-block;border:0;border-radius:4px;padding:10px 18px;
  font-family:"IBM Plex Mono",monospace;font-size:.85rem;font-weight:600;
  cursor:pointer;margin:16px 10px 0 0}
.btn-verify{background:var(--ok);color:var(--bg)}
.btn-save{background:var(--signal);color:var(--bg)}
.btn-reopen{background:transparent;color:var(--bad);
  border:1px solid var(--bad)}
.auto{font-size:.78rem;color:var(--ink-faint);margin-top:3px}
.flash{border:1px solid var(--ok);color:var(--ok);border-radius:4px;
  padding:8px 12px;margin:14px 0;font-family:"IBM Plex Mono",monospace;
  font-size:.8rem}
.flash.err{border-color:var(--bad);color:var(--bad)}
.kv th{width:30%;border:0;border-bottom:1px solid var(--line);
  background:transparent}
.kv td{border:0;border-bottom:1px solid var(--line)}
"""


def esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def load_all():
    doc = rs.load(rs.CAPTURES, {})
    reviews = rs.load(rs.REVIEWS, {})
    by_md5 = defaultdict(list)
    for c in doc.get("captures", []):
        by_md5[c["md5"]].append(c)
    return doc, reviews, by_md5


def page(title: str, body: str) -> bytes:
    return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>{STYLE}</style></head><body><div class="wrap">{body}</div></body></html>""".encode()


def badge(rec: dict) -> str:
    if rec.get("status") == "verified":
        return (f'<span class="badge b-ok">✓ VERIFIED '
                f'{esc((rec.get("reviewed_on") or "")[:10])}</span>')
    return '<span class="badge b-pend">⚠ PENDING REVIEW</span>'


def render_list(flash: str = "") -> bytes:
    doc, reviews, by_md5 = load_all()
    samples = doc.get("samples", {})
    rows = []
    for md5, events in sorted(by_md5.items(),
                              key=lambda kv: max(e["_ts"] for e in kv[1]),
                              reverse=True):
        rec = reviews.get(md5, {})
        fam = rec.get("family") or samples.get(md5, {}).get("family") or \
            "unattributed"
        srcs = ", ".join(sorted({e["src_ip"] for e in events}))
        last = max(e["_ts"] for e in events)[:16].replace("T", " ")
        rows.append(
            f'<tr class="rowlink" onclick="location=\'/sample/{esc(md5)}\'">'
            f'<td class="mono"><a href="/sample/{esc(md5)}">{esc(md5)}</a></td>'
            f'<td>{badge(rec)}</td><td>{esc(fam)}</td>'
            f'<td>{len(events)}</td><td class="mono">{esc(srcs)}</td>'
            f'<td class="mono">{esc(last)}</td></tr>')
    pending = sum(1 for m in by_md5
                  if reviews.get(m, {}).get("status") != "verified")
    body = f"""
<p class="mono dim">honeylab // analyst review console (local)</p>
<h1>Captured samples <span class="dim">({len(by_md5)} total,
{pending} pending)</span></h1>
{f'<div class="flash">{esc(flash)}</div>' if flash else ''}
<p class="dim">Select a sample to review, edit, and verify its details.
Verifying regenerates the public malware page and pushes.</p>
<table>
<tr><th>md5</th><th>status</th><th>family</th><th>events</th>
<th>source IPs</th><th>last delivery</th></tr>
{''.join(rows) or '<tr><td colspan="6" class="dim">no captures yet</td></tr>'}
</table>
<p class="dim mono" style="margin-top:20px;font-size:.78rem">
public page: <a href="https://pumpkinescobar.github.io/honeypot-reports/malware.html">malware.html</a>
&middot; CLI: python3 review_samples.py</p>"""
    return page("review console // captured samples", body)


def render_detail(md5: str, flash: str = "", err: bool = False) -> bytes:
    doc, reviews, by_md5 = load_all()
    if md5 not in by_md5:
        return page("not found", '<p>unknown sample. <a href="/">back</a></p>')
    rec = reviews.get(md5, {})
    auto = doc.get("samples", {}).get(md5, {})
    events = sorted(by_md5[md5], key=lambda e: e["_ts"], reverse=True)
    ev_rows = "".join(
        f'<tr><td class="mono">{esc(e["_ts"][:19])}</td>'
        f'<td class="mono">{esc(e["src_ip"])}</td>'
        f'<td class="mono">{esc(e["protocol"])} {esc(e["transport"])}'
        f'/{esc(e["dst_port"])}</td>'
        f'<td class="mono">{esc(e.get("url") or "(inline drop)")}</td></tr>'
        for e in events)
    fam = rec.get("family", auto.get("family") or "")
    ftype = rec.get("file_type", auto.get("file_type") or "")
    mitre = ",".join(rec.get("mitre") or [])
    notes = rec.get("notes", "")
    flash_html = (f'<div class="flash{" err" if err else ""}">{esc(flash)}'
                  '</div>') if flash else ""
    body = f"""
<p class="mono dim"><a href="/">&larr; all samples</a></p>
<h1 class="mono" style="word-break:break-all">{esc(md5)}</h1>
{badge(rec)}
{flash_html}
<table class="kv" style="margin-top:16px">
<tr><th>AV detection</th><td>{esc(auto.get("av_malicious"))} /
{esc(auto.get("av_total"))} engines</td></tr>
<tr><th>Auto family (MB/VT)</th><td>{esc(auto.get("family") or "unattributed")}</td></tr>
<tr><th>Auto file type</th><td>{esc(auto.get("file_type") or "?")}</td></tr>
<tr><th>Tags</th><td>{esc(auto.get("tags") or "-")}</td></tr>
<tr><th>First seen (intel)</th><td>{esc(auto.get("first_seen") or "-")}</td></tr>
<tr><th>Lookups</th><td>
<a href="https://www.virustotal.com/gui/search/{esc(md5)}">VirusTotal</a> &middot;
<a href="https://bazaar.abuse.ch/browse.php?search=md5%3A{esc(md5)}">MalwareBazaar</a></td></tr>
</table>

<h2 style="font-size:1rem;color:var(--signal);margin-top:26px">Delivery
events ({len(events)})</h2>
<table><tr><th>timestamp (utc)</th><th>source</th><th>vector</th>
<th>url</th></tr>{ev_rows}</table>

<form method="post" action="/sample/{esc(md5)}">
<h2 style="font-size:1rem;color:var(--signal);margin:0">Analyst record</h2>
<label>Family</label>
<input type="text" name="family" value="{esc(fam)}">
<div class="auto">auto: {esc(auto.get("family") or "unattributed")}</div>
<label>File type</label>
<input type="text" name="file_type" value="{esc(ftype)}">
<label>MITRE ATT&amp;CK (comma separated)</label>
<input type="text" name="mitre" value="{esc(mitre)}">
<div class="auto">default: T1190 initial access + T1105 payload transfer;
T1210 = worm propagation context</div>
<label>Notes</label>
<textarea name="notes">{esc(notes)}</textarea>
<label style="text-transform:none;letter-spacing:0">
<input type="checkbox" name="publish" checked
 style="width:auto;margin-right:6px">publish on action (regenerate
malware.html + git push)</label>
<button class="btn btn-verify" name="action" value="verify">✓ Verify</button>
<button class="btn btn-save" name="action" value="save">Save only</button>
<button class="btn btn-reopen" name="action" value="reopen">Reopen</button>
</form>"""
    return page(f"review // {md5[:12]}", body)


def apply_action(md5: str, form: dict) -> tuple[str, bool]:
    """Returns (flash message, is_error)."""
    reviews = rs.load(rs.REVIEWS, {})
    if md5 not in reviews:
        # ledger stub missing (e.g. sync never ran): create one on the fly
        rs.sync(notify=False)
        reviews = rs.load(rs.REVIEWS, {})
    rec = reviews.get(md5)
    if rec is None:
        return ("no ledger record for this hash; run review_samples.py sync",
                True)
    action = form.get("action", "save")
    rec["family"] = form.get("family", rec.get("family", ""))
    rec["file_type"] = form.get("file_type", rec.get("file_type", ""))
    rec["mitre"] = [t.strip().upper()
                    for t in form.get("mitre", "").split(",") if t.strip()]
    rec["notes"] = form.get("notes", rec.get("notes", ""))
    if action == "verify":
        rec["status"] = "verified"
        rec["reviewed_on"] = rs.now()
    elif action == "reopen":
        rec["status"] = "pending_review"
        rec["reviewed_on"] = None
    reviews[md5] = rec
    rs.save_reviews(reviews)
    msg = f"{action}: saved"
    if form.get("publish"):
        try:
            rs.regen_and_commit(md5, action)
            msg = f"{action}: saved, page regenerated and pushed"
        except subprocess.CalledProcessError as e:
            return (f"{action}: ledger saved, but publish failed: {e}", True)
    return (msg, False)


ALLOWED_HOSTS = {f"{HOST}:{PORT}", f"localhost:{PORT}"}
ALLOWED_ORIGINS = {f"http://{h}" for h in ALLOWED_HOSTS}


class Handler(BaseHTTPRequestHandler):
    def _host_ok(self) -> bool:
        # Defeats DNS rebinding: a hostile page resolving its own domain to
        # 127.0.0.1 still sends its domain in the Host header.
        return self.headers.get("Host", "") in ALLOWED_HOSTS

    def _origin_ok(self) -> bool:
        # CSRF guard for state-changing POSTs. Browsers always attach Origin
        # (or at least Referer) on cross-origin form posts, so any present
        # value must be ours. Absent both = non-browser client (curl), fine.
        origin = self.headers.get("Origin")
        referer = self.headers.get("Referer")
        if origin is not None:
            return origin in ALLOWED_ORIGINS
        if referer is not None:
            return any(referer.startswith(o + "/") or referer == o
                       for o in ALLOWED_ORIGINS)
        return True

    def _send(self, body: bytes, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._host_ok():
            return self._send(b"forbidden", 403)
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            return self._send(render_list())
        if path.startswith("/sample/"):
            return self._send(render_detail(path.split("/sample/", 1)[1]))
        return self._send(page("404", '<p><a href="/">back</a></p>'), 404)

    def do_POST(self):
        if not self._host_ok() or not self._origin_ok():
            return self._send(b"forbidden", 403)
        path = urllib.parse.urlparse(self.path).path
        if not path.startswith("/sample/"):
            return self._send(page("404", '<p><a href="/">back</a></p>'), 404)
        md5 = path.split("/sample/", 1)[1]
        length = int(self.headers.get("Content-Length", 0))
        form = {k: v[0] for k, v in urllib.parse.parse_qs(
            self.rfile.read(length).decode()).items()}
        flash, err = apply_action(md5, form)
        self._send(render_detail(md5, flash=flash, err=err))

    def log_message(self, fmt, *args):
        print(f"[review-ui] {self.address_string()} {fmt % args}")


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[review-ui] listening on http://{HOST}:{PORT}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
