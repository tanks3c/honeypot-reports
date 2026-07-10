#!/usr/bin/env python3
"""
Analyst review ledger for captured malware samples.

Every unique hash in captures_latest.json gets a record in
sample_reviews.json. New hashes are stubbed as `pending_review` with the
auto-enrichment values prefilled; the analyst verifies (or corrects) family,
file type, MITRE mapping, and notes, which flips the record to `verified`.
malware_page.py renders the badge and prefers analyst values over auto ones.

Pipeline use (capture_pipeline.sh):
    python3 review_samples.py sync --notify
        Stub any new hashes, send a Signal review request for them.

Analyst use:
    python3 review_samples.py                # list all samples + status
    python3 review_samples.py show 8a4e      # full record (md5 prefix ok)
    python3 review_samples.py verify 8a4e \
        --family trojan.barys/dloader \
        --mitre T1190,T1105 \
        --notes "SMB inline drop, EternalBlue-style; T1210 = propagation ctx"
    python3 review_samples.py reopen 8a4e    # flip back to pending_review
    Add --commit to verify/reopen to regenerate the page and git commit+push.

Default MITRE prefill is T1190 (internet-facing SMB exploited = initial
access) + T1105 (payload pushed onto host). T1210 is noted as worm
propagation context, not the primary mapping - see the 2026-07-09 analysis.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent
CAPTURES = REPO / "captures_latest.json"
REVIEWS = REPO / "sample_reviews.json"

DEFAULT_MITRE = ["T1190", "T1105"]
DEFAULT_NOTES = ("AUTO: SMB/445 inline drop (no URL). Mapped T1190 "
                 "(internet-facing service exploited, initial access) + "
                 "T1105 (payload transfer). T1210 applies only as worm "
                 "propagation context. Verify family/mapping and edit "
                 "as needed.")

# signal-cli REST API config is shared with net-baseline (same daemon).
SIGNAL_CFG = Path.home() / ".config" / "net-baseline" / "config.yaml"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text())


def save_reviews(reviews: dict):
    REVIEWS.write_text(json.dumps(reviews, indent=2, sort_keys=True) + "\n")


def sync(notify: bool = False) -> list:
    """Stub a pending_review record for every hash that has none.
    Returns the list of newly flagged md5s."""
    doc = load(CAPTURES, {})
    reviews = load(REVIEWS, {})
    samples = doc.get("samples", {})
    hashes = sorted({c["md5"] for c in doc.get("captures", [])})
    new = []
    for md5 in hashes:
        if md5 in reviews:
            continue
        auto = samples.get(md5, {})
        reviews[md5] = {
            "status": "pending_review",
            "first_flagged": now(),
            "reviewed_on": None,
            "family": auto.get("family") or "",
            "file_type": auto.get("file_type") or "",
            "mitre": list(DEFAULT_MITRE),
            "notes": DEFAULT_NOTES,
            "auto": {k: auto.get(k) for k in
                     ("family", "file_type", "tags", "first_seen",
                      "av_malicious", "av_total")},
        }
        new.append(md5)
    if new:
        save_reviews(reviews)
        print(f"[review] flagged {len(new)} new sample(s) for review: "
              + ", ".join(m[:8] for m in new))
        if notify:
            notify_signal(new, reviews)
    else:
        print("[review] no new samples")
    return new


def notify_signal(md5s: list, reviews: dict):
    """Best-effort Signal ping via the local signal-cli REST API."""
    try:
        import requests
        import yaml
        scfg = yaml.safe_load(SIGNAL_CFG.read_text()).get("signal", {})
        if not scfg.get("enabled") or not scfg.get("number"):
            return
        lines = [f"🧪 honeylab: {len(md5s)} new malware sample(s) "
                 "pending review"]
        for m in md5s[:5]:
            r = reviews[m]
            fam = r.get("family") or "unattributed"
            lines.append(f"{m[:12]}… {fam}")
        lines.append("verify: cd ~/projects/honeypot-reports && "
                     "python3 review_samples.py")
        resp = requests.post(
            f"{scfg['api_url'].rstrip('/')}/v2/send",
            json={"message": "\n".join(lines),
                  "number": scfg["number"],
                  "recipients": scfg.get("recipients") or [scfg["number"]]},
            timeout=30)
        if resp.status_code >= 300:
            print(f"[review] Signal send failed: {resp.status_code}",
                  file=sys.stderr)
        else:
            print("[review] Signal review request sent")
    except Exception as e:
        print(f"[review] Signal notify skipped: {e}", file=sys.stderr)


def resolve(reviews: dict, prefix: str) -> str:
    hits = [m for m in reviews if m.startswith(prefix.lower())]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        sys.exit(f"no sample matches '{prefix}'")
    sys.exit(f"ambiguous prefix '{prefix}': " + ", ".join(h[:12] for h in hits))


def cmd_list(reviews: dict):
    if not reviews:
        print("no samples in the ledger yet (run: review_samples.py sync)")
        return
    print(f"{'md5':34} {'status':16} {'family':28} reviewed")
    for md5, r in sorted(reviews.items(),
                         key=lambda kv: kv[1].get("first_flagged") or "",
                         reverse=True):
        flag = "⚠ " if r["status"] == "pending_review" else "✓ "
        print(f"{flag}{md5:32} {r['status']:16} "
              f"{(r.get('family') or 'unattributed'):28} "
              f"{r.get('reviewed_on') or '-'}")


def cmd_show(reviews: dict, prefix: str):
    md5 = resolve(reviews, prefix)
    print(json.dumps({md5: reviews[md5]}, indent=2))


def apply_edits(rec: dict, args) -> dict:
    if args.family is not None:
        rec["family"] = args.family
    if args.file_type is not None:
        rec["file_type"] = args.file_type
    if args.mitre is not None:
        rec["mitre"] = [t.strip().upper() for t in args.mitre.split(",")
                        if t.strip()]
    if args.notes is not None:
        rec["notes"] = args.notes
    return rec


def regen_and_commit(md5: str, action: str):
    subprocess.run([sys.executable, str(REPO / "malware_page.py")],
                   check=True)
    subprocess.run(["git", "-C", str(REPO), "add", "sample_reviews.json",
                    "docs/malware.html", "docs/index.html"], check=True)
    r = subprocess.run(["git", "-C", str(REPO), "diff", "--cached",
                        "--quiet"])
    if r.returncode == 0:
        print("[review] nothing to commit")
        return
    subprocess.run(["git", "-C", str(REPO), "commit", "-m",
                    f"Sample review: {action} {md5[:12]}"], check=True)
    subprocess.run(["git", "-C", str(REPO), "pull", "--rebase"], check=True)
    subprocess.run(["git", "-C", str(REPO), "push"], check=True)
    print("[review] committed and pushed")


def main():
    ap = argparse.ArgumentParser(
        description="Review ledger for captured malware samples.")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list", help="list samples + review status (default)")
    p = sub.add_parser("show", help="print one sample's full record")
    p.add_argument("md5")
    for name, hlp in (("verify", "mark verified, optionally editing fields"),
                      ("update", "edit fields without changing status"),
                      ("reopen", "flip back to pending_review")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("md5")
        p.add_argument("--family")
        p.add_argument("--file-type", dest="file_type")
        p.add_argument("--mitre",
                       help="comma-separated technique IDs, e.g. T1190,T1105")
        p.add_argument("--notes")
        p.add_argument("--commit", action="store_true",
                       help="regenerate malware.html and git commit+push")
    p = sub.add_parser("sync", help="stub review records for new hashes")
    p.add_argument("--notify", action="store_true",
                   help="send a Signal review request for new samples")
    args = ap.parse_args()

    if args.cmd == "sync":
        sync(notify=args.notify)
        return
    reviews = load(REVIEWS, {})
    if args.cmd in (None, "list"):
        cmd_list(reviews)
        return
    if args.cmd == "show":
        cmd_show(reviews, args.md5)
        return

    md5 = resolve(reviews, args.md5)
    rec = apply_edits(reviews[md5], args)
    if args.cmd == "verify":
        rec["status"] = "verified"
        rec["reviewed_on"] = now()
    elif args.cmd == "reopen":
        rec["status"] = "pending_review"
        rec["reviewed_on"] = None
    reviews[md5] = rec
    save_reviews(reviews)
    print(f"[review] {args.cmd}: {md5[:12]} status={rec['status']} "
          f"family={rec.get('family') or 'unattributed'} "
          f"mitre={','.join(rec.get('mitre', []))}")
    if args.commit:
        regen_and_commit(md5, args.cmd)


if __name__ == "__main__":
    main()
