#!/usr/bin/env python3
"""
dionaea_downloads.py
====================
Phase 3 capture source: read the Dionaea `downloads` table straight from the
honeypot's sqlite (ground truth) and emit it in the capture shape the daily
report renders.

Why this exists:
  The Wazuh indexer carries zero Dionaea download events - only accept
  connections flow to the SIEM. Captures live only in the honeypot's sqlite
  (/opt/dionaea/data/dionaea.sqlite, `downloads` table). So the report's
  indexer-based fetch_downloads() always returns 0. This reads the sqlite
  directly instead.

How it reaches the honeypot:
  The honeypot has no outbound internet (egress locked to the SIEM + the SSM
  endpoints). The only channel in is SSM. This runs `aws ssm send-command`
  (AWS-RunShellScript) to execute a single read-only sqlite query on the box
  and pulls the JSON result back. Nothing is written on the honeypot.

  Whoever runs this needs AWS creds that can ssm:SendCommand to the honeypot
  (the honeymike profile does). To schedule it on the analysis box, that box's
  instance role needs ssm:SendCommand + ssm:GetCommandInvocation scoped to the
  honeypot instance.

Output:
  captures_YYYYMMDD.json  ->  {"generated", "source", "captures": [ ... ]}
  each capture: {_ts (ISO), src_ip, dst_port, transport, protocol, url, md5,
                 size, sha256}  (size/sha256 are null; sqlite has neither)

Usage:
      python3 dionaea_downloads.py                     # honeymike defaults
      python3 dionaea_downloads.py --hours 24          # only recent captures
      python3 dionaea_downloads.py --out captures.json
"""

import os
import sys
import json
import time
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timezone

# .env auto-load (same pattern as the siblings)
_env = Path(__file__).parent / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

INSTANCE_ID = os.environ.get("HONEYPOT_INSTANCE_ID", "i-0b0b4309b4b821173")
AWS_PROFILE = os.environ.get("HONEYPOT_AWS_PROFILE", "honeymike")
AWS_REGION  = os.environ.get("HONEYPOT_AWS_REGION", "us-east-1")
SQLITE_PATH = os.environ.get("DIONAEA_SQLITE", "/opt/dionaea/data/dionaea.sqlite")

# Read-only join: downloads -> connections for host/time/proto/port. Column
# names are the confirmed Dionaea schema (downloads: download_md5_hash,
# download_url; connections: remote_host, local_port, connection_protocol,
# connection_transport, connection_timestamp).
_SQL = (
    "SELECT d.download_md5_hash AS md5, d.download_url AS url, "
    "c.remote_host AS src_ip, c.local_port AS dst_port, "
    "c.connection_protocol AS protocol, c.connection_transport AS transport, "
    "c.connection_timestamp AS ts "
    "FROM downloads d JOIN connections c ON d.connection = c.connection "
    "WHERE d.download_md5_hash IS NOT NULL AND d.download_md5_hash != '' "
    "ORDER BY c.connection_timestamp DESC;"
)


def _aws(*args, timeout=60):
    """Run an aws-cli command, return parsed stdout (text). Raises on failure."""
    cmd = ["aws", "--profile", AWS_PROFILE, "--region", AWS_REGION, *args]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"aws {' '.join(args[:2])} failed: "
                           f"{p.stderr.strip()[:300]}")
    return p.stdout.strip()


def run_sqlite_over_ssm(hours=None) -> list:
    """Execute the read-only query on the honeypot via SSM and return the raw
    row dicts sqlite -json produced."""
    remote_cmd = f'sudo sqlite3 -json {SQLITE_PATH} "{_SQL}"'
    # JSON (not the commands= shorthand) so the SQL's quotes and commas survive.
    params = json.dumps({"commands": [remote_cmd]})
    cmd_id = _aws("ssm", "send-command",
                  "--instance-ids", INSTANCE_ID,
                  "--document-name", "AWS-RunShellScript",
                  "--parameters", params,
                  "--query", "Command.CommandId", "--output", "text")
    # Poll for completion.
    for _ in range(30):
        time.sleep(2)
        try:
            out = _aws("ssm", "get-command-invocation",
                       "--command-id", cmd_id, "--instance-id", INSTANCE_ID,
                       "--query", "{S:Status,O:StandardOutputContent,E:StandardErrorContent}",
                       "--output", "json")
        except RuntimeError:
            continue  # invocation may not be registered for a beat
        inv = json.loads(out)
        status = inv.get("S")
        if status in ("Success", "Failed", "Cancelled", "TimedOut"):
            if status != "Success":
                raise RuntimeError(f"remote query {status}: "
                                   f"{(inv.get('E') or '').strip()[:300]}")
            body = (inv.get("O") or "").strip()
            rows = json.loads(body) if body else []
            if hours is not None:
                cutoff = time.time() - hours * 3600
                rows = [r for r in rows
                        if _as_epoch(r.get("ts")) and _as_epoch(r.get("ts")) >= cutoff]
            return rows
    raise RuntimeError("SSM command did not complete within timeout")


def _as_epoch(ts):
    try:
        return float(ts)
    except (TypeError, ValueError):
        return None


def to_capture(row: dict) -> dict:
    """Normalize one sqlite row into the report's capture shape."""
    epoch = _as_epoch(row.get("ts"))
    iso = (datetime.fromtimestamp(epoch, timezone.utc).isoformat()
           if epoch else None)
    try:
        port = int(row.get("dst_port") or 0)
    except (TypeError, ValueError):
        port = 0
    return {
        "_ts":       iso,
        "src_ip":    row.get("src_ip") or "unknown",
        "dst_port":  port,
        "transport": row.get("transport") or "",
        "protocol":  row.get("protocol") or "unknown",
        "url":       row.get("url") or "",
        "md5":       str(row.get("md5")).lower(),
        "size":      None,
        "sha256":    None,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Pull the Dionaea downloads table from the honeypot sqlite "
                    "via SSM and write captures_YYYYMMDD.json.")
    ap.add_argument("--hours", type=int, default=None,
                    help="Only captures from the last N hours (default: all)")
    ap.add_argument("--out", default=None,
                    help="Output path (default captures_YYYYMMDD.json)")
    ap.add_argument("--instance-id", default=INSTANCE_ID)
    args = ap.parse_args()

    globals()["INSTANCE_ID"] = args.instance_id
    print(f"[*] honeypot: {args.instance_id} (profile {AWS_PROFILE}, {AWS_REGION})")
    try:
        rows = run_sqlite_over_ssm(args.hours)
    except Exception as e:
        print(f"[ERROR] could not read honeypot sqlite over SSM: {e}",
              file=sys.stderr)
        sys.exit(1)

    captures = [to_capture(r) for r in rows if r.get("md5")]
    hashes = sorted({c["md5"] for c in captures})
    out_path = Path(args.out or
                    f"captures_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json")
    out_path.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "source": "dionaea-sqlite",
        "instance_id": INSTANCE_ID,
        "captures": captures,
    }, indent=2), encoding="utf-8")

    print(f"[+] {len(captures)} capture(s), {len(hashes)} unique hash(es)")
    print(f"[+] wrote {out_path.resolve()}")


if __name__ == "__main__":
    main()
