#!/usr/bin/env python3
"""Render a STIX 2.1 bundle from the spamtrap S3 export.

This is the community-sharing artifact (the MISP alternative). Unlike the
HTML page, STIX indicators are NOT defanged: the bundle is meant for
machine ingestion into other analysts' MISP/TIP instances. Deterministic
IDs (UUIDv5) so re-runs produce stable objects instead of duplicates.

Emits docs/stix-bundle.json. Runs on homebase right after the renderer.
"""
import json
import os
import subprocess
import sys
import uuid
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
OUT = REPO / "docs" / "stix-bundle.json"

# stable namespace for this producer's deterministic IDs
NS = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")
IDENTITY_ID = "identity--" + str(uuid.uuid5(NS, "spamtrap-producer"))


def sid(kind, value):
    return f"{kind}--" + str(uuid.uuid5(NS, f"{kind}:{value}"))


def indicator(value, pattern, name, labels, first, last):
    return {
        "type": "indicator", "spec_version": "2.1",
        "id": sid("indicator", value),
        "created_by_ref": IDENTITY_ID,
        "created": first or "2026-01-01T00:00:00Z",
        "modified": last or first or "2026-01-01T00:00:00Z",
        "name": name, "pattern": pattern, "pattern_type": "stix",
        "valid_from": first or "2026-01-01T00:00:00Z",
        "labels": labels,
    }


def main():
    r = subprocess.run(["aws", "s3", "cp", f"s3://{BUCKET}/{KEY}", "-",
                        "--profile", PROFILE], capture_output=True, check=True)
    d = json.loads(r.stdout)

    objects = [{
        "type": "identity", "spec_version": "2.1", "id": IDENTITY_ID,
        "created": "2026-07-06T00:00:00Z", "modified": "2026-07-06T00:00:00Z",
        "name": "honeylab spamtrap", "identity_class": "system",
        "description": "Automated email spamtrap. IOCs from unsolicited mail "
                       "to a seeded catch-all domain.",
    }]

    for c in d.get("campaigns", []):
        for addr in c.get("sample_addrs", []):
            esc = addr.replace("'", "\\'")
            objects.append(indicator(
                addr, f"[email-message:from_ref.value = '{esc}']",
                f"spamtrap campaign sender ({c['ckey']})",
                ["malicious-activity", "phishing"],
                c.get("first_seen"), c.get("last_seen")))

    for dom in d.get("young_domains", []):
        if dom.get("age_days") is not None and dom["age_days"] <= 30:
            esc = dom["domain"].replace("'", "\\'")
            objects.append(indicator(
                dom["domain"], f"[domain-name:value = '{esc}']",
                f"newly registered sender domain ({dom['age_days']}d old)",
                ["malicious-activity", "anomalous-activity"], None, None))

    for ip in d.get("top_ips", []):
        if (ip.get("abuse_score") or 0) >= 25:
            objects.append(indicator(
                ip["ip"], f"[ipv4-addr:value = '{ip['ip']}']",
                f"spam source IP (AbuseIPDB {ip['abuse_score']})",
                ["malicious-activity"], None, None))

    bundle = {"type": "bundle",
              "id": "bundle--" + str(uuid.uuid5(NS, d.get("generated", "x"))),
              "objects": objects}
    OUT.write_text(json.dumps(bundle, indent=1))
    print(f"wrote {len(objects)} STIX objects "
          f"({len(objects) - 1} indicators) to {OUT.name}")


if __name__ == "__main__":
    sys.exit(main())
