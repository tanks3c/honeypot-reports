#!/usr/bin/env bash
# Scheduled honeypot capture pipeline (runs on homebase via a systemd user
# timer). Pull the Dionaea downloads table from the honeypot sqlite over SSM,
# enrich the hashes (MalwareBazaar + VirusTotal, keys from SSM), embed the
# enrichment, and commit captures_latest.json so the analysis-box daily report
# can consume it with --captures-json.
#
# Runs on homebase because that is where the honeymike profile + outbound live;
# the honeypot has no outbound internet and the report host has no honeymike
# creds. Delivery is via a repo commit: the report host git-pulls and reads the
# tracked captures_latest.json.
set -uo pipefail
cd "$(dirname "$0")" || exit 1

export AWS_KEY_PROFILE="${AWS_KEY_PROFILE:-honeymike}"
OUT=captures_latest.json

if ! python3 dionaea_downloads.py --out "$OUT"; then
    echo "[pipeline] honeypot pull failed; leaving previous $OUT in place"
    exit 1
fi

# Enrichment is best-effort: a missing/rate-limited key must not fail the run.
python3 enrich_samples.py --captures-json "$OUT" --embed \
    || echo "[pipeline] enrichment degraded (keys/rate limit); captures still published"

# Flag any new hashes for analyst review (stubs sample_reviews.json) and
# ping Signal so the review doesn't sit unnoticed. Best-effort.
python3 review_samples.py sync --notify \
    || echo "[pipeline] review sync failed; captures still published"

# Regenerate the public malware page + index metric tile from the captures.
python3 malware_page.py \
    || echo "[pipeline] malware page render failed; captures still published"

# Publish only when the captures/enrichment actually changed. The JSON's top
# level `generated` timestamp bumps every run, so a raw `git diff` would commit
# every cycle; compare a content signature over captures+samples instead, and
# discard a timestamp-only churn so the tree stays clean.
CHANGED=$(python3 - "$OUT" <<'PY'
import json, sys, subprocess, hashlib
def sig(doc):
    return hashlib.sha256(json.dumps(
        {"c": doc.get("captures"), "s": doc.get("samples")},
        sort_keys=True).encode()).hexdigest()
new = json.load(open(sys.argv[1]))
try:
    old = json.loads(subprocess.check_output(
        ["git", "show", "HEAD:" + sys.argv[1]], stderr=subprocess.DEVNULL))
except Exception:
    old = None
print("yes" if (old is None or sig(old) != sig(new)) else "no")
PY
)
if [ "$CHANGED" = "yes" ]; then
    git add "$OUT" docs/malware.html docs/index.html sample_reviews.json
    git commit -q -m "Automated capture update $(date -u +%FT%TZ)" || exit 0
    git push -q || echo "[pipeline] git push failed (credential helper?); commit is local"
    echo "[pipeline] published capture update"
else
    git checkout -- "$OUT" docs/malware.html docs/index.html 2>/dev/null   # drop timestamp-only churn
    # a review stub for a NEW hash can't happen here (new hash => CHANGED=yes),
    # so leave sample_reviews.json alone: analyst edits must survive.
    echo "[pipeline] no capture change"
fi
