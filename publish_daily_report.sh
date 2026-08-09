#!/usr/bin/env bash
# Dionaea daily report: generate + publish.
#
# Runs as a SYSTEM unit (dionaea-report.timer, User=ssm-user) on the
# wazuh-analysis EC2 box (i-0436e7c3ab07a5307), NOT on homebase, because
# wazuh_daily_report.py needs the Wazuh indexer on localhost:9200.
#
# PUBLISHING MODEL, as of 2026-08-09 (Option B): this box does NOT push.
# It generates the report and commits it to local main only. Homebase then runs
# ~/bin/relay_daily_report.sh (dionaea-report-relay.timer, 06:20/14:20/22:20 UTC),
# pulls the committed report over SSM, pushes it to origin, and resets this box
# to origin/main. Rationale: a deception-adjacent honeypot-account box must never
# hold a credential that can rewrite published intel. Do NOT re-add `git push`
# here, and do NOT install a deploy key on this box.
#
# Distinct exit codes so `systemctl status dionaea-report` triages instantly:
#   78  repo is in a state this script must not touch (wedged / detached / wrong branch)
#   1   report generation failed
#   (128 is retired: the push step was removed 2026-08-09, so exit 128 from this
#    unit now means something genuinely new, not the old credential fault.)
set -euo pipefail
cd "$(dirname "$0")"

# Log to cron_publish.log AND stdout, so the systemd journal is not blind.
exec > >(tee -a cron_publish.log) 2>&1
echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) run start ==="

GIT_DIR_PATH="$(git rev-parse --git-dir)"
WEDGE_SENTINEL=".publish_wedged"

die_wedged() {
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  echo "!! PUBLISH ABORTED: $1"
  echo "!! The repo is in a state this script must not write to."
  echo "!! Refusing to add/commit, because doing so stacks commits"
  echo "!! somewhere 'main' cannot see them (this happened 2026-08-06)."
  echo "!! Resolve by hand, then delete $WEDGE_SENTINEL."
  echo "!!   git -C $(pwd) status"
  echo "!!   git -C $(pwd) branch -v"
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  {
    echo "wedged_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "reason=$1"
    echo "head=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  } > "$WEDGE_SENTINEL"
  exit 78
}

# ---- Pre-flight guard. Must run BEFORE any git-mutating command. ----
# 1. An interrupted rebase leaves .git/rebase-merge or .git/rebase-apply behind.
if [ -d "$GIT_DIR_PATH/rebase-merge" ] || [ -d "$GIT_DIR_PATH/rebase-apply" ]; then
  die_wedged "rebase already in progress"
fi
# 2. Likewise for an interrupted merge / cherry-pick / revert.
for f in MERGE_HEAD CHERRY_PICK_HEAD REVERT_HEAD BISECT_LOG; do
  [ -e "$GIT_DIR_PATH/$f" ] && die_wedged "interrupted operation: $f present"
done
# 3. Detached HEAD: symbolic-ref fails when HEAD is not on a branch.
CURRENT_BRANCH="$(git symbolic-ref --quiet --short HEAD || true)"
[ -z "$CURRENT_BRANCH" ] && die_wedged "detached HEAD (not on any branch)"
# 4. Only ever publish from main.
[ "$CURRENT_BRANCH" != "main" ] && die_wedged "on branch '$CURRENT_BRANCH', expected 'main'"
# 5. A leftover sentinel means a previous run wedged and nobody cleared it.
[ -e "$WEDGE_SENTINEL" ] && die_wedged "sentinel $WEDGE_SENTINEL present from an earlier run"
# 6. Unmerged index entries.
git diff --cached --diff-filter=U --quiet || die_wedged "unmerged paths in the index"
echo "preflight ok: on $CURRENT_BRANCH, no rebase/merge in progress"

# ---- Sync BEFORE generating, so the local commit is always on top of ----
# ---- origin/main and the generated artifact can never conflict.      ----
# If anything goes wrong here, abort so the repo is never left mid-rebase.
if ! git fetch origin main; then
  echo "WARN: fetch failed, continuing with the local tree"
elif ! git rebase origin/main; then
  echo "ERROR: rebase onto origin/main failed, aborting it to keep the repo clean"
  git rebase --abort || true
  die_wedged "could not rebase onto origin/main (conflict), rebase aborted"
fi

if [ -f .env ]; then
  set -a; source .env; set +a
fi
export WZ_PW="${OPENSEARCH_PASS:?OPENSEARCH_PASS not set in .env}"

mkdir -p docs

python3 wazuh_daily_report.py \
  --hours 24 \
  --out docs/daily-report.html \
  --enrich-db ip_cache.db

if git diff --quiet -- docs/daily-report.html; then
  echo "no change, skip commit"
else
  git add docs/daily-report.html
  git commit -m "Automated report update $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "committed to local main; homebase relay publishes it (no push from this box by design)"
fi

echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) run end ==="
