#!/usr/bin/env bash
# Audit a directory of <CVE>.cocci rules with cvehound's own test suite -- the
# authority check for any generated rule set (`rulegen export-rules` writes a
# run's rules in this form).
#
#   scripts/audit_rules.sh <rules-dir> [jobs]
#   AUDIT_HEADS=runs/<run>/manifest.json   pin the branch heads to what that run scored
#   AUDIT_CVES=<id list>                   audit only these CVEs (one per line)
#   AUDIT_LOG=reports/audit-<name>.log     where the log goes (default: by timestamp)
#   CVEHOUND_REPO=../cvehound              the cvehound checkout to audit in
#
# The suite fetches the kernel remotes at start-up unless told not to, and a
# fetched branch head is a tree the oracle never scored: CVEHOUND_TEST_OFFLINE=1
# always, and AUDIT_HEADS pins `--branch` to the SHAs a run's manifest recorded.
# cvehound resolves rules from its editable checkout, so the rules are installed on
# a scratch branch there and removed on exit whatever happens -- never while a
# rulegen run is using that checkout. One pytest invocation covers every CVE. The
# suite's branch worktrees (several GB) go under TMPDIR.
set -euo pipefail
cd "$(dirname "$0")/.."

RULES=${1:?rules directory}
JOBS=${2:-8}
CVEHOUND=${CVEHOUND_REPO:-../cvehound}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BRANCH="audit-rules-$STAMP"
IDS=$(mktemp)
REPORT=${AUDIT_LOG:-reports/audit-rules-$STAMP.log}

[ -d "$RULES" ] || { echo "no rules directory at $RULES" >&2; exit 1; }
# Untracked files do not matter: the audit only adds and removes rules under cvehound/cve.
if [ -n "$(git -C "$CVEHOUND" status --porcelain --untracked-files=no)" ]; then
    echo "$CVEHOUND has uncommitted changes; commit or stash them first" >&2
    exit 1
fi
if pgrep -f 'rulegen (ru[n]|resco[r]e) ' >/dev/null; then
    echo "a rulegen run is using $CVEHOUND; wait for it to finish" >&2
    exit 1
fi

ORIGINAL=$(git -C "$CVEHOUND" rev-parse --abbrev-ref HEAD)
restore() {
    git -C "$CVEHOUND" checkout -q --force "$ORIGINAL" 2>/dev/null || true
    git -C "$CVEHOUND" clean -qfd cvehound/cve 2>/dev/null || true
    git -C "$CVEHOUND" branch -qD "$BRANCH" 2>/dev/null || true
    rm -f "$IDS"
    echo "restored $CVEHOUND to $ORIGINAL"
}
trap restore EXIT

for rule in "$RULES"/*.cocci; do basename "$rule" .cocci; done | sort > "$IDS"
if [ -n "${AUDIT_CVES:-}" ]; then
    grep -Fxf "$AUDIT_CVES" "$IDS" > "$IDS.subset" && mv "$IDS.subset" "$IDS"
fi
count=$(wc -l < "$IDS")
branch_args=()
if [ -n "${AUDIT_HEADS:-}" ]; then
    while read -r sha; do branch_args+=(--branch "$sha"); done < <(
        python3 -c "import json,sys; [print(v) for _k, v in sorted(json.load(open(sys.argv[1]))['kernel']['heads'].items())]" "$AUDIT_HEADS")
    echo "branch heads pinned to $AUDIT_HEADS (${#branch_args[@]} args)"
fi
echo "auditing $count rules from $RULES with -n $JOBS"

git -C "$CVEHOUND" checkout -q -b "$BRANCH"
# A rule the checkout already has (a gold CVE) is replaced by the generated one.
while read -r cve; do
    rm -f "$CVEHOUND/cvehound/cve/$cve.cocci" "$CVEHOUND/cvehound/cve/disputed/$cve.cocci"
    cp "$RULES/$cve.cocci" "$CVEHOUND/cvehound/cve/"
done < "$IDS"

mkdir -p reports
cve_args=()
while read -r cve; do cve_args+=(--cve "$cve"); done < "$IDS"
status=0
( cd "$CVEHOUND" && CVEHOUND_CONTENT=none CVEHOUND_TEST_OFFLINE=1 uv run --with psutil \
    --with pytest-xdist --with filelock --with gitpython python -m pytest tests/ --runslow \
    --between-mode=commits -n "$JOBS" -q -rf "${branch_args[@]}" "${cve_args[@]}" ) 2>&1 \
    | tee "$REPORT" || status=$?

echo
tail -1 "$REPORT"
echo "full log: $REPORT"
exit "$status"
