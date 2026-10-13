#!/usr/bin/env bash
# managed-by: security-gate v0.1.0-p0 (owned)
#
# Steps of the security gate that only a human runs, in their own terminal and
# with their own GitHub login. Do not hand this script to a coding agent.
#
#   bash .security-gate/human/human.sh confirm <pr-number> [--yes --head SHA] [--remote NAME]
#
# confirm
#   A pull request whose head differs from the default branch in
#   .github/workflows/ or .security-gate/ gets "inconclusive" from the gate
#   (rule SG-TRUST-001) until a human has read the change and confirmed it.
#   This command shows the protected files that differ and their diff against
#   the default branch, computes the fingerprint of the protected files in the
#   head commit, and after you type "yes" stores it in the repository variable
#   SECURITY_GATE_CONFIG. It is a variable, not a secret: the value is a hash.
#   Then re-run the gate on that pull request.
#
#   The fingerprint is computed by gate.py taken from the default branch, never
#   from the pull request. Run this script from the default branch too.
#
#   It refuses (exit 4) when the default branch changed protected files after
#   the pull request branched off (merge or rebase the default branch into it
#   first), and when a protected path is a symlink or a submodule (those can
#   never be confirmed).
#
#   Without a terminal the command refuses to run, unless you pass --yes. With
#   --yes you must name the head commit you reviewed (--head, 40 hex digits):
#   if the pull request has moved on since, nothing is confirmed. In --yes mode
#   the diff is printed, so that it stays in your terminal log.
#
# Exit codes: 0 done or nothing to do, 1 not confirmed, 2 usage or setup
# error, 4 a precondition is not met.
set -euo pipefail

readonly VARIABLE=SECURITY_GATE_CONFIG
readonly GATE=.security-gate/bin/gate.py
readonly SELF=.security-gate/human/human.sh
SCRIPT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
readonly SCRIPT
TMP_DIR=""

cleanup() {
  if [ -n "$TMP_DIR" ]; then rm -rf -- "$TMP_DIR"; fi
}
trap cleanup EXIT

fail() {
  local code=$1
  shift
  printf 'human.sh: %s\n' "$*" >&2
  exit "$code"
}

usage() {
  printf '%s\n' \
    "usage: bash $SELF confirm <pr-number> [--yes --head SHA] [--remote NAME]" \
    "" \
    "  confirm   confirm the protected changes of a pull request (SG-TRUST-001)" \
    "  --yes     do not prompt; required when there is no terminal; needs --head" \
    "  --head    the full commit id of the head you reviewed; refuse if the head moved" \
    "  --remote  git remote of the GitHub repository (default: origin)"
}

cmd_confirm() {
  local pr="" yes=0 remote=origin reviewed=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --yes) yes=1 ;;
      --head)
        [ $# -ge 2 ] || fail 2 "--head needs a value"
        reviewed=$2
        shift
        ;;
      --remote)
        [ $# -ge 2 ] || fail 2 "--remote needs a value"
        remote=$2
        shift
        ;;
      -h | --help) usage; exit 0 ;;
      -*) fail 2 "unknown option: $1" ;;
      *)
        [ -z "$pr" ] || fail 2 "only one pull request number is accepted"
        pr=$1
        ;;
    esac
    shift
  done
  [[ "$pr" =~ ^[1-9][0-9]*$ ]] || { usage >&2; exit 2; }
  if [ "$yes" -eq 1 ] && [ -z "$reviewed" ]; then
    fail 2 "--yes needs --head <the full commit id of the head you reviewed>"
  fi
  if [ -n "$reviewed" ] && ! [[ "$reviewed" =~ ^[0-9a-f]{40}$ ]]; then
    fail 2 "--head must be a full commit id: 40 lowercase hex digits"
  fi
  if [ "$yes" -eq 0 ] && { [ ! -t 0 ] || [ ! -t 1 ]; }; then
    fail 2 "no terminal. Run this yourself in a terminal, or pass --yes to confirm without a prompt."
  fi
  local tool
  for tool in git gh python3; do
    command -v "$tool" >/dev/null 2>&1 || fail 2 "$tool is not installed"
  done

  local top repo default state head_sha base_sha
  top=$(git rev-parse --show-toplevel 2>/dev/null) || fail 2 "run this inside a clone of the repository"
  cd "$top"
  repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner) || fail 2 "gh cannot read the repository; check gh auth status"
  default=$(gh repo view "$repo" --json defaultBranchRef --jq .defaultBranchRef.name) || fail 2 "gh cannot read the default branch"
  state=$(gh pr view "$pr" --repo "$repo" --json state --jq .state) || fail 2 "gh cannot read pull request #$pr"
  [ "$state" = OPEN ] || fail 4 "pull request #$pr is $state, not OPEN"
  head_sha=$(gh pr view "$pr" --repo "$repo" --json headRefOid --jq .headRefOid) || fail 2 "gh cannot read the head of #$pr"
  [[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 2 "unexpected head commit id from gh"
  if [ -n "$reviewed" ] && [ "$head_sha" != "$reviewed" ]; then
    fail 4 "the head of #$pr is now $head_sha, not the $reviewed you reviewed; review the new commits, then run again with --head $head_sha"
  fi

  git fetch --quiet --no-tags "$remote" "+refs/heads/$default:refs/security-gate/default" "+refs/pull/$pr/head:refs/security-gate/pr-$pr" || fail 2 "git cannot get $default and #$pr from the remote $remote"
  [ "$(git rev-parse "refs/security-gate/pr-$pr")" = "$head_sha" ] || fail 4 "the head of #$pr on $remote is not the one GitHub reports; run again"
  base_sha=$(git rev-parse refs/security-gate/default)

  TMP_DIR=$(mktemp -d)
  local tmp=$TMP_DIR
  git show "$base_sha:$GATE" > "$tmp/gate.py" 2>/dev/null || fail 4 "$GATE is not on $default: merge the onboarding first"
  git show "$base_sha:$SELF" > "$tmp/human.sh" 2>/dev/null || fail 4 "$SELF is not on $default"
  cmp -s "$tmp/human.sh" "$SCRIPT" || fail 4 "this human.sh differs from the one on $default; run the copy from $default"

  python3 -I "$tmp/gate.py" protected-diff --repo "$top" --default "$base_sha" --head "$head_sha" > "$tmp/report" || fail 2 "gate.py could not compute the protected changes"
  local fp changed stale special
  fp=$(sed -n 's/^fingerprint=//p' "$tmp/report")
  changed=$(sed -n 's/^changed=//p' "$tmp/report")
  stale=$(sed -n 's/^behind=//p' "$tmp/report")
  special=$(sed -n 's/^unconfirmable=//p' "$tmp/report")
  [[ "$fp" =~ ^sha256:[0-9a-f]{64}$ ]] || fail 2 "gate.py returned no fingerprint"
  [[ "$changed" =~ ^[0-9]+$ && "$stale" =~ ^[0-9]+$ && "$special" =~ ^[0-9]+$ ]] || fail 2 "gate.py returned no list of changes"

  printf 'Repository:   %s (default branch %s)\n' "$repo" "$default"
  printf 'Pull request: #%s, head %s\n' "$pr" "$head_sha"
  if [ "$special" -gt 0 ]; then
    printf 'Protected paths that are symlinks or submodules:\n'
    sed -n 's/^unconfirmable://p' "$tmp/report"
    fail 4 "a symlink or submodule on a protected path can never be confirmed: its content is outside the protected set. Remove it in a pull request."
  fi
  if [ "$changed" -eq 0 ]; then
    printf 'The head has the same protected files as %s. Nothing to confirm.\n' "$default"
    exit 0
  fi
  printf 'Protected files where the head differs from %s:\n' "$default"
  sed -n 's/^changed://p' "$tmp/report"
  if [ "$stale" -gt 0 ]; then
    printf '%s changed these protected files after the pull request branched off:\n' "$default"
    sed -n 's/^behind://p' "$tmp/report"
    fail 4 "merge or rebase $default into #$pr first, so that the diff shows only its own changes; then run again"
  fi
  python3 -I "$tmp/gate.py" protected-diff --repo "$top" --default "$base_sha" --head "$head_sha" --patch > "$tmp/patch" || fail 2 "gate.py could not show the diff"
  if [ "$yes" -eq 1 ]; then
    printf '\nThe full diff (control characters are escaped):\n'
    sed -n 'p' "$tmp/patch"
    printf '\n--yes: setting %s on %s to\n  %s\n' "$VARIABLE" "$repo" "$fp"
  else
    printf '\nPress Enter to read the full diff (control characters are escaped).'
    read -r _ || fail 1 "no answer; nothing was changed"
    if command -v less >/dev/null 2>&1; then
      less "$tmp/patch"
    else
      sed -n 'p' "$tmp/patch"
    fi
    printf '\nOnly confirm what you have read and understood: a pull request that\n'
    printf 'changes the gate or its workflow can switch the gate off.\n'
    printf 'Set %s on %s to\n  %s\nType yes to confirm: ' "$VARIABLE" "$repo" "$fp"
    local answer
    read -r answer || fail 1 "no answer; nothing was changed"
    [ "$answer" = yes ] || fail 1 "not confirmed; nothing was changed"
  fi

  gh variable set "$VARIABLE" --repo "$repo" --body "$fp" || fail 2 "gh could not write $VARIABLE (admin or write access is needed)"
  [ "$(gh variable get "$VARIABLE" --repo "$repo")" = "$fp" ] || fail 2 "$VARIABLE does not read back as written"
  printf '%s is set. Now re-run the security-gate check of #%s in the Actions tab,\n' "$VARIABLE" "$pr"
  printf 'or with: gh run rerun <run id> --repo %s   (the run is listed by\n' "$repo"
  printf '  gh run list --repo %s --workflow security-gate.yml --commit %s)\n' "$repo" "$head_sha"
  printf 'If the re-run still reports SG-TRUST-001, push a new commit to the pull request.\n'
}

main() {
  [ $# -ge 1 ] || { usage >&2; exit 2; }
  local cmd=$1
  shift
  case "$cmd" in
    confirm) cmd_confirm "$@" ;;
    -h | --help | help) usage ;;
    *) usage >&2; exit 2 ;;
  esac
}

main "$@"
