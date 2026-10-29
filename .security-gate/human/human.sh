#!/usr/bin/env bash
# managed-by: security-gate v0.1.0-b4 (owned)
#
# Steps of the security gate that only a human runs, in their own terminal and
# with their own GitHub login. Do not hand this script to a coding agent.
#
# Every command first looks for a mark of an AI agent host or of an editor's
# built-in terminal in its environment (the closed list is in
# refuse_agent_host below) and refuses with exit 4 if it finds one, in a
# terminal and with --yes alike, before it reads the repository or calls
# GitHub. Run it yourself, in a terminal of your own: not through the agent,
# not with the ! prefix of an agent's prompt, not in the editor's terminal.
#
# The check is friction, not a boundary: whoever starts this script can drop
# the marks first (env -u NAME, or a fresh environment). What keeps an agent
# from confirming its own change is its GitHub login: one that cannot write
# repository variables, secrets or settings.
#
# Neither command runs git in the clone it is started in. A clone that a
# coding agent writes to can hold hooks and git configuration (a fsmonitor
# command, a remote that points elsewhere) that git would run with your
# login. The script fetches what it needs, the default branch and for confirm
# the pull request, from the URL GitHub gives for the repository into a bare
# repository of its own in a temporary directory, with hooks off and without
# the system git configuration. Your global git configuration applies, and gh
# answers git's request for credentials, as in gh repo clone. gh still reads
# the clone's remotes to tell which repository you mean: check the name the
# script prints (actions-policy --yes needs --repo). For any git command you
# run in that clone yourself, it stays a way to your login.
#
#   bash .security-gate/human/human.sh confirm <pr-number> [--yes --head SHA]
#   bash .security-gate/human/human.sh actions-policy [--yes --repo OWNER/NAME]
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
# actions-policy
#   For a public repository. GitHub blocks pull_request_target by default in a
#   public repository that has no Actions event policy for the workflow, and
#   the gate runs on pull_request_target. This command sets P-A, a repository
#   Actions policy that targets only .github/workflows/security-gate.yml and
#   lets it run only on pull_request_target. It reads the repository's
#   policies (the list, then each listed policy by id: the list shows no
#   conditions and no rules), shows what it will create or update and, after
#   you type "yes", writes P-A (admin access is needed), reads it back and
#   checks it. When P-A is in place it changes nothing. For a private or
#   internal repository it says that no policy is needed and changes nothing.
#
#   It never changes another policy. It refuses (exit 4) when another active
#   policy may stop the gate's workflow on pull_request_target, one that
#   GitHub does not show by id included, and it reports one that also lets
#   other workflows run on pull_request_target. Whether GitHub's default
#   block still stops other workflows once P-A exists is not proven (ADR 0003).
#
#   The policy and its checks come from gate.py on the default branch, and the
#   script refuses unless it is the copy on the default branch.
#
#   Without a terminal the command refuses to run, unless you pass --yes. With
#   --yes you must name the repository you mean (--repo OWNER/NAME): if this
#   clone is of another one, nothing is changed.
#
# Exit codes: 0 done or nothing to do, 1 not confirmed, 2 usage or setup
# error, 4 a precondition is not met (a mark of an agent host is one).
set -euo pipefail

readonly VARIABLE=SECURITY_GATE_CONFIG
readonly GATE=.security-gate/bin/gate.py
readonly SELF=.security-gate/human/human.sh
readonly WORKFLOW=.github/workflows/security-gate.yml
readonly POLICY_API="X-GitHub-Api-Version: 2026-03-10"
readonly OWNER_REPO_RE='^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$'
readonly NO_REPO="gh cannot read the repository: run this inside a clone of it, and check gh auth status"
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

# Refuse (exit 4) when the environment carries a mark of an AI agent host or
# of an editor's built-in terminal. The marks are a closed list: TERM_PROGRAM
# vscode, cursor or kiro, and the names below, matched against the names of
# the exported variables only (compgen -e prints names, never values). Claude
# Code and its Agent SDK, Codex, Cursor, Kiro, opencode, Copilot, VS Code and
# Hermes set them in the shells that run their commands. CODEX_HOME,
# COPILOT_HOME, OPENCODE_CONFIG and OPENCODE_CONFIG_DIR only say where a tool
# keeps its settings, and a person's own shell may export them. There is no
# switch that turns the check off.
refuse_agent_host() {
  local mark="" names name
  case "${TERM_PROGRAM:-}" in
    vscode | cursor | kiro) mark="TERM_PROGRAM=$TERM_PROGRAM" ;;
  esac
  [ "$(type -t compgen)" = builtin ] || fail 2 "this bash has no compgen, so it cannot check for an agent host"
  # compgen exits 1 when no variable is exported at all.
  names=$(compgen -e) || names=""
  while [ -z "$mark" ] && IFS= read -r name; do
    case "$name" in
      CODEX_HOME | COPILOT_HOME | OPENCODE_CONFIG | OPENCODE_CONFIG_DIR) ;;
      CLAUDECODE* | CLAUDE_CODE_* | CLAUDE_AGENT_SDK_* | AI_AGENT | CODEX_* | CURSOR_* | KIRO_* | OPENCODE* \
        | COPILOT_* | VSCODE_* | HERMES_SESSION_*) mark=$name ;;
    esac
  done <<<"$names"
  [ -z "$mark" ] || fail 4 "$mark marks an AI agent host or an editor's built-in terminal. Run this yourself, in your own terminal: not through the agent, not with the ! prefix of an agent's prompt and not in the editor's built-in terminal."
}

usage() {
  printf '%s\n' \
    "usage: bash $SELF confirm <pr-number> [--yes --head SHA]" \
    "       bash $SELF actions-policy [--yes --repo OWNER/NAME]" \
    "" \
    "  confirm         confirm the protected changes of a pull request (SG-TRUST-001)" \
    "  actions-policy  set P-A in a public repository: the gate's workflow may run on" \
    "                  pull_request_target, and on no other event" \
    "  --yes     do not prompt; required when there is no terminal; needs --head (confirm)" \
    "            or --repo (actions-policy)" \
    "  --head    the full commit id of the head you reviewed; refuse if the head moved" \
    "  --repo    OWNER/NAME of the repository you mean; refuse if this clone is of another"
}

cmd_confirm() {
  local pr="" yes=0 reviewed=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --yes) yes=1 ;;
      --head)
        [ $# -ge 2 ] || fail 2 "--head needs a value"
        reviewed=$2
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

  local repo default state head_sha base_sha
  repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner) || fail 2 "$NO_REPO"
  is_owner_repo "$repo" || fail 2 "unexpected repository name from gh"
  default=$(gh repo view "$repo" --json defaultBranchRef --jq .defaultBranchRef.name) || fail 2 "gh cannot read the default branch"
  is_branch_name "$default" || fail 2 "unexpected default branch name from gh"
  state=$(gh pr view "$pr" --repo "$repo" --json state --jq .state) || fail 2 "gh cannot read pull request #$pr"
  [ "$state" = OPEN ] || fail 4 "pull request #$pr is $state, not OPEN"
  head_sha=$(gh pr view "$pr" --repo "$repo" --json headRefOid --jq .headRefOid) || fail 2 "gh cannot read the head of #$pr"
  [[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 2 "unexpected head commit id from gh"
  if [ -n "$reviewed" ] && [ "$head_sha" != "$reviewed" ]; then
    fail 4 "the head of #$pr is now $head_sha, not the $reviewed you reviewed; review the new commits, then run again with --head $head_sha"
  fi

  TMP_DIR=$(mktemp -d)
  local tmp=$TMP_DIR
  fetch_own_copy "$repo" "$default and #$pr" "+refs/heads/$default:refs/security-gate/default" "+refs/pull/$pr/head:refs/security-gate/pr-$pr"
  [ "$(own_git rev-parse --verify --quiet "refs/security-gate/pr-$pr^{commit}")" = "$head_sha" ] || fail 4 "the head of #$pr that git got from GitHub is not the one GitHub reports; run again"
  base_sha=$(own_git rev-parse --verify --quiet "refs/security-gate/default^{commit}") || fail 2 "git got no commit for $default"

  own_git cat-file blob "$base_sha:$GATE" > "$tmp/gate.py" 2>/dev/null || fail 4 "$GATE is not on $default: merge the onboarding first"
  own_git cat-file blob "$base_sha:$SELF" > "$tmp/human.sh" 2>/dev/null || fail 4 "$SELF is not on $default"
  cmp -s "$tmp/human.sh" "$SCRIPT" || fail 4 "this human.sh differs from the one on $default; run the copy from $default"

  python3 -I "$tmp/gate.py" protected-diff --repo "$tmp/repo.git" --default "$base_sha" --head "$head_sha" > "$tmp/report" || fail 2 "gate.py could not compute the protected changes"
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
  python3 -I "$tmp/gate.py" protected-diff --repo "$tmp/repo.git" --default "$base_sha" --head "$head_sha" --patch > "$tmp/patch" || fail 2 "gate.py could not show the diff"
  if [ "$yes" -eq 1 ]; then
    printf '\nThe full diff (control characters are escaped):\n'
    sed -n 'p' "$tmp/patch"
    printf '\n--yes: setting %s on %s to\n  %s\n' "$VARIABLE" "$repo" "$fp"
  else
    printf '\nPress Enter to read the full diff (control characters are escaped).'
    read -r _ || fail 1 "no answer; nothing was changed"
    if command -v less >/dev/null 2>&1; then
      # -F: a diff that fits on one screen is printed and less exits at once.
      # -X: the diff stays on screen after less exits. -K: Ctrl+C leaves less.
      printf '\n(Long diffs open in less: arrow keys scroll, q closes it.\n If q does nothing, switch the keyboard to the Latin layout.)\n'
      less -FXK "$tmp/patch" || true
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

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# OWNER/NAME of a GitHub repository; a name is never . or ..
is_owner_repo() {
  [[ "$1" =~ $OWNER_REPO_RE && "$1" != */. && "$1" != */.. ]]
}

# A branch name this script puts into a refspec.
is_branch_name() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$ && "$1" != *..* ]]
}

# git on the script's own bare repository in $TMP_DIR, run from there and
# never on the clone the script was started in (see the top of this file):
# no hooks, no fsmonitor, no system configuration, no prompt.
own_git() {
  GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 git -C "$TMP_DIR" --git-dir="$TMP_DIR/repo.git" \
    -c core.hooksPath=/dev/null -c core.fsmonitor=false "$@"
}

# Fetch the refspecs from the URL GitHub gives for repository $1 into the
# script's own bare repository; $2 says what for an error message. gh is the
# only credential helper of that fetch.
fetch_own_copy() {
  local repo=$1 what=$2 url
  shift 2
  url=$(gh repo view "$repo" --json url --jq .url) || fail 2 "gh cannot read the URL of $repo"
  [[ "$url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/[^/]+/[^/]+$ && "$(lower "${url#https://*/}")" = "$(lower "$repo")" ]] \
    || fail 2 "unexpected URL of $repo from gh"
  GIT_CONFIG_NOSYSTEM=1 git -C "$TMP_DIR" init --quiet --bare --template= repo.git || fail 2 "git cannot create a repository in $TMP_DIR"
  own_git -c credential.helper= -c 'credential.helper=!gh auth git-credential' fetch --quiet --no-tags "$url" "$@" \
    || fail 2 "git cannot get $what from $url"
}

# The HTTP status of a failed gh api call, from the line gh prints on stderr
# ("gh: Not Found (HTTP 404)"). GitHub's own message is not printed.
http_status() {
  local status
  status=$(sed -n 's/.*(HTTP \([0-9][0-9][0-9]\)).*/\1/p' "$1" | sed -n '1p')
  printf '%s' "${status:-none}"
}

# The repository's Actions policies, those set above it included, into $2.
get_policies() {
  local repo=$1 out=$2 err=$3 status
  if gh api --method GET -H "$POLICY_API" "repos/$repo/actions/policies?per_page=100" > "$out" 2> "$err"; then
    return 0
  fi
  status=$(http_status "$err")
  case "$status" in
    403 | 404) fail 2 "gh cannot read the Actions policies of $repo (HTTP $status): run this with a GitHub login that has admin access to $repo" ;;
    *) fail 2 "gh cannot read the Actions policies of $repo (HTTP $status)" ;;
  esac
}

# gate.py's report on the repository's Actions policies, into $2/report. The
# list gives only a summary of each policy (no conditions, no rules), so each
# listed policy is read by id as well, into $2/by-id/<id>.json, or an empty
# <id>.404 when GitHub does not show it by id (as it may for a policy set
# above the repository). gate.py judges from these answers only.
judge_policies() {
  local repo=$1 dir=$2 id
  mkdir -- "$dir" "$dir/by-id"
  get_policies "$repo" "$dir/list.json" "$dir/gh.err"
  python3 -I "$TMP_DIR/gate.py" actions-policy --ids "$dir/list.json" > "$dir/ids" || fail 2 "gate.py could not read the Actions policies of $repo"
  while IFS= read -r id; do
    [[ "$id" =~ ^[1-9][0-9]{0,18}$ ]] || fail 2 "gate.py returned no policy id"
    if gh api --method GET -H "$POLICY_API" "repos/$repo/actions/policies/$id" > "$dir/answer" 2> "$dir/gh.err"; then
      mv -- "$dir/answer" "$dir/by-id/$id.json"
    elif [ "$(http_status "$dir/gh.err")" = 404 ]; then
      : > "$dir/by-id/$id.404"
    else
      fail 2 "gh cannot read policy #$id of $repo (HTTP $(http_status "$dir/gh.err"))"
    fi
  done < "$dir/ids"
  python3 -I "$TMP_DIR/gate.py" actions-policy --list "$dir/list.json" --details "$dir/by-id" > "$dir/report" || fail 2 "gate.py could not read the Actions policies of $repo"
}

cmd_actions_policy() {
  local yes=0 named=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --yes) yes=1 ;;
      --repo)
        [ $# -ge 2 ] || fail 2 "--repo needs a value"
        named=$2
        shift
        ;;
      -h | --help) usage; exit 0 ;;
      *) fail 2 "unknown argument: $1" ;;
    esac
    shift
  done
  if [ "$yes" -eq 1 ] && [ -z "$named" ]; then
    fail 2 "--yes needs --repo OWNER/NAME, the repository you mean"
  fi
  if [ -n "$named" ] && ! is_owner_repo "$named"; then
    fail 2 "--repo must be OWNER/NAME"
  fi
  if [ "$yes" -eq 0 ] && { [ ! -t 0 ] || [ ! -t 1 ]; }; then
    fail 2 "no terminal. Run this yourself in a terminal, or pass --yes --repo OWNER/NAME to do it without a prompt."
  fi
  local tool
  for tool in git gh python3; do
    command -v "$tool" >/dev/null 2>&1 || fail 2 "$tool is not installed"
  done

  local repo visibility default
  repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner) || fail 2 "$NO_REPO"
  is_owner_repo "$repo" || fail 2 "unexpected repository name from gh"
  if [ -n "$named" ] && [ "$(lower "$named")" != "$(lower "$repo")" ]; then
    fail 4 "this clone is of $repo, not $named; nothing was changed"
  fi
  visibility=$(gh repo view "$repo" --json visibility --jq .visibility) || fail 2 "gh cannot read the visibility of $repo"
  case "$visibility" in
    PUBLIC) ;;
    PRIVATE | INTERNAL)
      printf '%s is %s. GitHub blocks pull_request_target by default only in public\n' "$repo" "$(lower "$visibility")"
      printf 'repositories, so the gate needs no Actions policy here. Nothing was changed.\n'
      exit 0
      ;;
    *) fail 2 "unexpected visibility of $repo from gh" ;;
  esac
  default=$(gh repo view "$repo" --json defaultBranchRef --jq .defaultBranchRef.name) || fail 2 "gh cannot read the default branch"
  is_branch_name "$default" || fail 2 "unexpected default branch name from gh"

  TMP_DIR=$(mktemp -d)
  local tmp=$TMP_DIR
  fetch_own_copy "$repo" "$default" "+refs/heads/$default:refs/security-gate/default"
  own_git cat-file blob "refs/security-gate/default:$GATE" > "$tmp/gate.py" 2>/dev/null || fail 4 "$GATE is not on $default: merge the onboarding first"
  own_git cat-file blob "refs/security-gate/default:$SELF" > "$tmp/human.sh" 2>/dev/null || fail 4 "$SELF is not on $default"
  cmp -s "$tmp/human.sh" "$SCRIPT" || fail 4 "this human.sh differs from the one on $default; run the copy from $default"
  python3 -I "$tmp/gate.py" actions-policy --body > "$tmp/body.json" || fail 2 "the gate.py on $default cannot write P-A"

  judge_policies "$repo" "$tmp/before"
  local state policy verb
  state=$(sed -n 's/^state=//p' "$tmp/before/report")
  policy=$(sed -n 's/^policy=//p' "$tmp/before/report")
  printf 'Repository: %s (public, default branch %s)\n' "$repo" "$default"
  sed -n 's/^blocks: /May stop the gate:/p; s/^note: /Note:/p' "$tmp/before/report"
  case "$state" in
    correct)
      [[ "$policy" =~ ^[1-9][0-9]{0,18}$ ]] || fail 2 "gate.py returned no policy id"
      printf 'P-A is in place: policy #%s. Nothing to change.\n' "$policy"
      exit 0
      ;;
    blocked) fail 4 "P-A cannot lift another policy's block: change the policies above in the settings of $repo (Actions, Policies), or ask the owner of the organization that set them; then run again. Nothing was changed." ;;
    ambiguous) fail 4 "several policies of $repo have the name of P-A: delete all but one in its settings (Actions, Policies), then run again. Nothing was changed." ;;
    absent)
      verb=create
      printf '\nThis creates P-A on %s:\n' "$repo"
      ;;
    differs)
      [[ "$policy" =~ ^[1-9][0-9]{0,18}$ ]] || fail 2 "gate.py returned no policy id"
      verb=update
      printf '\nPolicy #%s has the name of P-A, but its\n' "$policy"
      sed -n 's/^differs://p' "$tmp/before/report"
      printf 'This updates policy #%s on %s to P-A:\n' "$policy" "$repo"
      ;;
    *) fail 2 "gate.py returned no decision" ;;
  esac
  sed -n 'p' "$tmp/body.json"
  printf '\nP-A targets only %s and lets it run on\n' "$WORKFLOW"
  printf 'pull_request_target and on no other event. It allows nothing to any other\n'
  printf 'workflow and changes no other policy. Whether GitHub'"'"'s default block still\n'
  printf 'stops other workflows on pull_request_target while P-A exists is not proven.\n'
  if [ "$yes" -eq 1 ]; then
    printf '\n--yes: %s P-A on %s\n' "$verb" "$repo"
  else
    printf '\nType yes to %s it: ' "$verb"
    local answer
    read -r answer || fail 1 "no answer; nothing was changed"
    [ "$answer" = yes ] || fail 1 "not confirmed; nothing was changed"
  fi

  if [ "$verb" = create ]; then
    gh api --method POST -H "$POLICY_API" "repos/$repo/actions/policies" --input "$tmp/body.json" \
      > "$tmp/written.json" 2> "$tmp/gh.err" \
      || fail 2 "gh could not create P-A on $repo (HTTP $(http_status "$tmp/gh.err")): admin access is needed"
  else
    gh api --method PUT -H "$POLICY_API" "repos/$repo/actions/policies/$policy" --input "$tmp/body.json" \
      > "$tmp/written.json" 2> "$tmp/gh.err" \
      || fail 2 "gh could not update policy #$policy on $repo (HTTP $(http_status "$tmp/gh.err")): admin access is needed"
  fi
  python3 -I "$tmp/gate.py" actions-policy --policy "$tmp/written.json" > "$tmp/written" || fail 2 "GitHub did not answer with a policy; check the settings of $repo (Actions, Policies)"
  local id
  id=$(sed -n 's/^policy=//p' "$tmp/written")
  [[ "$id" =~ ^[1-9][0-9]{0,18}$ ]] || fail 2 "GitHub answered without a policy id"
  if [ "$verb" = update ] && [ "$id" != "$policy" ]; then
    fail 2 "GitHub answered with policy #$id, not #$policy"
  fi
  # Read it back: the policy alone, then all of them, which must show it as P-A.
  gh api --method GET -H "$POLICY_API" "repos/$repo/actions/policies/$id" > "$tmp/back.json" 2> "$tmp/gh.err" \
    || fail 2 "gh cannot read policy #$id back (HTTP $(http_status "$tmp/gh.err"))"
  python3 -I "$tmp/gate.py" actions-policy --policy "$tmp/back.json" > "$tmp/back" || fail 2 "policy #$id does not read back as a policy"
  if [ "$(sed -n 's/^state=//p' "$tmp/back")" != correct ] || [ "$(sed -n 's/^policy=//p' "$tmp/back")" != "$id" ]; then
    sed -n 's/^differs://p' "$tmp/back"
    fail 2 "policy #$id does not read back as written; check it in the settings of $repo (Actions, Policies)"
  fi
  judge_policies "$repo" "$tmp/after"
  if [ "$(sed -n 's/^state=//p' "$tmp/after/report")" != correct ] || [ "$(sed -n 's/^policy=//p' "$tmp/after/report")" != "$id" ]; then
    fail 2 "the Actions policies of $repo do not show policy #$id as P-A"
  fi
  printf 'P-A is set: policy #%s on %s, read back and checked.\n' "$id" "$repo"
  printf 'The next gate run on a pull request shows that the gate still starts.\n'
}

main() {
  refuse_agent_host
  [ $# -ge 1 ] || { usage >&2; exit 2; }
  local cmd=$1
  shift
  case "$cmd" in
    confirm) cmd_confirm "$@" ;;
    actions-policy) cmd_actions_policy "$@" ;;
    -h | --help | help) usage ;;
    *) usage >&2; exit 2 ;;
  esac
}

main "$@"
