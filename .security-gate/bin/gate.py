# managed-by: security-gate v0.1.0-p0 (owned)
"""security-gate: the pull request gate. Standard library only, Python 3.11+.

The owned workflow .github/workflows/security-gate.yml runs this file from a
checkout of the default branch:

    python3 -I gate/.security-gate/bin/gate.py pr --trusted gate --tree pr

Exit codes: 0 pass, 1 fail, 2 inconclusive. Anything but 0 fails the job, and
with it the security-gate check run on the head of the pull request.

Trust rules:
- this code comes from the default branch (--trusted), never from the pull
  request;
- the pull request (--tree) is read only as git objects of its head commit:
  rev-parse, merge-base, ls-tree, diff-tree, cat-file. Git runs with an empty
  private work tree, no global or system config, no attributes, no textconv or
  external diff, no replace objects and no network. Files of the checked-out
  work tree are never opened, and nothing from the pull request is executed;
- the gate has no token and calls no API.

The verdict of this version:
- self-check: the run is the owned workflow on pull_request_target from the
  default branch, on a GitHub-hosted runner;
- SG-TRUST-001: the protected files (.github/workflows/ and .security-gate/,
  except state.json) of the head are compared with those of the default branch
  tip, not of a merge base. Any difference is inconclusive, unless the
  fingerprint of the protected files in the head equals the repository
  variable SECURITY_GATE_CONFIG, which only a human sets (human.sh confirm).
  A merge base is not used: with several best common ancestors (criss-cross
  history) git picks one, and a head that carries the tree of that one can
  hide a deletion that the merge then applies. When the head and the default
  branch agree on every protected path, the merge leaves those paths as they
  are on the default branch, whatever the base. A symlink or submodule on a
  protected path is inconclusive and cannot be confirmed: its content lives
  outside the protected set;
- gate-integrity, the built-in rules: the drill canary, symlinks that dangle
  or point outside the repository, submodules and Git LFS pointers (content
  not in the repository, not scanned). Two canaries planted by the gate itself
  prove that the rules saw the tree.

Third-party scanners (gitleaks, osv-scanner, semgrep, zizmor) are not run by
this version. They will run in containers without network on a read-only
mount of the head tree, each adding one entry to TOOLS. zizmor_post_filter
below is the filter the zizmor entry will use.

Subcommands for human.sh:
    gate.py fingerprint --repo DIR --commit REV
    gate.py protected-diff --repo DIR --default REV --head REV [--patch]
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import posixpath
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

GATE_VERSION = "0.1.0-p0"
RECEIPT_SCHEMA = "security-gate/receipt"
RECEIPT_SCHEMA_VERSION = 1
FINGERPRINT_SCHEMA = "security-gate/fingerprint"
FINGERPRINT_SCHEMA_VERSION = 1

EVENT = "pull_request_target"
WORKFLOW_PATH = ".github/workflows/security-gate.yml"
GATE_PATH = ".security-gate/bin/gate.py"
CONFIG_VARIABLE = "SECURITY_GATE_CONFIG"
RECEIPT_ARTIFACT = "security-gate-receipt"

# The protected set. Paths are compared in lower case, so a case variant of a
# protected directory is protected too. A non-directory entry on the way to a
# protected directory (".github" as a symlink) is protected as well.
PROTECTED_DIRS = (".github/workflows", ".security-gate")
NOT_PROTECTED = frozenset({".security-gate/state.json"})
LINK_MODE = "120000"

PASS, FAIL, INCONCLUSIVE = "pass", "fail", "inconclusive"
EXIT = {PASS: 0, FAIL: 1, INCONCLUSIVE: 2}
FAIL_CODES = frozenset({"finding", "exception_expired"})

# The drill canary: "security-gate-canary:v1:" and 32 lowercase hex digits.
# It is assembled here so that this file never contains a canary itself.
CANARY_RULE = "security-gate-canary"
CANARY_PREFIX = (CANARY_RULE + ":v1:").encode()
CANARY_RE = re.compile(re.escape(CANARY_PREFIX) + rb"[0-9a-f]{32}")
CANARY_LEN = len(CANARY_PREFIX) + 32

RULES = (
    (CANARY_RULE, "high", "drill canary in a file of the head tree"),
    ("security-gate-symlink-dangling", "medium", "symlink whose target is not in the head tree"),
    ("security-gate-symlink-escape", "medium", "symlink with an absolute target or one outside the repository"),
    ("security-gate-submodule", "medium", "submodule: its content is not in this repository and is not scanned"),
    ("security-gate-lfs", "medium", "Git LFS pointer: the content is not in this repository and is not scanned"),
)
SEVERITY = {rule: sev for rule, sev, _ in RULES}

# A Git LFS pointer file (git-lfs spec v1, and the older hawser prefix). The
# spec keeps pointers under 1024 bytes; a larger file is not a pointer, and its
# content is in the repository and scanned like any other file.
LFS_PREFIXES = (b"version https://git-lfs.github.com/spec/", b"version https://hawser.github.com/spec/v1")
LFS_MAX_POINTER = 1024

MAX_ITEMS = 500
MAX_SHOWN = 20
CHUNK = 1 << 20
MAX_LINK_TARGET = 4096
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical(obj: object) -> bytes:
    """Canonical JSON, as for document hashes in docs/contracts/README.md."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def shown(text: str) -> str:
    """A repository path or other untrusted text, safe to print: quoted, with
    control and invisible format characters escaped. A path with a newline
    therefore cannot start a line, and so cannot inject a workflow command."""
    out = []
    for ch in text:
        if ch in "\"\\":
            out.append("\\" + ch)
        elif ch.isprintable() and unicodedata.category(ch) != "Cf":
            out.append(ch)
        elif ord(ch) < 0x100:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}" if ord(ch) < 0x10000 else f"\\U{ord(ch):08x}")
    return '"' + "".join(out) + '"'


def is_protected(path: str) -> bool:
    if path in NOT_PROTECTED:
        return False
    low = path.lower()
    return any(low == d or low.startswith(d + "/") or d.startswith(low + "/") for d in PROTECTED_DIRS)


# ---------------------------------------------------------------------------
# Git, objects only
# ---------------------------------------------------------------------------

class GitError(Exception):
    pass


_GIT_CONFIG = (
    "core.quotePath=false", "core.fsmonitor=false", "core.hooksPath=" + os.devnull,
    "core.attributesFile=" + os.devnull, "diff.external=", "diff.noprefix=false", "core.pager=cat",
    "protocol.allow=never", "credential.helper=", "gc.auto=0", "maintenance.auto=false",
)


@dataclass(frozen=True)
class Entry:
    mode: str
    kind: str      # blob or commit (a submodule)
    oid: str
    path: str


@dataclass
class Blob:
    size: int = 0
    sha256: str = ""
    canary_lines: list[int] = field(default_factory=list)
    head: bytes = b""


class Git:
    """One repository, read through its object database only."""

    def __init__(self, repo: Path, scratch: Path) -> None:
        self.scratch = scratch
        worktree = scratch / "empty-worktree"
        worktree.mkdir(parents=True, exist_ok=True)
        home = scratch / "home"
        home.mkdir(parents=True, exist_ok=True)
        keep = {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "TMPDIR")}
        self.environ = dict(keep, HOME=str(home), LC_ALL="C", GIT_CONFIG_NOSYSTEM="1",
                            GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM="1", GIT_NO_REPLACE_OBJECTS="1",
                            GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_NO_LAZY_FETCH="1",
                            GIT_ADVICE="0")
        repo = Path(repo).absolute()
        # The ceiling stops git from taking a parent directory's repository.
        probe = dict(self.environ, GIT_CEILING_DIRECTORIES=str(repo.parent))
        proc = subprocess.run(["git", "-C", str(repo), "rev-parse", "--absolute-git-dir"], capture_output=True,
                              timeout=60, check=False, env=probe)
        if proc.returncode != 0:
            raise GitError("not a git repository")
        git_dir = proc.stdout.decode("utf-8", "surrogateescape").strip()
        self.prefix = ["git", "--git-dir=" + git_dir, "--work-tree=" + str(worktree), "--literal-pathspecs"]
        for item in _GIT_CONFIG:
            self.prefix += ["-c", item]

    def run(self, *args: str, data: bytes | None = None, ok: tuple[int, ...] = (0,)) -> bytes:
        try:
            proc = subprocess.run(self.prefix + list(args), input=data, capture_output=True, timeout=600,
                                  check=False, env=self.environ)
        except (OSError, subprocess.SubprocessError) as exc:
            raise GitError(f"git {args[0]} could not run: {type(exc).__name__}") from None
        if proc.returncode not in ok:
            raise GitError(f"git {args[0]} exited {proc.returncode}")
        return proc.stdout

    def rev(self, rev: str) -> str:
        out = self.run("rev-parse", "--verify", "--end-of-options", rev + "^{commit}").decode().strip()
        if not SHA1_RE.match(out):
            raise GitError("rev-parse did not return a SHA-1 commit id")
        return out

    def object_format(self) -> str:
        return self.run("rev-parse", "--show-object-format").decode().strip()

    def merge_base(self, a: str, b: str) -> str | None:
        out = self.run("merge-base", a, b, ok=(0, 1)).decode().strip()
        return out or None

    def merge_bases(self, a: str, b: str) -> list[str]:
        """Every best common ancestor: a criss-cross history has more than one."""
        return self.run("merge-base", "--all", a, b, ok=(0, 1)).decode().split()

    def count(self, a: str, b: str) -> int:
        return int(self.run("rev-list", "--count", f"{a}..{b}").decode().strip())

    def tree(self, commit: str) -> list[tuple[str, str, str, bytes]]:
        """(mode, kind, oid, raw path) of every non-tree entry."""
        out = self.run("ls-tree", "-r", "-z", "--full-tree", commit)
        result = []
        for rec in out.split(b"\0"):
            if not rec:
                continue
            meta, _, raw = rec.partition(b"\t")
            mode, kind, oid = meta.decode("ascii").split(" ")
            result.append((mode, kind, oid, raw))
        return result

    def changes(self, a: str, b: str) -> list[tuple[str, bytes]]:
        """(status, raw path) for every changed non-tree entry, renames split."""
        out = self.run("diff-tree", "-r", "--no-renames", "--no-ext-diff", "--no-textconv", "--name-status",
                       "-z", a, b)
        parts = out.split(b"\0")
        if parts and parts[-1] == b"":
            parts.pop()
        if len(parts) % 2:
            raise GitError("diff-tree output is not status/path pairs")
        return [(parts[i].decode("ascii"), parts[i + 1]) for i in range(0, len(parts), 2)]

    def write_blob(self, data: bytes) -> str:
        return self.run("hash-object", "-w", "--no-filters", "--stdin", data=data).decode().strip()

    def patch(self, a: str, b: str, paths: list[str]) -> bytes:
        return self.run("diff", "--no-color", "--text", "--no-ext-diff", "--no-textconv", "--no-renames",
                        a, b, "--", *paths)

    def blobs(self, oids: list[str]) -> dict[str, Blob]:
        """Stream every blob once through cat-file --batch: size, sha256, the
        line numbers of canaries, and the first bytes (for symlink targets)."""
        result: dict[str, Blob] = {}
        if not oids:
            return result
        proc = subprocess.Popen(self.prefix + ["cat-file", "--batch"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=self.environ)

        def feed() -> None:
            try:
                for oid in oids:
                    proc.stdin.write(oid.encode() + b"\n")
                proc.stdin.close()
            except OSError:
                pass

        writer = threading.Thread(target=feed, daemon=True)
        writer.start()
        try:
            for oid in oids:
                header = proc.stdout.readline().split()
                if len(header) != 3 or header[0].decode() != oid or header[1] != b"blob":
                    raise GitError("cat-file did not return the requested blob")
                size = int(header[2])
                blob = Blob(size=size)
                digest = hashlib.sha256()
                remaining = size
                tail, nl_before = b"", 0
                while remaining:
                    chunk = proc.stdout.read(min(CHUNK, remaining))
                    if not chunk:
                        raise GitError("cat-file output ended early")
                    remaining -= len(chunk)
                    digest.update(chunk)
                    if len(blob.head) < MAX_LINK_TARGET + 1:
                        blob.head += chunk[:MAX_LINK_TARGET + 1 - len(blob.head)]
                    buf = tail + chunk
                    for m in CANARY_RE.finditer(buf):
                        blob.canary_lines.append(1 + nl_before + buf.count(b"\n", 0, m.start()))
                    cut = max(0, len(buf) - (CANARY_LEN - 1))
                    nl_before += buf.count(b"\n", 0, cut)
                    tail = buf[cut:]
                if proc.stdout.read(1) != b"\n":
                    raise GitError("cat-file output is not terminated")
                blob.sha256 = "sha256:" + digest.hexdigest()
                result[oid] = blob
        finally:
            proc.stdout.close()
            code = proc.wait(timeout=600)
            writer.join(timeout=60)
        if code != 0:
            raise GitError(f"git cat-file exited {code}")
        return result


# ---------------------------------------------------------------------------
# Fingerprint of the protected set
# ---------------------------------------------------------------------------

def decode_entries(raw: list[tuple[str, str, str, bytes]]) -> tuple[list[Entry], list[bytes]]:
    good, bad = [], []
    for mode, kind, oid, path in raw:
        try:
            good.append(Entry(mode, kind, oid, path.decode("utf-8")))
        except UnicodeDecodeError:
            bad.append(path)
    return good, bad


def fingerprint(entries: list[Entry], blobs: dict[str, Blob]) -> str:
    """sha256 of the canonical JSON of [path, mode, content sha256] for every
    protected entry, sorted by path. A submodule contributes its commit id."""
    rows = []
    for e in sorted((e for e in entries if is_protected(e.path)), key=lambda e: e.path):
        rows.append([e.path, e.mode, blobs[e.oid].sha256 if e.kind == "blob" else "commit:" + e.oid])
    doc = {"schema": FINGERPRINT_SCHEMA, "schema_version": FINGERPRINT_SCHEMA_VERSION, "entries": rows}
    return sha256_hex(canonical(doc))


def protected_blob_oids(entries: list[Entry]) -> list[str]:
    return sorted({e.oid for e in entries if e.kind == "blob" and is_protected(e.path)})


def protected_changes(git: Git, default: str, head: str) -> tuple[list[tuple[str, str]], list[bytes]]:
    """(status, path) of every protected path where the head differs from the
    default branch tip (two-dot, never a merge base), and the raw changed
    paths that are not UTF-8."""
    changed, bad = [], []
    for status, raw in git.changes(default, head):
        try:
            path = raw.decode("utf-8")
        except UnicodeDecodeError:
            bad.append(raw)
            continue
        if is_protected(path):
            changed.append((status, path))
    return sorted(changed, key=lambda c: c[1]), bad


def unconfirmable(entries: list[Entry]) -> list[str]:
    """Protected paths that are symlinks or submodules. The fingerprint sees
    only the link text or the commit id, not the content behind it, so no
    confirmation can cover them."""
    return sorted(e.path for e in entries if is_protected(e.path) and (e.mode == LINK_MODE or e.kind == "commit"))


def behind(git: Git, default: str, head: str) -> list[str]:
    """Protected paths the default branch changed after the head branched off,
    from any of its merge bases. Only used to explain an inconclusive verdict:
    the head then lacks a protected change that is already on the default
    branch, and has to take it in first."""
    paths = set()
    for base in git.merge_bases(default, head):
        for _, raw in git.changes(base, default):
            path = raw.decode("utf-8", "backslashreplace")
            if is_protected(path):
                paths.add(path)
    return sorted(paths)


def parse_config(value: str | None) -> tuple[set[str], bool]:
    """Confirmed fingerprints from SECURITY_GATE_CONFIG, and whether the value
    is well formed. The value itself is never printed."""
    text = (value or "").strip()
    if not text:
        return set(), True
    if FINGERPRINT_RE.match(text):
        return {text}, True
    return set(), False


# ---------------------------------------------------------------------------
# gate-integrity: built-in rules on the head tree
# ---------------------------------------------------------------------------

def resolve_link(path: str, target: bytes, links: dict[str, bytes], names: set[str], dirs: set[str],
                 depth: int = 0) -> str:
    """'ok', 'dangling' or 'escape' for a symlink, resolved lexically inside
    the head tree. Nothing on disk is looked at."""
    if depth > 40 or len(target) > MAX_LINK_TARGET:
        return "dangling"
    try:
        text = target.decode("utf-8")
    except UnicodeDecodeError:
        return "dangling"
    if text.startswith("/"):
        return "escape"
    parts = [p for p in posixpath.dirname(path).split("/") if p]
    comps = [c for c in text.split("/") if c not in ("", ".")]
    for i, comp in enumerate(comps):
        if comp == "..":
            if not parts:
                return "escape"
            parts.pop()
            continue
        parts.append(comp)
        current = "/".join(parts)
        if current in links:
            rest = "/".join(comps[i + 1:])
            inner = links[current]
            joined = inner + (b"/" + rest.encode() if rest else b"")
            return resolve_link(current, joined, links, names, dirs, depth + 1)
    final = "/".join(parts)
    return "ok" if final == "" or final in names or final in dirs else "dangling"


def finding(rule: str, path: str, line: int | None) -> dict:
    return {"rule": rule, "path": path, "line": line, "severity": SEVERITY[rule],
            "fingerprint": sha256_hex(canonical([rule, path, line]))}


def gate_integrity(git: Git, entries: list[Entry], blobs: dict[str, Blob], self_file: bytes) -> dict:
    start = time.monotonic()
    nonce = os.urandom(16).hex()
    canary_oid = git.write_blob(b"drill\n" + CANARY_PREFIX + nonce.encode() + b"\n")
    link_oid = git.write_blob(("security-gate-missing-" + nonce).encode())
    planted = git.blobs([canary_oid, link_oid])

    files = [e for e in entries if e.kind == "blob" and not e.mode.startswith("120")]
    links = {e.path: blobs[e.oid].head for e in entries if e.kind == "blob" and e.mode.startswith("120")}
    names = {e.path for e in entries}
    dirs = {"/".join(e.path.split("/")[:i]) for e in entries for i in range(1, e.path.count("/") + 1)}

    items = []
    for e in files:
        for line in blobs[e.oid].canary_lines:
            items.append(finding(CANARY_RULE, e.path, line))
    for path in sorted(links):
        state = resolve_link(path, links[path], links, names, dirs)
        if state != "ok":
            items.append(finding("security-gate-symlink-" + state, path, None))
    for e in entries:
        if e.kind == "commit":
            items.append(finding("security-gate-submodule", e.path, None))
    for e in files:
        blob = blobs[e.oid]
        if blob.size < LFS_MAX_POINTER and blob.head.startswith(LFS_PREFIXES):
            items.append(finding("security-gate-lfs", e.path, None))

    canary_path = "\0planted-link"   # NUL cannot occur in a git path: no clash
    canaries = [
        {"id": "gate-integrity-file", "expected_rule": CANARY_RULE, "found": bool(planted[canary_oid].canary_lines)},
        {"id": "gate-integrity-symlink", "expected_rule": "security-gate-symlink-dangling",
         "found": resolve_link(canary_path, planted[link_oid].head, links, names, dirs) == "dangling"},
    ]
    by_severity = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for item in items:
        by_severity[item["severity"]] += 1
    reasons = []
    if items:
        outcome, code = FAIL, "finding"
        listed = "; ".join(i["rule"] + " " + shown(i["path"]) + (f":{i['line']}" if i["line"] else "")
                           for i in items[:MAX_SHOWN])
        reasons.append(("finding", f"{len(items)} finding(s): {listed}" + (" ..." if len(items) > MAX_SHOWN else "")))
    else:
        outcome, code = PASS, None
    missed = [c["id"] for c in canaries if not c["found"]]
    if missed:
        reasons.append(("canary_missed", "planted canaries not found: " + ", ".join(missed)))
    if not files:
        reasons.append(("zero_scanned", "no regular file in the head tree"))
    if outcome == PASS and reasons:
        outcome, code = INCONCLUSIVE, reasons[0][0]
    rules_doc = [[rule, sev, desc] for rule, sev, desc in RULES] + [CANARY_PREFIX.decode(), CANARY_LEN,
                                                                     [p.decode() for p in LFS_PREFIXES], LFS_MAX_POINTER]
    receipt = {
        "name": "gate-integrity",
        "version": GATE_VERSION,
        "artifact": {"kind": "binary", "ref": GATE_PATH, "sha256": sha256_hex(self_file)},
        "argv": [],
        "network": "none",
        "rules_loaded": len(RULES),
        "rules_sha256": sha256_hex(canonical(rules_doc)),
        "scanned": {"files": len(files), "commits": None, "packages": None, "paths": [""],
                    "paths_truncated": False, "lockfiles": []},
        "canaries": canaries,
        "exit_code": 1 if items or any(c["found"] for c in canaries) else 0,
        "stderr_markers": [],
        "retried": False,
        "findings": {"total": len(items), "by_severity": by_severity, "items": items[:MAX_ITEMS],
                     "truncated": len(items) > MAX_ITEMS},
        "outcome": outcome,
        "reason_code": code,
        "duration_s": int(time.monotonic() - start),
    }
    return {"receipt": receipt, "reasons": reasons}


# Every tool the gate runs, in order. Container scanners join here later.
TOOLS = (("gate-integrity", gate_integrity),)


# ---------------------------------------------------------------------------
# zizmor post-filter (ADR 0003, 3.5, item 5)
# ---------------------------------------------------------------------------

def _zizmor_paths(item: object) -> set[str] | None:
    if not isinstance(item, dict) or not isinstance(item.get("locations"), list) or not item["locations"]:
        return None
    paths = set()
    for loc in item["locations"]:
        try:
            path = loc["symbolic"]["key"]["Local"]["verbatim_path"]
        except (KeyError, TypeError):
            return None
        if not isinstance(path, str):
            return None
        paths.add(path.removeprefix("./"))
    return paths


def zizmor_post_filter(findings: list, owned: bytes | None, reference: bytes | None,
                       confirmed: bool) -> tuple[list, list]:
    """Remove exactly one zizmor finding: dangerous-triggers located only in
    the owned workflow, when that file is byte for byte the reference (the
    default branch version, or the template in this repository's own CI) or
    its fingerprint was confirmed by a human. Anything else is kept, so two
    such findings, a renamed audit or a changed file stay red."""
    candidates = [i for i, item in enumerate(findings)
                  if isinstance(item, dict) and item.get("ident") == "dangerous-triggers"
                  and _zizmor_paths(item) == {WORKFLOW_PATH}]
    if len(candidates) != 1 or owned is None:
        return list(findings), []
    if reference is not None and owned == reference:
        basis = "same_as_default"
    elif confirmed:
        basis = "confirmed_fingerprint"
    else:
        return list(findings), []
    kept = [item for i, item in enumerate(findings) if i != candidates[0]]
    return kept, [{"tool": "zizmor", "rule": "dangerous-triggers", "path": WORKFLOW_PATH, "basis": basis,
                   "file_sha256": sha256_hex(owned)}]


# ---------------------------------------------------------------------------
# The pull request verdict
# ---------------------------------------------------------------------------

def _int_or_none(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() else None


def new_receipt() -> dict:
    g = os.environ.get
    return {
        "schema": RECEIPT_SCHEMA,
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "mode": "pr",
        "run": {"repository": g("GITHUB_REPOSITORY"), "event": g("GITHUB_EVENT_NAME"),
                "workflow_ref": g("GITHUB_WORKFLOW_REF"),
                "workflow_sha": g("GITHUB_WORKFLOW_SHA") if SHA1_RE.match(g("GITHUB_WORKFLOW_SHA") or "") else None,
                "run_id": _int_or_none(g("GITHUB_RUN_ID")), "run_attempt": _int_or_none(g("GITHUB_RUN_ATTEMPT")),
                "runner_environment": g("RUNNER_ENVIRONMENT")},
        "subject": {"head_sha": None, "default_branch": None, "merge_base": None, "commits": None,
                    "canary_commit": None, "pr_number": None},
        "trusted": {"gate_sha": None, "skill_version": GATE_VERSION,
                    # No lock.json exists yet: the sha256 of empty input means
                    # "no lock.json" (docs/contracts/gate-receipt.md, History).
                    "lock_sha256": sha256_hex(b""), "config_source": "default",
                    "head_config_fingerprint": None, "confirmed": False},
        "self_check": {"outcome": INCONCLUSIVE, "failed": []},
        "trust_checks": [{"id": "SG-TRUST-001", "outcome": INCONCLUSIVE, "paths": []}],
        "tools": [],
        "coverage": {"expected_lockfiles": [], "scanned_lockfiles": [], "missing": [], "unexpected_manifests": [],
                     "outcome": PASS},
        "exceptions": {"source": ".security-gate/exceptions.yaml", "applied": 0, "expired": [],
                       "false_positive_count": 0, "outcome": PASS},
        "post_filters": [],
        "outcome": INCONCLUSIVE,
        "reasons": [],
        "exit_code": EXIT[INCONCLUSIVE],
        "finished_at": None,
    }


def add_reason(receipt: dict, code: str, detail: str, tool: str | None = None) -> None:
    receipt["reasons"].append({"code": code, "tool": tool, "detail": detail})


def read_event(receipt: dict) -> dict:
    path = os.environ.get("GITHUB_EVENT_PATH")
    try:
        with open(path or "", "rb") as fh:
            event = json.loads(fh.read())
        pr = event["pull_request"]
        info = {"number": pr["number"], "head_sha": pr["head"]["sha"],
                "default_branch": event["repository"]["default_branch"]}
    except (OSError, ValueError, KeyError, TypeError):
        add_reason(receipt, "invalid_document", "the event payload (GITHUB_EVENT_PATH) is missing or not a "
                                                "pull_request_target payload")
        return {}
    if not (isinstance(info["number"], int) and isinstance(info["head_sha"], str)
            and isinstance(info["default_branch"], str)):
        add_reason(receipt, "invalid_document", "the event payload has fields of an unexpected type")
        return {}
    return info


def run_pr(args: argparse.Namespace, receipt: dict, scratch: Path) -> None:
    run = receipt["run"]
    trusted = Git(args.trusted, scratch / "trusted")
    git = Git(args.tree, scratch / "pr")
    if trusted.object_format() != "sha1" or git.object_format() != "sha1":
        add_reason(receipt, "unsupported_object_format", "the repository does not use SHA-1 object ids")
        return
    event = read_event(receipt)
    head = os.environ.get("PR_HEAD_SHA", "")
    if not SHA1_RE.match(head):
        add_reason(receipt, "invalid_document", "PR_HEAD_SHA is not a 40-hex commit id")
        return
    if event and event["head_sha"] != head:
        add_reason(receipt, "invalid_document", "PR_HEAD_SHA differs from the head in the event payload")
        return
    sub = receipt["subject"]
    sub["head_sha"] = head
    sub["pr_number"] = event.get("number")
    default = event.get("default_branch")
    sub["default_branch"] = default

    gate_sha = trusted.rev("HEAD")
    receipt["trusted"]["gate_sha"] = gate_sha

    failed = []
    if run["event"] != EVENT:
        failed.append("event")
    if not default or run["workflow_ref"] != f"{run['repository']}/{WORKFLOW_PATH}@refs/heads/{default}":
        failed.append("workflow_ref")
    if run["workflow_sha"] != gate_sha:
        failed.append("workflow_sha")
    if run["runner_environment"] != "github-hosted":
        failed.append("runner_environment")
    receipt["self_check"] = {"outcome": INCONCLUSIVE if failed else PASS, "failed": failed}
    if failed:
        add_reason(receipt, "self_check_failed", "not the owned workflow on pull_request_target from the default "
                                                 "branch on a GitHub-hosted runner: " + ", ".join(failed))

    try:
        git.rev(head)
        git.rev(gate_sha)
    except GitError:
        add_reason(receipt, "tool_error", "the head or the default branch commit is not in the pull request "
                                          "checkout")
        return
    base = git.merge_base(gate_sha, head)
    if base is None:
        add_reason(receipt, "tool_error", "the head has no merge base with the default branch")
        return
    sub["merge_base"] = base
    sub["commits"] = git.count(base, head)

    entries, bad = decode_entries(git.tree(head))
    # SG-TRUST-001 compares with the default branch tip, never with a merge
    # base (see the module docstring and ADR 0003, 3.5, item 2).
    changed, bad_changed = protected_changes(git, gate_sha, head)
    bad = sorted(set(bad + bad_changed))
    if bad:
        add_reason(receipt, "non_utf8_path", f"{len(bad)} path(s) are not UTF-8, for example "
                                             + shown(bad[0].decode("utf-8", "backslashreplace")))

    oids = sorted({e.oid for e in entries if e.kind == "blob"})
    blobs = git.blobs(oids)

    # SG-TRUST-001
    confirmed_set, well_formed = parse_config(os.environ.get("SG_CONFIG"))
    if not well_formed:
        add_reason(receipt, "invalid_document", f"{CONFIG_VARIABLE} is set but is not one sha256:<64 hex> "
                                                "fingerprint")
    fp = fingerprint(entries, blobs)
    changed_paths = [path for _, path in changed]
    special = unconfirmable(entries)
    confirmed = fp in confirmed_set
    tr = receipt["trusted"]
    tr["head_config_fingerprint"] = fp
    tr["confirmed"] = confirmed

    def listed(paths: list[str]) -> str:
        return ", ".join(shown(p) for p in paths[:MAX_SHOWN]) + (" ..." if len(paths) > MAX_SHOWN else "")

    if changed_paths and not confirmed:
        detail = (f"{len(changed_paths)} protected path(s) differ from the default branch and the head "
                  f"fingerprint is not confirmed in {CONFIG_VARIABLE}: " + listed(changed_paths))
        stale = behind(git, gate_sha, head)
        if stale:
            detail += (f". The default branch changed {len(stale)} protected path(s) after this branch was "
                       f"created ({listed(stale)}): merge or rebase the default branch into the pull request "
                       f"first")
        add_reason(receipt, "protected_change_unconfirmed", detail)
    if special:
        add_reason(receipt, "protected_change_unconfirmed",
                   f"{len(special)} protected path(s) are symlinks or submodules, whose content is outside the "
                   f"protected set; they cannot be confirmed, remove them: " + listed(special))
    sg001 = INCONCLUSIVE if special or (changed_paths and not confirmed) else PASS
    receipt["trust_checks"] = [{"id": "SG-TRUST-001", "outcome": sg001,
                                "paths": sorted(set(changed_paths) | set(special))}]
    if sg001 == PASS:
        tr["config_source"] = "head_confirmed" if changed_paths else "default"

    self_file = Path(__file__).read_bytes()
    for name, tool in TOOLS:
        try:
            result = tool(git, entries, blobs, self_file)
        except GitError as exc:
            add_reason(receipt, "tool_error", str(exc), name)
            continue
        receipt["tools"].append(result["receipt"])
        for code, detail in result["reasons"]:
            add_reason(receipt, code, detail, name)


def finish(receipt: dict) -> None:
    if not receipt["tools"]:
        add_reason(receipt, "tool_missing", "no tool produced a receipt")
    codes = {r["code"] for r in receipt["reasons"]}
    parts = [receipt["self_check"]["outcome"], receipt["coverage"]["outcome"], receipt["exceptions"]["outcome"]]
    parts += [t["outcome"] for t in receipt["trust_checks"]] + [t["outcome"] for t in receipt["tools"]]
    if codes & FAIL_CODES or FAIL in parts:
        outcome = FAIL
    elif codes or any(p != PASS for p in parts):
        outcome = INCONCLUSIVE
    else:
        outcome = PASS
    if outcome != PASS and not receipt["reasons"]:
        add_reason(receipt, "tool_error", "a check is not pass but gave no reason")
    receipt["outcome"] = outcome
    receipt["exit_code"] = EXIT[outcome]
    receipt["finished_at"] = now()


def annotate(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def md(text: str) -> str:
    return text.replace("|", "\\|").replace("`", "'").replace("<", "&lt;")


def report(receipt: dict) -> None:
    outcome = receipt["outcome"]
    print(f"security-gate: {outcome.upper()} (exit {receipt['exit_code']})")
    for r in receipt["reasons"]:
        level = "error" if outcome != PASS else "notice"
        print(f"::{level} title=security-gate {r['code']}::" + annotate(r["detail"]))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary:
        return
    lines = [f"## security-gate: {outcome}", ""]
    lines += [f"- self-check: {receipt['self_check']['outcome']}",
              f"- SG-TRUST-001: {receipt['trust_checks'][0]['outcome']}"]
    for t in receipt["tools"]:
        lines.append(f"- {t['name']}: {t['outcome']}, {t['findings']['total']} finding(s), "
                     f"{t['scanned']['files']} file(s) scanned")
    if receipt["reasons"]:
        lines += ["", "| reason | tool | detail |", "|---|---|---|"]
        lines += [f"| {r['code']} | {r['tool'] or ''} | {md(r['detail'])} |" for r in receipt["reasons"]]
    lines += ["", f"Receipt: artifact `{RECEIPT_ARTIFACT}`.", ""]
    try:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
    except OSError:
        print("security-gate: warning: could not write the job summary")


def cmd_pr(args: argparse.Namespace) -> int:
    receipt = new_receipt()
    with tempfile.TemporaryDirectory(prefix="security-gate-") as tmp:
        try:
            run_pr(args, receipt, Path(tmp))
        except GitError as exc:
            add_reason(receipt, "tool_error", str(exc))
        except Exception as exc:  # noqa: BLE001 - a crash is inconclusive, never pass
            frame = traceback.extract_tb(exc.__traceback__)[-1]
            add_reason(receipt, "tool_error", f"internal error {type(exc).__name__} at line {frame.lineno}")
    finish(receipt)
    out = Path(args.out) if args.out else Path(os.environ.get("RUNNER_TEMP") or ".") / "security-gate"
    try:
        out.mkdir(parents=True, exist_ok=True)
        data = json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        (out / "receipt.json").write_text(data, encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"security-gate: INCONCLUSIVE - cannot write the receipt: {type(exc).__name__}")
        return EXIT[INCONCLUSIVE]
    report(receipt)
    return receipt["exit_code"]


# ---------------------------------------------------------------------------
# Subcommands for human.sh
# ---------------------------------------------------------------------------

def _protected_state(git: Git, commit: str) -> tuple[list[Entry], str]:
    entries, bad = decode_entries(git.tree(commit))
    if bad:
        raise GitError("the commit has paths that are not UTF-8")
    return entries, fingerprint(entries, git.blobs(protected_blob_oids(entries)))


def cmd_fingerprint(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="security-gate-") as tmp:
        git = Git(args.repo, Path(tmp))
        print(_protected_state(git, git.rev(args.commit))[1])
    return 0


def sanitize_patch(data: bytes) -> str:
    out = []
    for line in data.decode("utf-8", "replace").split("\n"):
        out.append("".join(ch if ch == "\t" or (ch.isprintable() and unicodedata.category(ch) != "Cf")
                           else shown(ch)[1:-1] for ch in line))
    return "\n".join(out)


def cmd_protected_diff(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="security-gate-") as tmp:
        git = Git(args.repo, Path(tmp))
        default, head = git.rev(args.default), git.rev(args.head)
        if git.merge_base(default, head) is None:
            raise GitError("no merge base")
        entries, fp = _protected_state(git, head)
        changed, bad = protected_changes(git, default, head)
        if bad:
            raise GitError("a changed path is not UTF-8")
        stale = behind(git, default, head)
        special = unconfirmable(entries)
        print(f"default={default}\nhead={head}\nfingerprint={fp}\nchanged={len(changed)}\nbehind={len(stale)}\n"
              f"unconfirmable={len(special)}")
        for status, path in changed:
            print(f"changed:  {status} {shown(path)}")
        for path in stale:
            print(f"behind:  {shown(path)}")
        for path in special:
            print(f"unconfirmable:  {shown(path)}")
        if args.patch and changed:
            print(sanitize_patch(git.patch(default, head, [p for _, p in changed])))
    return 0


def main(argv: list[str] | None = None) -> int:
    if sys.version_info < (3, 11):  # noqa: UP036 - the guard is for an interpreter older than the target
        print("security-gate: INCONCLUSIVE - Python 3.11 or newer is required")
        return EXIT[INCONCLUSIVE]
    parser = argparse.ArgumentParser(prog="gate.py", description="security-gate pull request gate")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("pr", help="judge the pull request (CI)")
    p.add_argument("--trusted", type=Path, required=True, help="checkout of the default branch")
    p.add_argument("--tree", type=Path, required=True, help="checkout of the pull request head, read as data")
    p.add_argument("--out", type=Path, default=None, help="receipt directory (default $RUNNER_TEMP/security-gate)")
    p = sub.add_parser("fingerprint", help="print the fingerprint of the protected set of a commit")
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--commit", required=True)
    p = sub.add_parser("protected-diff", help="list where a head differs from the default branch on protected paths")
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--default", required=True, help="tip of the default branch")
    p.add_argument("--head", required=True)
    p.add_argument("--patch", action="store_true", help="also print the patch, control characters escaped")
    args = parser.parse_args(argv)
    if args.command == "pr":
        return cmd_pr(args)
    try:
        return cmd_fingerprint(args) if args.command == "fingerprint" else cmd_protected_diff(args)
    except (GitError, UnicodeDecodeError, ValueError) as exc:
        print(f"gate.py: error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT[INCONCLUSIVE]


if __name__ == "__main__":
    sys.exit(main())
