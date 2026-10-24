# managed-by: security-gate v0.1.0-b3 (owned)
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
  not in the repository, not scanned), and scanner configuration or ignore
  files, which the scanners below never read. Two canaries planted by the gate
  itself prove that the rules saw the tree;
- the scanners pinned in .security-gate/lock.json (taken from the default
  branch, or from the head once SG-TRUST-001 passed; from the default branch
  again when a confirmed new gate.py that declares a lock.json schema this
  version does not read brings a lock.json of it, see run_pr), each run as a
  container
  by digest: gitleaks on the head tree and on the commits of the pull request
  (each file also under a name of the gate's, so that no path allowlist of
  gitleaks skips it), osv-scanner on the lock files of the head, zizmor on
  its workflows, semgrep on every file of the head with the gate's own rules
  (.security-gate/semgrep-rules.yml, from the same commit as lock.json),
  which block, and the Semgrep Registry rules, downloaded on every run and
  never stored, whose findings only signal unless lock.json says block. A
  container that reads pull request data has no network and a read-only view
  of it; the two containers with network download the vulnerability
  databases and the Registry rules and see no pull request data. No scanner
  reads a configuration or an ignore list from the pull request. Each scanner
  finds a canary of the gate in the same call that scans the pull request, or
  the result is inconclusive.

Subcommands for human.sh:
    gate.py fingerprint --repo DIR --commit REV
    gate.py protected-diff --repo DIR --default REV --head REV [--patch]
"""
from __future__ import annotations

import argparse
import ast
import datetime
import hashlib
import io
import json
import os
import posixpath
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import threading
import time
import tokenize
import traceback
import unicodedata
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

GATE_VERSION = "0.1.0-b3"
RECEIPT_SCHEMA = "security-gate/receipt"
RECEIPT_SCHEMA_VERSION = 4
FINGERPRINT_SCHEMA = "security-gate/fingerprint"
FINGERPRINT_SCHEMA_VERSION = 1
LOCK_SCHEMA = "security-gate/lock"
LOCK_SCHEMA_VERSION = 2
# lock.json v1 (slice A) pins no semgrep. It is still read, so that a
# repository on v0.1.0-a1 can take the new gate.py first and lock.json v2 in a
# second pull request (ADR 0006): until then semgrep is tool_missing. A
# version above these, in a confirmed pull request whose gate.py declares it,
# is judged with the default branch's scanners (lock_schema_ahead, run_pr).
# The gate of the default branch reads the next line in the gate.py of the
# pull request that upgrades it, as data (lock_schemas_declared): keep it one
# line, written exactly so.
LOCK_SCHEMA_VERSIONS = (1, 2)

EVENT = "pull_request_target"
WORKFLOW_PATH = ".github/workflows/security-gate.yml"
GATE_PATH = ".security-gate/bin/gate.py"
LOCK_PATH = ".security-gate/lock.json"
SEMGREP_RULES_PATH = ".security-gate/semgrep-rules.yml"
CONFIG_VARIABLE = "SECURITY_GATE_CONFIG"
RECEIPT_ARTIFACT = "security-gate-receipt"

# The protected set. Paths are compared in lower case, so a case variant of a
# protected directory is protected too. A non-directory entry on the way to a
# protected directory (".github" as a symlink) is protected as well.
PROTECTED_DIRS = (".github/workflows", ".security-gate")
NOT_PROTECTED = frozenset({".security-gate/state.json"})
LINK_MODE = "120000"
FILE_MODES = frozenset({"100644", "100755"})

PASS, FAIL, INCONCLUSIVE = "pass", "fail", "inconclusive"
EXIT = {PASS: 0, FAIL: 1, INCONCLUSIVE: 2}
FAIL_CODES = frozenset({"finding", "exception_expired"})
SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# The drill canary: "security-gate-canary:v1:" and 32 lowercase hex digits.
# It is assembled here so that this file never contains a canary itself.
CANARY_RULE = "security-gate-canary"
CANARY_PREFIX = (CANARY_RULE + ":v1:").encode()
CANARY_RE = re.compile(re.escape(CANARY_PREFIX) + rb"[0-9a-f]{32}")
CANARY_LEN = len(CANARY_PREFIX) + 32

# Files a scanner would read as its configuration or ignore list if it were
# run the usual way. The gate never lets a scanner read them (see each
# scanner), so a pull request cannot quiet a scanner with one; the file is
# reported, because it suppresses nothing and only looks as if it did.
SCANNER_CONFIG_NAMES = frozenset({".gitleaksignore", ".gitleaks.toml", "osv-scanner.toml", "zizmor.yml",
                                  "zizmor.yaml", ".semgrepignore"})

RULES = (
    (CANARY_RULE, "high", "drill canary in a file of the head tree"),
    ("security-gate-symlink-dangling", "medium", "symlink whose target is not in the head tree"),
    ("security-gate-symlink-escape", "medium", "symlink with an absolute target or one outside the repository"),
    ("security-gate-submodule", "medium", "submodule: its content is not in this repository and is not scanned"),
    ("security-gate-lfs", "medium", "Git LFS pointer: the content is not in this repository and is not scanned"),
    ("security-gate-scanner-config", "medium",
     "scanner configuration or ignore file: the gate does not read it and it suppresses nothing; remove it"),
)
SEVERITY = {rule: sev for rule, sev, _ in RULES}

# A Git LFS pointer file (git-lfs spec v1, and the older hawser prefix). The
# spec keeps pointers under 1024 bytes; a larger file is not a pointer, and its
# content is in the repository and scanned like any other file.
LFS_PREFIXES = (b"version https://git-lfs.github.com/spec/", b"version https://hawser.github.com/spec/v1")
LFS_MAX_POINTER = 1024

MAX_ITEMS = 500
MAX_SHOWN = 20
MAX_PATHS = 50
CHUNK = 1 << 20
MAX_LINK_TARGET = 4096
MAX_LOCK_BYTES = 1 << 20
MAX_GATE_BYTES = 1 << 20
MAX_SCANNED_FILE = 128 << 20
MAX_RECORD = 4 << 20
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


def listed(paths: list[str]) -> str:
    return ", ".join(shown(p) for p in paths[:MAX_SHOWN]) + (" ..." if len(paths) > MAX_SHOWN else "")


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
# The identity of the objects the gate writes itself (the gitleaks snapshot).
_GATE_IDENTITY = {"GIT_AUTHOR_NAME": "security-gate", "GIT_AUTHOR_EMAIL": "security-gate@invalid",
                  "GIT_COMMITTER_NAME": "security-gate", "GIT_COMMITTER_EMAIL": "security-gate@invalid"}


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
    nul: bool = False   # a NUL byte anywhere: git's "binary"


@dataclass(frozen=True)
class Change:
    """A regular file that a commit of the pull request adds or changes. A
    merge commit has one Change per parent for each file that differs from
    all its parents."""
    commit: str
    path: str
    old: str | None     # the blob before (its parent's, or a rename source), None if the file is new
    new: str            # the blob the commit wrote
    parent: int = 0     # which parent old belongs to
    parents: int = 1    # how many parents the commit has


ZERO_OID = "0" * 40


def raw_records(out: bytes) -> list[tuple[list[str], list[str], str, bytes]]:
    """(modes, oids, status, path) from `diff-tree -r -z --raw --no-abbrev`
    output; modes and oids end with the result, a rename or copy keeps its
    destination path."""
    parts = out.split(b"\0")
    records, i = [], 0
    while i < len(parts):
        meta = parts[i]
        if not meta:
            i += 1
            continue
        if not meta.startswith(b":") or i + 1 >= len(parts):
            raise GitError("diff-tree output is not raw records")
        n = len(meta) - len(meta.lstrip(b":"))
        fields = meta[n:].decode("ascii").split(" ")
        if len(fields) != 2 * n + 3:
            raise GitError("diff-tree output is not raw records")
        modes, oids, status = fields[:n + 1], fields[n + 1:2 * n + 2], fields[2 * n + 2]
        if n == 1 and status[:1] in ("R", "C"):
            path, i = parts[i + 2], i + 3
        else:
            path, i = parts[i + 1], i + 2
        records.append((modes, oids, status, path))
    return records


def git_environ(home: Path) -> dict[str, str]:
    keep = {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "TMPDIR")}
    return dict(keep, HOME=str(home), LC_ALL="C", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                GIT_ATTR_NOSYSTEM="1", GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0",
                GIT_NO_LAZY_FETCH="1", GIT_ADVICE="0")


class Git:
    """One repository, read through its object database only."""

    def __init__(self, repo: Path, scratch: Path) -> None:
        self.scratch = scratch
        worktree = scratch / "empty-worktree"
        worktree.mkdir(parents=True, exist_ok=True)
        home = scratch / "home"
        home.mkdir(parents=True, exist_ok=True)
        self.environ = git_environ(home)
        repo = Path(repo).absolute()
        # The ceiling stops git from taking a parent directory's repository.
        probe = dict(self.environ, GIT_CEILING_DIRECTORIES=str(repo.parent))
        proc = subprocess.run(["git", "-C", str(repo), "rev-parse", "--absolute-git-dir"], capture_output=True,
                              timeout=60, check=False, env=probe)
        if proc.returncode != 0:
            raise GitError("not a git repository")
        self.git_dir = Path(proc.stdout.decode("utf-8", "surrogateescape").strip())
        self.prefix = ["git", "--git-dir=" + str(self.git_dir), "--work-tree=" + str(worktree), "--literal-pathspecs"]
        for item in _GIT_CONFIG:
            self.prefix += ["-c", item]

    @property
    def objects(self) -> Path:
        return self.git_dir / "objects"

    def run(self, *args: str, data: bytes | None = None, ok: tuple[int, ...] = (0,),
            extra: dict[str, str] | None = None) -> bytes:
        try:
            proc = subprocess.run(self.prefix + list(args), input=data, capture_output=True, timeout=600,
                                  check=False, env=dict(self.environ, **(extra or {})))
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

    def root_records(self, commit: str) -> list[bytes]:
        """The raw ls-tree -z records of the root tree of a commit."""
        return [rec for rec in self.run("ls-tree", "-z", "--full-tree", commit).split(b"\0") if rec]

    def entry_at(self, commit: str, path: str) -> tuple[str, str, str] | None:
        """(mode, kind, oid) of the entry at a path of a commit, or None."""
        out = self.run("ls-tree", "-z", "--full-tree", commit, "--", path)
        for rec in out.split(b"\0"):
            meta, _, raw = rec.partition(b"\t")
            if rec and raw == path.encode("utf-8"):
                mode, kind, oid = meta.decode("ascii").split(" ")
                return mode, kind, oid
        return None

    def blob_bytes(self, oid: str, limit: int) -> bytes:
        size = int(self.run("cat-file", "-s", oid).decode().strip())
        if size > limit:
            raise GitError(f"a blob of {size} bytes is larger than the {limit} bytes the gate reads")
        return self.run("cat-file", "blob", oid)

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

    def mktree(self, records: list[bytes]) -> str:
        """A tree from raw ls-tree -z records; entries may live in alternates."""
        return self.run("mktree", "-z", "--missing", data=b"".join(r + b"\0" for r in records)).decode().strip()

    def commit_tree(self, tree: str, message: str, parents: tuple[str, ...] = ()) -> str:
        args = [a for p in parents for a in ("-p", p)]
        return self.run("commit-tree", tree, *args, "-m", message, extra=_GATE_IDENTITY).decode().strip()

    def pr_changes(self, head: str, base: str) -> list[Change]:
        """Every regular file a non-merge commit of base..head adds or
        changes, against its first parent, with renames detected as git log
        detects them. Deletions are left out: they add no content.

        A merge commit adds content of its own only where its file differs
        from every parent ("evil merge"; `git log -p` shows merges without a
        diff, so gitleaks never sees it). For each such file there is one
        Change per parent; a line counts as added by the merge only if it is
        added against every parent (judge_gitleaks)."""
        changes = []
        for commit in self.run("rev-list", "--no-merges", head, "^" + base).decode().split():
            out = self.run("diff-tree", "-r", "-z", "-M", "--root", "--raw", "--no-abbrev", "--no-commit-id",
                           "--no-ext-diff", "--no-textconv", commit)
            for modes, oids, status, raw in raw_records(out):
                if status[:1] == "D" or modes[-1] not in FILE_MODES:
                    continue
                old = oids[0] if oids[0] != ZERO_OID and modes[0] in FILE_MODES | {LINK_MODE} else None
                changes.append(Change(commit, raw.decode("utf-8", "backslashreplace"), old, oids[-1]))
        for commit in self.run("rev-list", "--merges", head, "^" + base).decode().split():
            # -c lists only the files that differ from all parents.
            out = self.run("diff-tree", "-r", "-z", "-c", "--raw", "--no-abbrev", "--no-commit-id", "--no-ext-diff",
                           "--no-textconv", commit)
            for modes, oids, _, raw in raw_records(out):
                if modes[-1] not in FILE_MODES or oids[-1] == ZERO_OID:
                    continue
                path, parents = raw.decode("utf-8", "backslashreplace"), len(oids) - 1
                for i in range(parents):
                    old = oids[i] if oids[i] != ZERO_OID and modes[i] in FILE_MODES | {LINK_MODE} else None
                    changes.append(Change(commit, path, old, oids[-1], i, parents))
        return changes

    def commits_with_additions(self, revs: list[str]) -> int:
        """Non-merge commits of revs whose diff adds at least one line: the
        commits gitleaks counts when it reads `git log -p` (it reports fewer
        for commits that only delete, rename or add binary files)."""
        out = self.run("log", "--no-merges", "--format=%x01%H", "--numstat", *revs, "--")
        counted, current = 0, False
        for line in out.split(b"\n"):
            if line.startswith(b"\x01"):
                current = False
                continue
            added = line.split(b"\t", 1)[0]
            if not current and added.isdigit() and int(added) > 0:
                current = True
                counted += 1
        return counted

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
                    blob.nul = blob.nul or b"\0" in chunk
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

    def write_blobs(self, pairs: list[tuple[str, Path]]) -> list[Path]:
        """Write each blob to its new file through one cat-file --batch.
        Returns the files that could not be created (an existing file of the
        same name, which only a case-insensitive file system produces)."""
        failed: list[Path] = []
        if not pairs:
            return failed
        proc = subprocess.Popen(self.prefix + ["cat-file", "--batch"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=self.environ)

        def feed() -> None:
            try:
                for oid, _ in pairs:
                    proc.stdin.write(oid.encode() + b"\n")
                proc.stdin.close()
            except OSError:
                pass

        writer = threading.Thread(target=feed, daemon=True)
        writer.start()
        try:
            for oid, path in pairs:
                header = proc.stdout.readline().split()
                if len(header) != 3 or header[0].decode() != oid or header[1] != b"blob":
                    raise GitError("cat-file did not return the requested blob")
                remaining = int(header[2])
                path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
                except FileExistsError:
                    fd = None
                    failed.append(path)
                with os.fdopen(fd, "wb") if fd is not None else open(os.devnull, "wb") as fh:
                    while remaining:
                        chunk = proc.stdout.read(min(CHUNK, remaining))
                        if not chunk:
                            raise GitError("cat-file output ended early")
                        remaining -= len(chunk)
                        fh.write(chunk)
                if proc.stdout.read(1) != b"\n":
                    raise GitError("cat-file output is not terminated")
        finally:
            proc.stdout.close()
            code = proc.wait(timeout=600)
            writer.join(timeout=60)
        if code != 0:
            raise GitError(f"git cat-file exited {code}")
        return failed


def scratch_repository(path: Path, objects: Path, scratch: Path) -> Git:
    """A bare repository of the gate's own: its config, attributes and refs
    are the gate's, and it reads the objects of another repository through
    alternates. `* diff` in info/attributes outranks every .gitattributes and
    sets the diff attribute on every path, so `git log -p` prints the content
    of every file as text, even one with NUL bytes, which git would otherwise
    show as "Binary files differ" and gitleaks would skip. `* !diff` would
    only restore git's own binary detection."""
    path.mkdir(parents=True)
    environ = git_environ(scratch / "init-home")
    (scratch / "init-home").mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(["git", "init", "--bare", "--quiet", "--template=", str(path)], capture_output=True,
                          timeout=60, check=False, env=environ)
    if proc.returncode != 0:
        raise GitError("git init of the scratch repository failed")
    (path / "objects" / "info").mkdir(parents=True, exist_ok=True)
    (path / "objects" / "info" / "alternates").write_text(str(objects) + "\n", encoding="utf-8")
    (path / "info").mkdir(parents=True, exist_ok=True)
    (path / "info" / "attributes").write_text("* diff\n", encoding="utf-8")
    return Git(path, scratch)


def safe_join(root: Path, rel: str) -> Path | None:
    """root/rel for a repository path, or None if the path could leave root
    or carries a control character."""
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts) or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in rel):
        return None
    return root.joinpath(*parts)


def write_new_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


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
# lock.json: the scanners, their images and their thresholds
# ---------------------------------------------------------------------------

# The scanners each version of lock.json pins.
LOCK_TOOLS = {1: ("gitleaks", "osv-scanner", "zizmor"), 2: ("gitleaks", "osv-scanner", "semgrep", "zizmor")}
_RULESET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*(?::[0-9]+)?(?:/[a-z0-9][a-z0-9._-]*)+$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$")
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_HTTPS_RE = re.compile(r"^https://[!-~]+$")
_DB_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$")
ECOSYSTEMS = ("npm", "PyPI")
# What a finding of a Semgrep Registry rule at or above min_severity does:
# signal (counted and listed in the receipt, never a fail; the template's
# value) or block (a fail, like a finding of the gate's own rules). Which
# rules are the Registry's the gate knows by the file it read them from.
REGISTRY_POLICIES = ("signal", "block")


class LockError(Exception):
    def __init__(self, detail: str, code: str = "invalid_document") -> None:
        super().__init__(detail)
        self.code = code


def _need(cond: bool, where: str, what: str) -> None:
    if not cond:
        raise LockError(f"lock.json: {where} {what}")


def _is_int(value: object, low: int, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def parse_lock(data: bytes) -> dict:
    """The validated lock document. Every field the gate uses is required and
    typed: a typo or a missing threshold is invalid_document, never a default.
    Unknown fields are ignored (docs/contracts/README.md)."""
    if not data.strip():
        raise LockError("lock.json is empty")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise LockError("lock.json is not JSON in UTF-8") from None
    _need(isinstance(doc, dict), "the document", "is not an object")
    _need(doc.get("schema") == LOCK_SCHEMA, "schema", f"is not {LOCK_SCHEMA}")
    version = doc.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool) or version not in LOCK_SCHEMA_VERSIONS:
        raise LockError("lock.json: schema_version is not one of " + ", ".join(map(str, LOCK_SCHEMA_VERSIONS)),
                        "unknown_schema_version")
    names = LOCK_TOOLS[version]
    tools = doc.get("tools")
    _need(isinstance(tools, dict) and set(tools) == set(names), "tools",
          f"must name exactly {', '.join(names)} (schema_version {version})")
    for name in names:
        t = tools[name]
        _need(isinstance(t, dict), name, "is not an object")
        _need(isinstance(t.get("version"), str) and bool(_VERSION_RE.match(t["version"])), name + ".version",
              "is not a version")
        _need(isinstance(t.get("image"), str) and bool(_IMAGE_RE.match(t["image"])), name + ".image",
              "is not an image name without tag or digest")
        _need(isinstance(t.get("digest"), str) and bool(_DIGEST_RE.match(t["digest"])), name + ".digest",
              "is not sha256:<64 hex>")
        _need(_is_int(t.get("timeout_s"), 30, 3600), name + ".timeout_s", "is not an integer from 30 to 3600")
        v = t.get("verified")
        _need(isinstance(v, dict) and isinstance(v.get("on"), str) and bool(_DATE_RE.match(v["on"]))
              and isinstance(v.get("release"), str) and bool(_HTTPS_RE.match(v["release"]))
              and isinstance(v.get("evidence"), list) and bool(v["evidence"])
              and all(isinstance(x, str) for x in v["evidence"]), name + ".verified",
              "needs on (date), release (https URL) and evidence (strings)")
        p = t.get("policy")
        _need(isinstance(p, dict) and p.get("min_severity") in RANK, name + ".policy.min_severity",
              "is not one of " + ", ".join(SEVERITIES))
        if name != "gitleaks":
            _need(p.get("unknown_severity") in RANK, name + ".policy.unknown_severity",
                  "is not one of " + ", ".join(SEVERITIES))
        if name == "osv-scanner":
            _need(isinstance(p.get("require_fix"), bool), name + ".policy.require_fix", "is not a boolean")
            _need(isinstance(p.get("malicious_fails"), bool), name + ".policy.malicious_fails", "is not a boolean")
            dbs = t.get("databases")
            _need(isinstance(dbs, list), name + ".databases", "is not an array")
            for i, db in enumerate(dbs):
                where = f"{name}.databases[{i}]"
                _need(isinstance(db, dict), where, "is not an object")
                _need(isinstance(db.get("name"), str) and bool(_VERSION_RE.match(db["name"])), where + ".name",
                      "is not a name")
                _need(db.get("ecosystem") in ECOSYSTEMS, where + ".ecosystem", "is not one of " + ", ".join(ECOSYSTEMS))
                _need(isinstance(db.get("source"), str) and bool(_HTTPS_RE.match(db["source"])), where + ".source",
                      "is not an https URL")
                _need(isinstance(db.get("path"), str) and bool(_DB_PATH_RE.match(db["path"])), where + ".path",
                      "is not a relative path")
                _need(_is_int(db.get("max_age_hours"), 1, 8760), where + ".max_age_hours",
                      "is not an integer from 1 to 8760")
            _need(sorted(db["ecosystem"] for db in dbs) == sorted(ECOSYSTEMS), name + ".databases",
                  "must list exactly one database for each of " + ", ".join(ECOSYSTEMS))
        if name == "semgrep":
            _need(p.get("registry") in REGISTRY_POLICIES, name + ".policy.registry",
                  "is not one of " + ", ".join(REGISTRY_POLICIES))
            sets = t.get("rulesets")
            _need(isinstance(sets, list) and bool(sets), name + ".rulesets", "is not a non-empty array")
            for i, rs in enumerate(sets):
                where = f"{name}.rulesets[{i}]"
                _need(isinstance(rs, dict), where, "is not an object")
                _need(isinstance(rs.get("name"), str) and bool(_RULESET_NAME_RE.match(rs["name"])), where + ".name",
                      "is not a name of lower case letters, digits, dots and hyphens")
                _need(isinstance(rs.get("source"), str) and bool(_HTTPS_RE.match(rs["source"])), where + ".source",
                      "is not an https URL")
                _need(_is_int(rs.get("min_rules"), 1, 1000000), where + ".min_rules",
                      "is not an integer from 1 to 1000000")
            _need(len({rs["name"] for rs in sets}) == len(sets), name + ".rulesets", "has two rulesets of one name")
    return doc


def load_lock(git: Git, commit: str) -> tuple[dict | None, bytes | None, tuple[str, str] | None]:
    """(document, bytes, problem) of lock.json in a commit, read as a git
    object."""
    entry = git.entry_at(commit, LOCK_PATH)
    if entry is None:
        return None, None, ("invalid_document", f"{LOCK_PATH} is missing, so no scanner can run")
    mode, kind, oid = entry
    if kind != "blob" or mode not in FILE_MODES:
        return None, None, ("invalid_document", f"{LOCK_PATH} is not a regular file")
    try:
        data = git.blob_bytes(oid, MAX_LOCK_BYTES)
    except GitError as exc:
        return None, None, ("invalid_document", f"{LOCK_PATH}: {exc}")
    try:
        return parse_lock(data), data, None
    except LockError as exc:
        return None, data, (exc.code, str(exc))


def lock_schema_ahead(data: bytes | None) -> int | None:
    """The schema_version of a lock.json that is newer than every version this
    gate reads: a JSON object of schema security-gate/lock whose
    schema_version is an integer above them all. Nothing else in it is read,
    and anything else is None: not JSON, not an object, another schema, a
    version that is no integer (a string, a boolean, 3.0) or not above them."""
    try:
        doc = json.loads(data.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(doc, dict) or doc.get("schema") != LOCK_SCHEMA:
        return None
    version = doc.get("schema_version")
    if isinstance(version, int) and not isinstance(version, bool) and version > max(LOCK_SCHEMA_VERSIONS):
        return version
    return None


# The line of gate.py that declares the lock.json schemas it reads.
_LOCK_SCHEMAS_LINE = re.compile(rb"^LOCK_SCHEMA_VERSIONS = \(([0-9, ]+)\)$", re.MULTILINE)


def lock_schemas_declared(data: bytes) -> tuple[int, ...]:
    """The lock.json schemas a gate.py declares, read as data: it is never
    imported or run. Only one line counts, written exactly as
    `LOCK_SCHEMA_VERSIONS = (1, 2)` from its first column to its end (digits,
    commas and spaces between the parentheses, nothing after them, no CR),
    and only if it is the one such line of the file and its literal is a
    non-empty tuple of integers. Anything else declares nothing: no such
    line, two of them, (3) (an integer), (1,,2) or (01) (no literal)."""
    lines = _LOCK_SCHEMAS_LINE.findall(data)
    if len(lines) != 1:
        return ()
    try:
        versions = ast.literal_eval("(" + lines[0].decode("ascii") + ")")
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return ()
    if not isinstance(versions, tuple) or not all(isinstance(v, int) and not isinstance(v, bool) for v in versions):
        return ()
    return versions


def head_lock_schemas(git: Git, entries: list[Entry], changed: list[tuple[str, str]]) -> tuple[int, ...]:
    """The lock.json schemas that gate.py of the head declares
    (lock_schemas_declared), if the pull request modifies it and it is a
    regular file of at most MAX_GATE_BYTES; else none."""
    if ("M", GATE_PATH) not in changed:
        return ()
    entry = next((e for e in entries if e.path == GATE_PATH), None)
    if entry is None or entry.kind != "blob" or entry.mode not in FILE_MODES:
        return ()
    try:
        return lock_schemas_declared(git.blob_bytes(entry.oid, MAX_GATE_BYTES))
    except GitError:
        return ()


# ---------------------------------------------------------------------------
# Containers
# ---------------------------------------------------------------------------

@dataclass
class Run:
    code: int | None            # None: the container did not finish
    out: bytes = b""
    err: str = ""
    duration: int = 0
    timed_out: bool = False
    retried: bool = False
    detail: str = ""


class Docker:
    """docker run for scanners: image by digest, pulled before, never pulled
    by run; no network unless asked; the runner's uid; a read-only root file
    system with an empty /tmp; no capabilities. The docker client gets an
    empty configuration directory, so no credential helper is consulted."""

    def __init__(self, scratch: Path) -> None:
        scratch.mkdir(parents=True, exist_ok=True)
        (scratch / "config").mkdir(exist_ok=True)
        (scratch / "home").mkdir(exist_ok=True)
        self.environ = {"PATH": os.environ.get("PATH", ""), "HOME": str(scratch / "home"),
                        "DOCKER_CONFIG": str(scratch / "config")}
        if os.environ.get("DOCKER_HOST"):
            self.environ["DOCKER_HOST"] = os.environ["DOCKER_HOST"]
        self.exe = shutil.which("docker", path=self.environ["PATH"])
        self.pulled: dict[str, str | None] = {}

    def _call(self, args: list[str], timeout: int) -> subprocess.CompletedProcess:
        return subprocess.run([self.exe, *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                              check=False, env=self.environ)

    def pull(self, ref: str) -> str | None:
        """None when the image is there, else what went wrong. One retry."""
        if ref in self.pulled:
            return self.pulled[ref]
        problem = "docker is not installed on the runner"
        if self.exe:
            for _ in range(2):
                try:
                    proc = self._call(["pull", "--quiet", ref], 600)
                except (OSError, subprocess.SubprocessError) as exc:
                    problem = f"docker pull could not run: {type(exc).__name__}"
                    continue
                if proc.returncode == 0:
                    problem = None
                    break
                problem = f"docker pull exited {proc.returncode}"
        self.pulled[ref] = problem
        return problem

    def run(self, ref: str, args: list[str], *, mounts: tuple = (), network: bool = False,
            variables: dict[str, str] | None = None, timeout: int = 600, ok: tuple[int, ...] = (0,),
            retry: bool = True) -> Run:
        """Run once more when the exit code is not one of ok, or on timeout."""
        result = Run(code=None, detail="docker is not installed on the runner")
        for attempt in range(2 if retry else 1):
            result = self._run_once(ref, args, mounts, network, variables or {}, timeout)
            result.retried = attempt > 0
            if result.code is not None and result.code in ok:
                break
        return result

    def _run_once(self, ref: str, args: list[str], mounts: tuple, network: bool, variables: dict[str, str],
                  timeout: int) -> Run:
        if not self.exe:
            return Run(code=None, detail="docker is not installed on the runner")
        name = "security-gate-" + os.urandom(8).hex()
        cmd = ["run", "--rm", "--pull", "never", "--name", name, "--network", "bridge" if network else "none",
               "--user", f"{os.getuid()}:{os.getgid()}", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--tmpfs", "/tmp", "-e", "HOME=/tmp", "-w", "/sg"]
        for key, value in variables.items():
            cmd += ["-e", f"{key}={value}"]
        for host, target, read_only in mounts:
            if ":" in str(host) or "," in str(host):
                return Run(code=None, detail="a mount path contains ':' or ','")
            cmd += ["-v", f"{host}:{target}" + (":ro" if read_only else "")]
        cmd += [ref, *args]
        start = time.monotonic()
        try:
            proc = self._call(cmd, timeout)
        except subprocess.TimeoutExpired:
            for stop in (["kill", name], ["rm", "-f", name]):
                try:
                    self._call(stop, 60)
                except (OSError, subprocess.SubprocessError):
                    pass
            return Run(code=None, duration=int(time.monotonic() - start), timed_out=True,
                       detail=f"did not finish in {timeout} s")
        except (OSError, subprocess.SubprocessError) as exc:
            return Run(code=None, detail=f"docker run could not run: {type(exc).__name__}")
        return Run(code=proc.returncode, out=proc.stdout, err=proc.stderr.decode("utf-8", "replace"),
                   duration=int(time.monotonic() - start))


# ---------------------------------------------------------------------------
# Scanner context, receipts and verdicts
# ---------------------------------------------------------------------------

@dataclass
class Scan:
    git: Git
    entries: list[Entry]
    blobs: dict[str, Blob]
    head: str
    base: str                   # the default branch tip
    scratch: Path
    lock: dict | None
    docker: Docker
    confirmed: bool
    self_file: bytes
    config: str = ""            # the commit lock.json and the gate's rules are read from
    canary_commit: str | None = None

    def spec(self, name: str) -> dict:
        return self.lock["tools"][name]

    def ref(self, name: str) -> str:
        return f"{self.spec(name)['image']}@{self.spec(name)['digest']}"

    def regular_files(self) -> list[Entry]:
        return [e for e in self.entries if e.kind == "blob" and e.mode in FILE_MODES]


# The semgrep image has no entry point: every command names its program.
_VERSION_ARGS = {"gitleaks": ["version"], "osv-scanner": ["--version"], "semgrep": ["semgrep", "--version"],
                 "zizmor": ["--version"]}
_VERSION_OUT = {"gitleaks": re.compile(r"^v?(\S+)\s*$"), "osv-scanner": re.compile(r"(?m)^osv-scanner version: (\S+)"),
                "semgrep": re.compile(r"^v?([0-9]\S*)\s*$"), "zizmor": re.compile(r"(?m)^zizmor (\S+)")}


def prepare(s: Scan, name: str) -> tuple[str | None, list[tuple[str, str]]]:
    """(version reported by the image, problems). The image is pulled by
    digest, and the version it reports must be the one lock.json names."""
    if s.lock is None:
        return None, [("tool_missing", f"{name} did not run: {LOCK_PATH} is missing or invalid")]
    ref = s.ref(name)
    problem = s.docker.pull(ref)
    if problem:
        return None, [("tool_missing", f"{name} did not run: {problem}")]
    run = s.docker.run(ref, _VERSION_ARGS[name], timeout=120)
    m = _VERSION_OUT[name].search(run.out.decode("utf-8", "replace")) if run.code == 0 else None
    if not m:
        return None, [("tool_error", f"{name} did not report its version (exit {run.code})")]
    version = m.group(1).removeprefix("v")
    if version != s.spec(name)["version"]:
        detail = f"{name} reports version {shown(version)}, lock.json names {s.spec(name)['version']}"
        return version, [("artifact_mismatch", detail)]
    return version, []


# The fields of `scanned` that only semgrep fills in (see run_semgrep).
NOT_SEMGREP = {"transcoded": None, "regex_only": None, "regex_only_paths": []}


def severity_counts(items: list[dict]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITIES}
    for item in items:
        counts[item["severity"]] += 1
    return counts


def tool_receipt(s: Scan, name: str, version: str, argv: list[str], run: Run, *, scanned: dict, canaries: list,
                 markers: list[str], items: list[dict], below: int, problems: list[tuple[str, str]],
                 rules_loaded: int | None, rules_sha256: str, databases: list | None = None,
                 fetch: dict | None = None, rulesets: list | None = None,
                 listing: str | None = None, signal: list | None = None, below_items: list | None = None,
                 tool_id: str | None = None) -> tuple[dict, list[tuple[str, str]]]:
    """The tool's receipt and its reasons. Findings at or above the threshold
    are a fail; any problem without such a finding is inconclusive. listing
    replaces the plain list of findings in the reason. signal: findings at
    or above the threshold that do not block (semgrep's Registry rules under
    policy registry: signal); they are no reason. below_items: the findings
    below the threshold, listed (the gate's own semgrep rules only). tool_id:
    the id of a second run of the same tool (semgrep with the Registry
    rules), else the name."""
    signal, listed = signal or [], (below_items or [])[:MAX_ITEMS]
    reasons = []
    if items:
        shown_items = listing or ("; ".join(f"{i['rule']} {shown(i['path'])}" + (f":{i['line']}" if i["line"] else "")
                                            for i in items[:MAX_SHOWN]) + (" ..." if len(items) > MAX_SHOWN else ""))
        reasons.append(("finding", f"{len(items)} finding(s) at or above {s.spec(name)['policy']['min_severity']}: "
                                   + shown_items))
    reasons += problems
    if items:
        outcome, code = FAIL, "finding"
    elif problems:
        outcome, code = INCONCLUSIVE, problems[0][0]
    else:
        outcome, code = PASS, None
    receipt = {
        "id": tool_id or name,
        "name": name,
        "version": version,
        "artifact": {"kind": "oci", "ref": s.spec(name)["image"], "sha256": s.spec(name)["digest"]},
        "argv": argv,
        "network": "none",
        "rules_loaded": rules_loaded,
        "rules_sha256": rules_sha256,
        "scanned": scanned,
        "canaries": canaries,
        "exit_code": run.code if run.code is not None else -1,
        "stderr_markers": markers,
        "retried": run.retried,
        "findings": {"total": len(items), "by_severity": severity_counts(items), "items": items[:MAX_ITEMS],
                     "truncated": len(items) > MAX_ITEMS, "below_threshold": below, "signal": len(signal),
                     "signal_items": signal[:MAX_ITEMS], "below_items": listed,
                     "below_truncated": bool(listed) and below > len(listed)},
        "databases": databases or [],
        "rulesets": rulesets or [],
        "fetch": fetch,
        "outcome": outcome,
        "reason_code": code,
        "duration_s": run.duration,
    }
    return receipt, reasons


def run_problem(name: str, run: Run, ok: tuple[int, ...]) -> list[tuple[str, str]]:
    if run.timed_out:
        return [("timeout", f"{name} {run.detail}")]
    if run.code is None:
        return [("tool_error", f"{name}: {run.detail}")]
    if run.code not in ok:
        return [("tool_error", f"{name} exited {run.code}, which is a failure, not a finding")]
    return []


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


def gate_integrity(s: Scan) -> dict:
    start = time.monotonic()
    git, entries, blobs = s.git, s.entries, s.blobs
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
    for e in entries:
        if posixpath.basename(e.path).lower() in SCANNER_CONFIG_NAMES:
            items.append(finding("security-gate-scanner-config", e.path, None))

    canary_path = "\0planted-link"   # NUL cannot occur in a git path: no clash
    canaries = [
        {"id": "gate-integrity-file", "expected_rule": CANARY_RULE, "found": bool(planted[canary_oid].canary_lines)},
        {"id": "gate-integrity-symlink", "expected_rule": "security-gate-symlink-dangling",
         "found": resolve_link(canary_path, planted[link_oid].head, links, names, dirs) == "dangling"},
    ]
    reasons = []
    if items:
        outcome, code = FAIL, "finding"
        shown_items = "; ".join(i["rule"] + " " + shown(i["path"]) + (f":{i['line']}" if i["line"] else "")
                                for i in items[:MAX_SHOWN])
        reasons.append(("finding", f"{len(items)} finding(s): {shown_items}" + (" ..." if len(items) > MAX_SHOWN else "")))
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
                                                                     [p.decode() for p in LFS_PREFIXES], LFS_MAX_POINTER,
                                                                     sorted(SCANNER_CONFIG_NAMES)]
    receipt = {
        "id": "gate-integrity",
        "name": "gate-integrity",
        "version": GATE_VERSION,
        "artifact": {"kind": "binary", "ref": GATE_PATH, "sha256": sha256_hex(s.self_file)},
        "argv": [],
        "network": "none",
        "rules_loaded": len(RULES),
        "rules_sha256": sha256_hex(canonical(rules_doc)),
        "scanned": {"files": len(files), "commits": None, "packages": None, "paths": [""],
                    "paths_truncated": False, "lockfiles": [], "unreadable": None, **NOT_SEMGREP},
        "canaries": canaries,
        "exit_code": 1 if items or any(c["found"] for c in canaries) else 0,
        "stderr_markers": [],
        "retried": False,
        "findings": {"total": len(items), "by_severity": severity_counts(items), "items": items[:MAX_ITEMS],
                     "truncated": len(items) > MAX_ITEMS, "below_threshold": 0, "signal": 0, "signal_items": [],
                     "below_items": [], "below_truncated": False},
        "databases": [],
        "rulesets": [],
        "fetch": None,
        "outcome": outcome,
        "reason_code": code,
        "duration_s": int(time.monotonic() - start),
    }
    return {"receipt": receipt, "reasons": reasons}


# ---------------------------------------------------------------------------
# gitleaks: the head tree and the commits of the pull request, one call
# ---------------------------------------------------------------------------

# The built-in rules, and nothing from the repository: GITLEAKS_CONFIG_TOML
# outranks a .gitleaks.toml. The ignore path is the empty /tmp, so the only
# .gitleaksignore gitleaks could read is one in the scratch repository, and
# that one is the gate's (there is none). gitleaks:allow is not honoured.
#
# The built-in configuration also has a global allowlist of paths: images and
# svg, fonts, pdf and office files, node_modules/, the npm and Python lock
# files, vendor/, go.mod and go.sum, virtualenvs, any path that contains
# "gitleaks.toml", and more. gitleaks skips a secret in such a file without a
# word. The gate does not depend on that list: it gives gitleaks a copy of
# every file of the head and of every change of the pull request under names
# of its own (<dir>/h/<n>, <dir>/c/<n>), which no path rule can match, and
# maps what gitleaks finds there back to the real path. The real paths are
# scanned as well, for the few rules that apply to some paths only (.tf,
# .yaml, .php, nuget.config, .p12).
GITLEAKS_CONFIG = "[extend]\nuseDefault = true\n"
GITLEAKS_CANARY_RULE = "github-pat"
GITLEAKS_SEVERITY = "high"   # gitleaks has no severities: every finding gets this one
_GITLEAKS_COMMITS = re.compile(r"INF (\d+) commits scanned")


def github_token_canary() -> str:
    """A value the built-in github-pat rule matches, made at run time."""
    alphabet = string.ascii_letters + string.digits
    return "gh" + "p_" + "".join(secrets.choice(alphabet) for _ in range(36))


# Content gitleaks reads but cannot match: its rules look for ASCII in the raw
# bytes. A file with NUL bytes is still read (see scratch_repository), so an
# ASCII secret inside a binary file is found; text in UTF-16 or UTF-32, and
# anything compressed, is not. Recognized by the first bytes of the blob.
_COMPRESSED = ((b"PK\x03\x04", "zip archive"), (b"PK\x05\x06", "zip archive"), (b"PK\x07\x08", "zip archive"),
               (b"\x1f\x8b", "gzip stream"), (b"\x1f\x9d", "compress stream"), (b"\xfd7zXZ\x00", "xz stream"),
               (b"7z\xbc\xaf\x27\x1c", "7z archive"), (b"\x28\xb5\x2f\xfd", "zstd stream"),
               (b"\x04\x22\x4d\x18", "lz4 stream"), (b"LZIP", "lzip stream"), (b"Rar!\x1a\x07", "rar archive"))
_BZIP2 = re.compile(rb"^BZh[1-9]1AY&SY")
_WIDE_BOMS = (b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")
_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _wide_layout(head: bytes) -> tuple[int, int] | None:
    """(width, lane) of ASCII text in UTF-16 or UTF-32 without a byte order
    mark: one byte lane of every 2 (or 4) is printable, all the other lanes
    are NUL."""
    for width in (2, 4):
        n = min(len(head), 4096) // width
        if n < 8:
            continue
        lanes = [head[i:n * width:width] for i in range(width)]
        nul = [lane.count(0) / n for lane in lanes]
        text = [i for i in range(width)
                if nul[i] <= 0.05 and sum(b in _PRINTABLE for b in lanes[i]) >= 0.7 * n]
        if len(text) == 1 and all(nul[i] >= 0.6 for i in range(width) if i != text[0]):
            return width, text[0]
    return None


def _wide_text(head: bytes) -> bool:
    return _wide_layout(head) is not None


def unreadable(blob: Blob) -> str | None:
    """Why gitleaks cannot read a blob's content, or None if it can."""
    if blob.head.startswith(_WIDE_BOMS) or (blob.nul and _wide_text(blob.head)):
        return "UTF-16 or UTF-32 text"
    for magic, what in _COMPRESSED:
        if blob.head.startswith(magic):
            return what
    return "bzip2 stream" if _BZIP2.match(blob.head) else None


def judge_gitleaks(report: bytes | None, stderr: str, code: int | None, layout: dict, expected_commits: int,
                   min_severity: str) -> dict:
    """Pure: findings, canaries, commit count and problems from a gitleaks
    run. layout is what the gate gave gitleaks: dir (its own directory),
    snapshot and copy (its two commits), files (the head paths, by the index
    n of their copy dir/h/<n>) and changes ([commit, path] by the index of
    dir/c/<n>). The canaries are dir/h/<len(files)> in the snapshot and
    dir/c/<len(changes)> in the copy."""
    problems: list[tuple[str, str]] = []
    markers = [m for m in ("ERR", "FTL") if re.search(rf"(?m)(?:^|\s){m}\s", stderr)]
    if markers:
        problems.append(("tool_error", "gitleaks logged " + " and ".join(markers)
                         + ": a failing git call still prints \"no leaks found\" and exits 0"))
    found = _GITLEAKS_COMMITS.findall(stderr)
    commits = int(found[-1]) if found else None
    data = None
    if report is not None:
        try:
            data = json.loads(report.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            data = None
    if not isinstance(data, list) or not all(isinstance(f, dict) for f in data):
        problems.append(("tool_error", "gitleaks wrote no readable report"))
        data = []
    own, snapshot, copy = layout["dir"] + "/", layout["snapshot"], layout["copy"]
    files, changes = layout["files"], layout["changes"]
    items, seen, below = [], set(), 0
    hits = {"head": False, "changes": False}
    merged: dict[tuple, set[int]] = {}   # a line of a merge commit -> the parents it is added against
    found_at: list[tuple] = []
    for f in data:
        rule, path, line, commit = f.get("RuleID"), f.get("File"), f.get("StartLine"), f.get("Commit")
        if not (isinstance(rule, str) and isinstance(path, str) and isinstance(commit, str)):
            problems.append(("tool_error", "gitleaks reported a finding without rule, file or commit"))
            continue
        line = line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None
        if path.startswith(own):
            area, _, index = path[len(own):].partition("/")
            n = int(index) if index.isdigit() and str(int(index)) == index else -1
            if area == "h" and commit == snapshot and 0 <= n <= len(files):
                if n == len(files):
                    hits["head"] = hits["head"] or rule == GITLEAKS_CANARY_RULE
                    continue
                path, where = files[n], "head"
            elif area == "c" and commit == copy and 0 <= n <= len(changes):
                if n == len(changes):
                    hits["changes"] = hits["changes"] or rule == GITLEAKS_CANARY_RULE
                    continue
                where, path = changes[n][0], changes[n][1]
                if len(changes[n]) == 4:   # [commit, path, parent, parents] of a merge commit
                    key = (rule, path, line, where, changes[n][3])
                    merged.setdefault(key, set()).add(changes[n][2])
                    continue
            else:
                problems.append(("tool_error", "gitleaks reported a file in the gate's own directory that it did not write"))
                continue
        elif commit == copy:
            problems.append(("tool_error", "gitleaks reported a file that is not in the gate's copy of the changes"))
            continue
        else:
            where = "head" if commit == snapshot else commit
        found_at.append((rule, path, line, where))
    # A line of a merge commit is its own content only if it is added
    # against every parent; otherwise it came from one of them.
    found_at += [key[:4] for key, parents in merged.items() if len(parents) == key[4]]
    wheres: dict[tuple, set[str]] = {}
    for rule, path, line, where in found_at:
        # The real path and the copy report the same finding: keep one.
        item = {"rule": rule, "path": path, "line": line, "severity": GITLEAKS_SEVERITY,
                "fingerprint": sha256_hex(canonical(["gitleaks", rule, path, line, where]))}
        if item["fingerprint"] in seen:
            continue
        seen.add(item["fingerprint"])
        if RANK[item["severity"]] >= RANK[min_severity]:
            items.append(item)
            wheres.setdefault((rule, path, line), set()).add(where)
        else:
            below += 1
    if code == 0 and data:
        problems.append(("tool_error", "gitleaks exited 0 yet reported findings"))
    if code == 1 and not data:
        problems.append(("tool_error", "gitleaks exited 1 yet reported no finding"))
    if commits is None:
        problems.append(("tool_error", "gitleaks did not report how many commits it scanned"))
    elif commits == 0:
        problems.append(("zero_scanned", "gitleaks scanned 0 commits"))
    elif commits != expected_commits:
        problems.append(("coverage_gap", (f"gitleaks scanned {commits} commit(s) with added lines, expected "
                                          f"{expected_commits}: {expected_commits - 2} of the pull request, the "
                                          f"snapshot of its head tree and the copy of its changes")))
    # A canary counts only as a finding that fails under the policy, like the
    # canaries of osv-scanner: a threshold above every gitleaks finding would
    # turn gitleaks off while the canaries still looked found.
    failing = RANK[GITLEAKS_SEVERITY] >= RANK[min_severity]
    canaries = [{"id": "gitleaks-builtin", "expected_rule": GITLEAKS_CANARY_RULE, "found": hits["head"] and failing},
                {"id": "gitleaks-changes", "expected_rule": GITLEAKS_CANARY_RULE, "found": hits["changes"] and failing}]
    missed = [c["id"] for c in canaries if not c["found"]]
    if missed and not failing and any(hits.values()):
        problems.append(("canary_missed", (f"gitleaks reported its canaries, but every gitleaks finding is "
                                           f"{GITLEAKS_SEVERITY}, below min_severity {min_severity} of lock.json, so "
                                           f"no secret could fail the gate")))
    elif missed:
        problems.append(("canary_missed", f"gitleaks did not report the {GITLEAKS_CANARY_RULE} canary of the gate: "
                                          + ", ".join(missed)))
    return {"items": items, "below": below, "canaries": canaries, "markers": markers, "commits": commits,
            "problems": problems, "listing": gitleaks_listing(wheres)}


def gitleaks_listing(wheres: dict[tuple, set[str]]) -> str:
    """The findings of gitleaks for a person: one entry per place, saying
    whether it is in the head tree, in commits of the pull request, or both.
    A secret only in the history stays in the branch after the file is
    fixed: that entry says so, and what to do."""
    entries, history = [], False
    for (rule, path, line), found in sorted(wheres.items(), key=lambda kv: (kv[0][1], kv[0][0], kv[0][2] or 0)):
        commits = sorted(w[:12] for w in found if w != "head")
        named = ("commit " if len(commits) == 1 else "commits ") + ", ".join(commits)
        where = ("head tree and " + named if commits else "head tree") if "head" in found else \
            f"only in {named}, not in the head tree"
        history = history or "head" not in found
        entries.append(f"{rule} {shown(path)}" + (f":{line}" if line else "") + f" ({where})")
    text = "; ".join(entries[:MAX_SHOWN]) + (" ..." if len(entries) > MAX_SHOWN else "")
    if history:
        text += (". A secret in a commit of the pull request stays in the branch even after the file is fixed: "
                 "revoke the key, because GitHub keeps pushed commits readable, then rewrite the branch without it")
    return text


def gitleaks_readable(s: Scan, files: list[Entry], changes: list[Change]) -> tuple[list[str], list[tuple[str, str]]]:
    """(the head paths gitleaks cannot read, problems). A file it cannot read
    is not counted as scanned. One that a commit of the pull request adds or
    changes is a coverage gap: its content reaches the default branch
    unchecked. One that only the default branch has is counted, but blocks
    no pull request."""
    opaque = [e.path for e in files if unreadable(s.blobs[e.oid])]
    blobs = dict(s.blobs)
    blobs.update(s.git.blobs(sorted({c.new for c in changes} - blobs.keys())))
    kinds = {}
    for c in changes:
        what = unreadable(blobs[c.new])
        if what:
            kinds.setdefault(c.path, what)
    problems = []
    if kinds:
        shown_kinds = "; ".join(f"{shown(p)} ({kinds[p]})" for p in sorted(kinds)[:MAX_SHOWN])
        problems.append(("coverage_gap", (f"gitleaks cannot read {len(kinds)} file(s) that the pull request adds or "
                                          f"changes, so their content is not scanned for secrets: {shown_kinds}"
                                          + (" ..." if len(kinds) > MAX_SHOWN else "")
                                          + ". Keep such content as plain text, or remove the file")))
    return opaque, problems


def nest(git: Git, tree: str, *names: str) -> str:
    """The tree that holds tree at the path names[0]/names[1]/..."""
    for name in reversed(names):
        tree = git.mktree([f"040000 tree {tree}\t{name}".encode()])
    return tree


def run_gitleaks(s: Scan) -> dict:
    name = "gitleaks"
    version, ready = prepare(s, name)
    if ready:
        return {"reasons": ready}
    work = s.scratch / "gitleaks"
    out = work / "out"
    out.mkdir(parents=True)
    repo = work / "history.git"
    hist = scratch_repository(repo, s.git.objects, s.scratch / "gitleaks-git")
    files = sorted(s.regular_files(), key=lambda e: e.path)
    changes = s.git.pr_changes(s.head, s.base)
    own = "security-gate-canary-" + os.urandom(16).hex()

    def canary() -> str:
        return hist.write_blob(f'token = "{github_token_canary()}"\n'.encode())

    # The snapshot: a root commit whose tree is the head tree plus the gate's
    # directory, so `git log -p` shows every file of the head as added lines,
    # under its own path and as the copy h/<n>, next to the canary.
    copies = hist.mktree([f"100644 blob {e.oid}\t{n}".encode() for n, e in enumerate(files)]
                         + [f"100644 blob {canary()}\t{len(files)}".encode()])
    root = hist.mktree(s.git.root_records(s.head) + [f"040000 tree {nest(hist, copies, 'h')}\t{own}".encode()])
    snapshot = hist.commit_tree(root, "security-gate: snapshot of the pull request head")
    # The copy of the changes: a commit whose diff from its parent is every
    # change of the pull request, as c/<n>, plus the canary. gitleaks reads it
    # in the same call; the parent itself is excluded.
    before = hist.mktree([f"100644 blob {c.old}\t{n}".encode() for n, c in enumerate(changes) if c.old])
    after = hist.mktree([f"100644 blob {c.new}\t{n}".encode() for n, c in enumerate(changes)]
                        + [f"100644 blob {canary()}\t{len(changes)}".encode()])
    parent = hist.commit_tree(nest(hist, before, own, "c"), "security-gate: the pull request before its changes")
    copy = hist.commit_tree(nest(hist, after, own, "c"), "security-gate: the changes of the pull request", (parent,))
    s.canary_commit = snapshot
    expected = hist.commits_with_additions([s.head, "^" + s.base]) + 2
    (repo / "objects" / "info" / "alternates").write_text("/sg/pr-objects\n", encoding="utf-8")
    argv = ["git", "--no-banner", "--no-color", "--redact", "--exit-code", "1", "--ignore-gitleaks-allow",
            "--gitleaks-ignore-path", "/tmp", "--log-level", "info", "--report-format", "json",
            "--report-path", "out/gitleaks.json", "--log-opts", f"{snapshot} {copy} {s.head} ^{s.base} ^{parent}",
            "history.git"]
    run = s.docker.run(s.ref(name), argv, mounts=((repo, "/sg/history.git", True), (s.git.objects, "/sg/pr-objects", True),
                                                   (out, "/sg/out", False)),
                       variables={"GITLEAKS_CONFIG_TOML": GITLEAKS_CONFIG}, timeout=s.spec(name)["timeout_s"], ok=(0, 1))
    report_file = out / "gitleaks.json"
    report = report_file.read_bytes() if run.code is not None and report_file.is_file() else None
    layout = {"dir": own, "snapshot": snapshot, "copy": copy, "files": [e.path for e in files],
              "changes": [[c.commit, c.path] if c.parents == 1 else [c.commit, c.path, c.parent, c.parents]
                          for c in changes]}
    j = judge_gitleaks(report, run.err, run.code, layout, expected, s.spec(name)["policy"]["min_severity"])
    opaque, problems = gitleaks_readable(s, files, changes)
    problems = run_problem(name, run, (0, 1)) + j["problems"] + problems
    receipt, reasons = tool_receipt(
        s, name, version, argv, run,
        scanned={"files": len(files) - len(opaque), "commits": j["commits"], "packages": None, "paths": [""],
                 "paths_truncated": False, "lockfiles": [], "unreadable": len(opaque), **NOT_SEMGREP},
        canaries=j["canaries"], markers=j["markers"], items=j["items"], below=j["below"], problems=problems,
        rules_loaded=None, rules_sha256=sha256_hex(GITLEAKS_CONFIG.encode()), listing=j["listing"])
    return {"receipt": receipt, "reasons": reasons}


# ---------------------------------------------------------------------------
# osv-scanner: lock files of the head, database downloaded apart
# ---------------------------------------------------------------------------

# Lock file name -> (osv-scanner extractor, ecosystem). Each extractor was run
# with osv-scanner 2.6.0 on a lock file with a known vulnerability. Its -L
# option needs the extractor's own name: npm-shrinkwrap.json has the format of
# package-lock.json, and "-L npm-shrinkwrap.json:..." is refused.
LOCKFILES = {"package-lock.json": ("package-lock.json", "npm"), "npm-shrinkwrap.json": ("package-lock.json", "npm"),
             "pnpm-lock.yaml": ("pnpm-lock.yaml", "npm"), "yarn.lock": ("yarn.lock", "npm"),
             "bun.lock": ("bun.lock", "npm"), "uv.lock": ("uv.lock", "PyPI"), "poetry.lock": ("poetry.lock", "PyPI"),
             "Pipfile.lock": ("Pipfile.lock", "PyPI"), "pdm.lock": ("pdm.lock", "PyPI"),
             "pylock.toml": ("pylock.toml", "PyPI")}
_PYLOCK_NAME = re.compile(r"^pylock\.[^/]+\.toml$")
# requirements.txt, requirements-dev.txt, dev-requirements.txt,
# requirements.prod.txt; and any .txt in a directory named requirements.
_REQUIREMENTS_NAME = re.compile(r"^(?:[^/]*[-_.])?requirements(?:[-_.][^/]*)?\.txt$")
# Dependency manifests that osv-scanner sees only through a lock file next to
# them or in a directory above (workspaces), and the lock files of ecosystems
# whose databases this gate does not download. Until expected.json exists,
# each is an unexpected_manifest: the gate cannot vouch for those packages.
_NPM_LOCK_NAMES = ", ".join(n for n, (_, eco) in LOCKFILES.items() if eco == "npm")
_UNSCANNED_ECOSYSTEMS = {
    "go.mod": "Go", "Cargo.lock": "crates.io", "Gemfile.lock": "RubyGems", "gems.locked": "RubyGems",
    "composer.lock": "Packagist", "pom.xml": "Maven", "gradle.lockfile": "Maven", "buildscript-gradle.lockfile": "Maven",
    "packages.lock.json": "NuGet", "pubspec.lock": "Pub", "mix.lock": "Hex", "Package.resolved": "SwiftURL",
    "Podfile.lock": "CocoaPods", "renv.lock": "CRAN", "conan.lock": "ConanCenter", "stack.yaml.lock": "Hackage",
    "cabal.project.freeze": "Hackage", "bun.lockb": "npm, binary bun.lockb", "deno.lock": "npm and JSR, deno.lock",
}
# Directories of installed or vendored packages: their manifests describe the
# packages, not the repository's dependencies.
_INSTALLED_DIRS = frozenset({"node_modules", "bower_components", "vendor", "site-packages"})
# The canaries: one lock file per ecosystem, with a version that has a known
# critical vulnerability with a fix (both checked against OSV). They must come
# out of the same call as failing findings under the policy, or the result is
# inconclusive.
OSV_CANARIES = (
    {"id": "osv-npm", "file": "package-lock.json", "parser": "package-lock.json", "ecosystem": "npm",
     "name": "minimist", "version": "1.2.5", "expected_rule": "CVE-2021-44906",
     "content": json.dumps({"name": "security-gate-canary", "version": "0.0.0", "lockfileVersion": 3,
                            "requires": True,
                            "packages": {"": {"name": "security-gate-canary", "version": "0.0.0",
                                              "dependencies": {"minimist": "1.2.5"}},
                                         "node_modules/minimist": {"version": "1.2.5"}}}, indent=2) + "\n"},
    {"id": "osv-pypi", "file": "requirements.txt", "parser": "requirements.txt", "ecosystem": "PyPI",
     "name": "pyyaml", "version": "5.3.1", "expected_rule": "CVE-2020-14343", "content": "pyyaml==5.3.1\n"},
)
_CVSS_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))
_GHSA_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
_PINNED_REQUIREMENT = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(?:\[[A-Za-z0-9._,\s-]*\])?\s*===?\s*"
                                 r"[A-Za-z0-9][A-Za-z0-9._+!-]*\s*(?:;.*)?$")
_REQUIREMENT_OPTIONS = ("--index-url", "-i", "--extra-index-url", "--find-links", "-f", "--trusted-host",
                        "--prefer-binary", "--no-binary", "--only-binary", "--pre", "--require-hashes", "--no-index")


def lockfile_kind(path: str) -> tuple[str, str] | None:
    """(osv-scanner parser, ecosystem) for a lock file path, or None. Lock
    files inside node_modules belong to installed packages, not to the
    repository's own dependencies."""
    parts = path.split("/")
    if "node_modules" in parts[:-1]:
        return None
    if parts[-1] in LOCKFILES:
        return LOCKFILES[parts[-1]]
    if _PYLOCK_NAME.match(parts[-1]):
        return ("pylock.toml", "PyPI")
    if _REQUIREMENTS_NAME.match(parts[-1]) or (len(parts) > 1 and parts[-2] == "requirements"
                                                and parts[-1].endswith(".txt")):
        return ("requirements.txt", "PyPI")
    return None


def _declares(name: str, data: bytes) -> bool | None:
    """Whether a manifest declares dependencies: True, False, or None when it
    cannot be read (then it counts as declaring them: fail closed)."""
    import tomllib  # Python 3.11+; imported here so that main() can refuse an older interpreter
    try:
        text = data.decode("utf-8-sig")
        if name == "package.json":
            doc = json.loads(text)
            return any(isinstance(doc.get(k), dict) and bool(doc[k])
                       for k in ("dependencies", "devDependencies", "optionalDependencies"))
        if name == "pyproject.toml":
            doc = tomllib.loads(text)
            project, tool = doc.get("project") or {}, doc.get("tool") or {}
            poetry = tool.get("poetry") or {}
            groups = (poetry.get("group") or {}).values()
            return bool(project.get("dependencies") or project.get("optional-dependencies")
                        or {"dependencies", "optional-dependencies"} & set(project.get("dynamic") or [])
                        or doc.get("dependency-groups") or set(poetry.get("dependencies") or {}) - {"python"}
                        or poetry.get("dev-dependencies") or any((g or {}).get("dependencies") for g in groups)
                        or (tool.get("pdm") or {}).get("dev-dependencies")
                        or (tool.get("uv") or {}).get("dev-dependencies"))
        if name in ("setup.py", "setup.cfg"):
            return "install_requires" in text
        if name == "go.mod":
            return re.search(r"(?m)^\s*require\b", text) is not None
        if name == "pom.xml":
            return "<dependency" in text
    except (UnicodeDecodeError, ValueError, AttributeError, TypeError):
        return None
    return True


def unexpected_manifests(s: Scan) -> list[tuple[str, str]]:
    """(path, why) for every dependency manifest of the head without a lock
    file that osv-scanner reads, and every lock file of an ecosystem this
    gate does not scan. A lock file counts for a manifest in its directory
    or in any directory below it (workspaces)."""
    locks = {"npm": set(), "PyPI": set()}
    for e in s.entries:
        kind = lockfile_kind(e.path)
        if kind:
            folder = posixpath.dirname(e.path)
            locks[kind[1]].add(folder)
            if posixpath.basename(folder) == "requirements":
                locks[kind[1]].add(posixpath.dirname(folder))

    def covered(path: str, ecosystem: str) -> bool:
        folder = posixpath.dirname(path)
        while True:
            if folder in locks[ecosystem]:
                return True
            if not folder:
                return False
            folder = posixpath.dirname(folder)

    names = {e.path for e in s.entries}
    out = []
    for e in s.entries:
        parts = e.path.split("/")
        name = parts[-1]
        if _INSTALLED_DIRS & set(parts[:-1]) or e.kind != "blob" or e.mode not in FILE_MODES:
            continue
        if name not in _UNSCANNED_ECOSYSTEMS and name not in ("package.json", "pyproject.toml", "Pipfile", "setup.py",
                                                            "setup.cfg"):
            continue
        try:
            declares = _declares(name, s.git.blob_bytes(e.oid, MAX_LOCK_BYTES))
        except GitError:
            declares = None
        if declares is False:
            continue
        unread = " (cannot be read, so its dependencies are unknown)" if declares is None else ""
        if name in _UNSCANNED_ECOSYSTEMS:
            out.append((e.path, f"{_UNSCANNED_ECOSYSTEMS[name]}: an ecosystem this gate does not scan{unread}"))
        elif name == "package.json" and not covered(e.path, "npm"):
            out.append((e.path, f"npm dependencies without a lock file ({_NPM_LOCK_NAMES}) here or above{unread}"))
        elif name == "Pipfile" and posixpath.join(posixpath.dirname(e.path), "Pipfile.lock") not in names:
            out.append((e.path, f"Pipfile without Pipfile.lock next to it{unread}"))
        elif name in ("pyproject.toml", "setup.py", "setup.cfg") and not covered(e.path, "PyPI"):
            out.append((e.path, (f"Python dependencies without a lock file or pinned requirements file here or "
                                 f"above{unread}")))
    return sorted(out)


def unpinned_requirements(text: str) -> list[str]:
    """Lines of a requirements file whose version osv-scanner cannot know:
    anything but name==version. Includes (-r, -c) are not followed by the
    gate, so they count too."""
    bad, logical = [], ""
    for raw in text.splitlines() + [""]:
        line = re.sub(r"(?:^|\s)#.*$", "", raw).rstrip()
        if line.endswith("\\"):
            logical += line[:-1] + " "
            continue
        logical = (logical + line).strip()
        if logical:
            tokens = [t for t in logical.split() if not t.startswith("--hash")]
            text_line = " ".join(tokens)
            if text_line.startswith("-"):
                option = text_line.split("=", 1)[0].split()[0]
                if option not in _REQUIREMENT_OPTIONS:
                    bad.append(text_line.split()[0])
            elif not _PINNED_REQUIREMENT.match(text_line):
                bad.append(text_line.split()[0][:40])
        logical = ""
    return bad


def cvss_band(score: object) -> str | None:
    try:
        value = float(str(score))
    except ValueError:
        return None
    for floor, band in _CVSS_BANDS:
        if value >= floor:
            return band
    return None


def _norm(name: object, ecosystem: str) -> str:
    text = str(name or "").lower()
    return re.sub(r"[-_.]+", "-", text) if ecosystem == "PyPI" else text


def _has_fix(records: list[dict], name: str, ecosystem: str) -> bool:
    """A fixed version is published for this package. Without affected data
    for the package the answer is yes: the gate fails closed."""
    seen = False
    for record in records:
        for affected in record.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            pkg = affected.get("package") or {}
            if pkg.get("ecosystem") != ecosystem or _norm(pkg.get("name"), ecosystem) != _norm(name, ecosystem):
                continue
            seen = True
            for rng in affected.get("ranges") or []:
                for event in (rng or {}).get("events") or []:
                    if isinstance(event, dict) and event.get("fixed"):
                        return True
    return not seen


def judge_osv(scan: bytes | None, code: int | None, expected: list[tuple[str, str]], policy: dict) -> dict:
    """Pure: findings, canaries and per lock file package counts from the JSON
    of an osv-scanner run (--all-packages). Paths are /sg/tree/<repository
    path> and /sg/canary/<file>."""
    problems: list[tuple[str, str]] = []
    try:
        doc = json.loads((scan or b"").decode("utf-8"))
        results = doc["results"]
        if not isinstance(results, list):
            raise TypeError
    except (UnicodeDecodeError, ValueError, KeyError, TypeError):
        doc, results = None, []
        problems.append(("tool_error", "osv-scanner wrote no readable JSON report"))
    counts: dict[str, int] = {}
    items, below, any_vuln = [], 0, False
    canary_hits: set[str] = set()
    for result in results:
        try:
            source = result["source"]["path"]
            packages = result.get("packages") or []
        except (KeyError, TypeError):
            problems.append(("tool_error", "osv-scanner reported a result without a source"))
            continue
        if not isinstance(source, str) or not isinstance(packages, list):
            problems.append(("tool_error", "osv-scanner reported a result of an unexpected type"))
            continue
        if source.startswith("/sg/tree/"):
            rel, canary = source[len("/sg/tree/"):], None
        elif source.startswith("/sg/canary/"):
            rel, canary = None, source[len("/sg/canary/"):]
        else:
            problems.append(("tool_error", "osv-scanner reported a file outside the scanned directories"))
            continue
        if rel is not None:
            counts[rel] = counts.get(rel, 0) + len(packages)
        for p in packages:
            pkg = (p or {}).get("package") or {}
            name, version, eco = str(pkg.get("name", "")), str(pkg.get("version", "")), str(pkg.get("ecosystem", ""))
            records = [v for v in (p.get("vulnerabilities") or []) if isinstance(v, dict)]
            by_id = {v.get("id"): v for v in records}
            for group in p.get("groups") or []:
                ids = [str(i) for i in (group.get("ids") or [])]
                aliases = [str(a) for a in (group.get("aliases") or [])]
                if not ids:
                    continue
                any_vuln = True
                members = [by_id[i] for i in ids if i in by_id]
                severity = cvss_band(group.get("max_severity", "")) or max(
                    (_GHSA_SEVERITY.get(str((m.get("database_specific") or {}).get("severity", "")).upper(), "")
                     for m in members), key=lambda sev: RANK.get(sev, -1), default="")
                severity = severity if severity in RANK else policy["unknown_severity"]
                malicious = any(x.startswith("MAL-") for x in ids + aliases)
                fixed = _has_fix(members, name, eco)
                if malicious and policy["malicious_fails"]:
                    severity, failing = "critical", True
                else:
                    failing = RANK[severity] >= RANK[policy["min_severity"]] and (fixed or not policy["require_fix"])
                rule = next((i for i in ids if i.startswith("GHSA-")), None) or next(
                    (a for a in aliases if a.startswith("CVE-")), None) or min(ids)
                if canary is not None:
                    for c in OSV_CANARIES:
                        if (canary == c["file"] and failing and _norm(name, eco) == c["name"] and version == c["version"]
                                and c["expected_rule"] in ids + aliases):
                            canary_hits.add(c["id"])
                    continue
                if failing:
                    items.append({"rule": rule, "path": rel, "line": None, "severity": severity,
                                  "fingerprint": sha256_hex(canonical(["osv-scanner", rule, rel, eco, name, version]))})
                else:
                    below += 1
    if doc is not None and code == 0 and any_vuln:
        problems.append(("tool_error", "osv-scanner exited 0 yet reported vulnerabilities"))
    if doc is not None and code == 1 and not any_vuln:
        problems.append(("tool_error", "osv-scanner exited 1 yet reported no vulnerability"))
    scanned = [path for path, _ in expected if counts.get(path, 0) > 0]
    missing = [path for path, _ in expected if counts.get(path, 0) == 0]
    if expected and not scanned:
        problems.append(("zero_scanned", f"osv-scanner found 0 packages in all {len(expected)} lock file(s): "
                                         + listed(missing)))
    elif missing:
        problems.append(("coverage_gap", f"osv-scanner found 0 packages in {len(missing)} lock file(s): "
                                         + listed(missing)))
    canaries = [{"id": c["id"], "expected_rule": c["expected_rule"], "found": c["id"] in canary_hits}
                for c in OSV_CANARIES]
    missed = [c["id"] for c in canaries if not c["found"]]
    if missed:
        problems.append(("canary_missed", "osv-scanner did not report the canary vulnerabilities as failing: "
                                          + ", ".join(missed)))
    return {"items": items, "below": below, "canaries": canaries, "counts": counts, "scanned": scanned,
            "missing": missing, "problems": problems}


_MODIFIED = re.compile(rb'"modified"\s*:\s*"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})')


def inspect_database(path: Path) -> dict:
    """sha256, number of records and the newest `modified` of an OSV export.
    The zip entries carry no timestamps, so the age of the data is the age of
    its newest record."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            digest.update(chunk)
    records, newest = 0, ""
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            records += 1
            with zf.open(info) as fh:
                m = _MODIFIED.search(fh.read(MAX_RECORD))
            if m and m.group(1).decode() > newest:
                newest = m.group(1).decode()
    return {"sha256": "sha256:" + digest.hexdigest(), "records": records, "newest": newest + "Z" if newest else None}


def check_databases(s: Scan, db_dir: Path, used: set[str]) -> tuple[list[dict], list[tuple[str, str]]]:
    entries, problems = [], []
    clock = datetime.datetime.now(datetime.UTC)
    for db in s.spec("osv-scanner")["databases"]:
        entry = {"name": db["name"], "ecosystem": db["ecosystem"], "source": db["source"], "path": db["path"],
                 "sha256": None, "records": None, "newest_record": None, "age_s": None,
                 "max_age_s": db["max_age_hours"] * 3600, "used": db["ecosystem"] in used}
        path = safe_join(db_dir, db["path"])
        try:
            if path is None or path.is_symlink() or not path.is_file():
                raise OSError("missing")
            info = inspect_database(path)
        except (OSError, zipfile.BadZipFile, ValueError):
            problems.append(("offline_db", f"the {db['name']} database was not downloaded or cannot be read"))
            entries.append(entry)
            continue
        entry.update(sha256=info["sha256"], records=info["records"], newest_record=info["newest"])
        if info["newest"]:
            newest = datetime.datetime.strptime(info["newest"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.UTC)
            entry["age_s"] = max(0, int((clock - newest).total_seconds()))
        if not info["records"] or entry["age_s"] is None:
            problems.append(("offline_db", f"the {db['name']} database has no dated records"))
        elif entry["used"] and entry["age_s"] > entry["max_age_s"]:
            problems.append(("offline_db", (f"the {db['name']} database is {entry['age_s'] // 3600} h old, more "
                                            f"than {db['max_age_hours']} h")))
        entries.append(entry)
    return entries, problems


def run_osv(s: Scan) -> dict:
    name = "osv-scanner"
    expected, problems, excluded = [], [], []
    for e in s.entries:
        kind = lockfile_kind(e.path)
        if kind is None:
            continue
        if e.kind != "blob" or e.mode not in FILE_MODES or safe_join(Path("/"), e.path) is None or "," in e.path:
            excluded.append(e.path)
        if e.kind != "blob" or e.mode not in FILE_MODES:
            problems.append(("coverage_gap", f"lock file {shown(e.path)} is a symlink or submodule and is not scanned"))
        elif safe_join(Path("/"), e.path) is None:
            problems.append(("coverage_gap", f"lock file {shown(e.path)} has a control character and is not scanned"))
        elif "," in e.path:
            # osv-scanner splits the value of -L on commas: "a,b/x.lock" would
            # be two paths, neither of which exists.
            problems.append(("coverage_gap", (f"lock file {shown(e.path)} has a comma in its path, which "
                                              f"osv-scanner cannot take, and is not scanned")))
        else:
            expected.append((e.path, kind, e.oid))
    expected.sort()
    manifests = unexpected_manifests(s)
    # A lock file the gate cannot hand to osv-scanner is expected and missing.
    every = sorted([p for p, _, _ in expected] + excluded)
    coverage = {"expected_lockfiles": every, "scanned_lockfiles": [], "missing": every,
                "unexpected_manifests": [p for p, _ in manifests], "outcome": PASS}
    uncovered = []
    if manifests:
        uncovered.append(("unexpected_manifest", (f"{len(manifests)} dependency file(s) whose packages osv-scanner in "
                                                  f"this gate does not see: "
                                                  + "; ".join(f"{shown(p)} ({why})" for p, why in manifests[:MAX_SHOWN])
                                                  + (" ..." if len(manifests) > MAX_SHOWN else ""))))
    version, ready = prepare(s, name)
    if ready:
        coverage["outcome"] = INCONCLUSIVE if every or manifests else PASS
        return {"reasons": ready + problems + uncovered, "coverage": coverage}
    work = s.scratch / "osv"
    tree, canary_dir, config, db_dir, fetch_out, out = (work / d for d in ("tree", "canary", "config", "db",
                                                                            "fetch-out", "out"))
    for d in (tree, canary_dir, config, db_dir, fetch_out, out):
        d.mkdir(parents=True)
    (config / "osv-scanner.toml").write_bytes(b"")
    for c in OSV_CANARIES:
        (canary_dir / c["file"]).write_text(c["content"], encoding="utf-8")
    unpinned = []
    for path, (parser, _), oid in expected:
        data = s.git.blob_bytes(oid, MAX_SCANNED_FILE)
        write_new_file(safe_join(tree, path), data)
        if parser == "requirements.txt":
            try:
                bad = unpinned_requirements(data.decode("utf-8"))
            except UnicodeDecodeError:
                bad = ["(not UTF-8)"]
            if bad:
                unpinned.append(path)
    if unpinned:
        problems.append(("unpinned_requirements", f"{len(unpinned)} requirements file(s) list packages without an "
                                                  f"exact version (name==version), so osv-scanner cannot know them: "
                                                  + listed(unpinned)))
    canary_args = [a for c in OSV_CANARIES for a in ("-L", f"{c['parser']}:canary/{c['file']}")]
    common = ["--no-call-analysis=all", "--format", "json", "--all-packages", "--config", "config/osv-scanner.toml"]
    variables = {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/sg/db"}
    timeout = s.spec(name)["timeout_s"]
    # 1. Download: network, and no pull request data mounted.
    fetch_argv = ["scan", "source", "--offline-vulnerabilities", "--download-offline-databases", "--no-resolve",
                  *common, "--output-file", "out/fetch.json", *canary_args]
    fetch = s.docker.run(s.ref(name), fetch_argv, network=True, variables=variables, timeout=timeout, ok=(0, 1),
                         mounts=((canary_dir, "/sg/canary", True), (config, "/sg/config", True),
                                 (db_dir, "/sg/db", False), (fetch_out, "/sg/out", False)))
    fetch_record = {"argv": fetch_argv, "network": "default", "exit_code": fetch.code if fetch.code is not None else -1,
                    "retried": fetch.retried, "duration_s": fetch.duration}
    used = {eco for _, (_, eco), _ in expected}
    databases, db_problems = check_databases(s, db_dir, used)
    if fetch.code not in (0, 1):
        db_problems.insert(0, ("offline_db", f"the database download {fetch.detail or f'exited {fetch.code}'}"))
    # 2. Scan: no network, everything read-only but the report directory.
    tree_args = [a for path, (parser, _), _ in expected for a in ("-L", f"{parser}:tree/{path}")]
    argv = ["scan", "source", "--offline", "--offline-vulnerabilities", "--no-resolve", *common,
            "--output-file", "out/scan.json", *tree_args, *canary_args]
    run = s.docker.run(s.ref(name), argv, variables=variables, timeout=timeout, ok=(0, 1),
                       mounts=((tree, "/sg/tree", True), (canary_dir, "/sg/canary", True), (config, "/sg/config", True),
                               (db_dir, "/sg/db", True), (out, "/sg/out", False)))
    report_file = out / "scan.json"
    report = report_file.read_bytes() if run.code is not None and report_file.is_file() else None
    j = judge_osv(report, run.code, [(p, eco) for p, (_, eco), _ in expected], s.spec(name)["policy"])
    problems = run_problem(name, run, (0, 1)) + db_problems + problems + j["problems"]
    missing = sorted(j["missing"] + excluded)
    coverage.update(scanned_lockfiles=j["scanned"], missing=missing,
                    outcome=INCONCLUSIVE if missing or run.code not in (0, 1) or manifests else PASS)
    paths = [p for p, _, _ in expected]
    receipt, reasons = tool_receipt(
        s, name, version, argv, run,
        scanned={"files": len(expected), "commits": None, "packages": sum(j["counts"].get(p, 0) for p in paths),
                 "paths": paths[:MAX_PATHS], "paths_truncated": len(paths) > MAX_PATHS,
                 "lockfiles": [{"path": p, "packages": j["counts"].get(p, 0)} for p in paths], "unreadable": None,
                 **NOT_SEMGREP},
        canaries=j["canaries"], markers=[], items=j["items"], below=j["below"], problems=problems,
        rules_loaded=sum(db["records"] or 0 for db in databases),
        rules_sha256=sha256_hex(canonical([[db["name"], db["sha256"]] for db in databases])),
        databases=databases, fetch=fetch_record)
    return {"receipt": receipt, "reasons": reasons + uncovered, "coverage": coverage}


# ---------------------------------------------------------------------------
# zizmor: the workflows of the head
# ---------------------------------------------------------------------------

ZIZMOR_CANARY = "canary/.github/workflows/security-gate-canary.yml"
ZIZMOR_CANARY_RULE = "template-injection"
# A run step that expands an attacker-controlled issue title: zizmor reports
# template-injection, high, on it.
ZIZMOR_CANARY_TEXT = ("name: security-gate-canary\non: issues\npermissions: {}\njobs:\n  canary:\n"
                      "    runs-on: ubuntu-24.04\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n")
ZIZMOR_FINDING_CODES = frozenset({0, 11, 12, 13, 14})
_ZIZMOR_SEVERITY = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
_WORKFLOW_FILE = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _zizmor_paths(item: object, root: str = "") -> set[str] | None:
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
        path = path.removeprefix("./")
        if not path.startswith(root):
            return None
        paths.add(path[len(root):])
    return paths


def zizmor_post_filter(findings: list, owned: bytes | None, reference: bytes | None,
                       confirmed: bool, root: str = "") -> tuple[list, list]:
    """Remove exactly one zizmor finding: dangerous-triggers located only in
    the owned workflow, when that file is byte for byte the reference (the
    default branch version, or the template in this repository's own CI) or
    its fingerprint was confirmed by a human. Anything else is kept, so two
    such findings, a renamed audit or a changed file stay red. root is the
    directory zizmor saw the repository under."""
    candidates = [i for i, item in enumerate(findings)
                  if isinstance(item, dict) and item.get("ident") == "dangerous-triggers"
                  and _zizmor_paths(item, root) == {WORKFLOW_PATH}]
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


def _primary(item: dict) -> tuple[str | None, int | None]:
    locations = [loc for loc in item.get("locations") or [] if isinstance(loc, dict)]
    pick = next((loc for loc in locations if (loc.get("symbolic") or {}).get("kind") == "Primary"),
                locations[0] if locations else None)
    try:
        path = pick["symbolic"]["key"]["Local"]["verbatim_path"]
    except (KeyError, TypeError):
        return None, None
    try:
        line = int(pick["concrete"]["location"]["start_point"]["row"]) + 1
    except (KeyError, TypeError, ValueError):
        line = None
    return (path.removeprefix("./") if isinstance(path, str) else None), line


def judge_zizmor(stdout: bytes, stderr: str, code: int | None, expected: list[str], owned: bytes | None,
                 reference: bytes | None, confirmed: bool, policy: dict) -> dict:
    """Pure: findings, canary, post-filter and coverage from a zizmor run on
    the inputs tree/ (the head's workflows) and canary/."""
    problems: list[tuple[str, str]] = []
    completed = set()
    for line in _ANSI.sub("", stderr).splitlines():
        m = re.search(r"\bcompleted (\S.*?)\s*$", line)
        if m:
            completed.add(m.group(1).removeprefix("./"))
    try:
        findings = json.loads(stdout.decode("utf-8"))
        if not isinstance(findings, list):
            raise TypeError
    except (UnicodeDecodeError, ValueError, TypeError):
        findings = []
        problems.append(("tool_error", "zizmor wrote no readable JSON report"))
    def severity_of(f: dict) -> str:
        return _ZIZMOR_SEVERITY.get(str((f.get("determinations") or {}).get("severity", "")), policy["unknown_severity"])

    # The canary counts only as a finding that fails under the policy.
    reported = [f for f in findings if isinstance(f, dict) and f.get("ident") == ZIZMOR_CANARY_RULE
                and _primary(f)[0] == ZIZMOR_CANARY]
    canary = any(RANK[severity_of(f)] >= RANK[policy["min_severity"]] for f in reported)
    raw = [f for f in findings if not (isinstance(f, dict) and (_primary(f)[0] or "").startswith("canary/"))]
    kept, removed = zizmor_post_filter(raw, owned, reference, confirmed, root="tree/")
    items, below = [], 0
    for f in kept:
        path, line = _primary(f) if isinstance(f, dict) else (None, None)
        if not path or not path.startswith("tree/") or not isinstance(f.get("ident"), str):
            problems.append(("tool_error", "zizmor reported a finding outside the scanned workflows"))
            continue
        severity = severity_of(f)
        rel = path[len("tree/"):]
        item = {"rule": f["ident"], "path": rel, "line": line, "severity": severity,
                "fingerprint": sha256_hex(canonical(["zizmor", f["ident"], rel, line]))}
        if RANK[severity] >= RANK[policy["min_severity"]]:
            items.append(item)
        else:
            below += 1
    if code == 0 and findings:
        problems.append(("tool_error", "zizmor exited 0 yet reported findings"))
    if code in ZIZMOR_FINDING_CODES - {0} and not findings:
        problems.append(("tool_error", f"zizmor exited {code} yet reported no finding"))
    missing = [p for p in expected if "tree/" + p not in completed]
    if missing:
        problems.append(("coverage_gap", f"zizmor did not audit {len(missing)} workflow(s): " + listed(missing)))
    if not canary and reported:
        problems.append(("canary_missed", (f"zizmor reported its {ZIZMOR_CANARY_RULE} canary at "
                                           f"{severity_of(reported[0])}, below min_severity {policy['min_severity']} "
                                           f"of lock.json, so the canary could not fail the gate")))
    elif not canary:
        problems.append(("canary_missed", f"zizmor did not report the {ZIZMOR_CANARY_RULE} canary of the gate"))
    return {"items": items, "below": below, "canary": canary, "removed": removed, "audited": len(completed & {
        "tree/" + p for p in expected}), "problems": problems}


def run_zizmor(s: Scan) -> dict:
    name = "zizmor"
    expected, problems = [], []
    for e in s.entries:
        if not _WORKFLOW_FILE.match(e.path):
            continue
        if e.kind != "blob" or e.mode not in FILE_MODES:
            problems.append(("coverage_gap", f"workflow {shown(e.path)} is a symlink or submodule and is not audited"))
        elif safe_join(Path("/"), e.path) is None:
            problems.append(("coverage_gap", f"workflow {shown(e.path)} has a control character and is not audited"))
        else:
            expected.append((e.path, e.oid))
    expected.sort()
    version, ready = prepare(s, name)
    if ready:
        return {"reasons": ready + problems}
    work = s.scratch / "zizmor"
    tree, canary_root = work / "tree", work / "canary"
    tree.mkdir(parents=True)
    write_new_file(canary_root / ".github" / "workflows" / "security-gate-canary.yml", ZIZMOR_CANARY_TEXT.encode())
    for path, oid in expected:
        write_new_file(safe_join(tree, path), s.git.blob_bytes(oid, MAX_SCANNED_FILE))

    def owned_at(commit: str) -> bytes | None:
        entry = s.git.entry_at(commit, WORKFLOW_PATH)
        if entry is None or entry[1] != "blob" or entry[0] not in FILE_MODES:
            return None
        return s.git.blob_bytes(entry[2], MAX_SCANNED_FILE)

    argv = ["--offline", "--no-config", "--no-ignores", "--collect", "all", "--strict-collection", "--no-progress",
            "--format", "json", "tree", "canary"]
    run = s.docker.run(s.ref(name), argv, timeout=s.spec(name)["timeout_s"], ok=tuple(ZIZMOR_FINDING_CODES),
                       mounts=((tree, "/sg/tree", True), (canary_root, "/sg/canary", True)))
    j = judge_zizmor(run.out, run.err, run.code, [p for p, _ in expected], owned_at(s.head), owned_at(s.base),
                     s.confirmed, s.spec(name)["policy"])
    problems = run_problem(name, run, tuple(ZIZMOR_FINDING_CODES)) + problems + j["problems"]
    receipt, reasons = tool_receipt(
        s, name, version, argv, run,
        scanned={"files": j["audited"], "commits": None, "packages": None, "paths": [".github/workflows"],
                 "paths_truncated": False, "lockfiles": [], "unreadable": None, **NOT_SEMGREP},
        canaries=[{"id": "zizmor-workflow", "expected_rule": ZIZMOR_CANARY_RULE, "found": j["canary"]}],
        markers=[], items=j["items"], below=j["below"], problems=problems, rules_loaded=None,
        rules_sha256=sha256_hex(canonical(argv)))
    return {"receipt": receipt, "reasons": reasons, "post_filters": j["removed"]}


# ---------------------------------------------------------------------------
# semgrep: the head tree, the gate's rules and the Registry rules
# ---------------------------------------------------------------------------

# Semgrep Registry rules may not be stored or redistributed (Semgrep Rules
# License v1.0). The gate downloads them on every run, in a container of its
# own with network and without pull request data, like the OSV databases, and
# counts them. The scan runs without network on those files and the gate's
# own rules (SEMGREP_RULES_PATH, MIT), read from the same commit as lock.json.
#
# semgrep runs twice on the same tree: with the gate's own rules alone, and
# with the downloaded rulesets alone. Of rules with one id in one call,
# semgrep 1.179.0 may drop all but the last on files without the text the
# last one looks for: a downloaded rule under the id of a gate's rule, given
# after the gate's rules, silenced that rule on the head and let its canary
# be found (ADR 0006). In a call of its own the Registry cannot touch the gate's
# rules. Each run has a receipt: "semgrep" (the gate's rules, which block by
# their severity) and "semgrep-registry" (the Registry's, which only signal
# under policy registry: signal, the template's, and block under
# registry: block). A finding belongs to the run that reported it, not to the
# look of its id: a Registry rule may be called sg-anything. A downloaded
# ruleset with an id of the gate's rules, or with one id twice, is not usable
# (offline_db), and a finding under an id that the run was not given is a
# tool error.
#
# Two rules of the Registry the gate pins, with a canary each, one for
# Python and one for JavaScript and TypeScript: if the Registry drops or
# renames one, its canary is missed and the run is inconclusive, not a quiet
# pass. Under registry: signal a canary of the Registry counts when semgrep
# reports it through the Registry rule at all, like the canary of the gate's
# warning rule; under block only as a finding that fails.
SEMGREP_REGISTRY_CANARY_RULE = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"
SEMGREP_REGISTRY_JS_CANARY_RULE = "javascript.lang.security.audit.spawn-shell-true.spawn-shell-true"
# p/default reports this rule on the owned workflow, which checks the pull
# request out under pull_request_target, as data only. Like zizmor's
# dangerous-triggers it is removed only there, only once, and only while the
# file equals the default branch's or a human confirmed it (ADR 0003, 3.5,
# item 5; ADR 0006).
SEMGREP_PRT_RULE = "yaml.github-actions.security.pull-request-target-code-checkout.pull-request-target-code-checkout"
_SEMGREP_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "ERROR": "high", "MEDIUM": "medium", "WARNING": "medium",
                     "LOW": "low", "INFO": "info"}
# semgrep lists every file it was given in paths.scanned (binary files too,
# with --no-exclude-binary-files). Partly parsed files are scanned as well,
# and listed once more as skipped with this reason.
_SEMGREP_PARTIAL = "analysis_failed_parser_or_internal_error"
_SEMGREP_PARSE_ERRORS = frozenset({"PartialParsing", "Syntax error", "Lexical error", "Other syntax error",
                                   "AST builder error"})
# Errors after which semgrep has no syntax tree of a file at all: only its
# regex rules read it. PartialParsing leaves a tree of the rest of the file.
_SEMGREP_UNPARSED = _SEMGREP_PARSE_ERRORS - {"PartialParsing"}
_SEMGREP_RULE_COUNT = re.compile(r"\bwith ([0-9][0-9,]*) Code rules?\b")
SEMGREP_IGNORE = ".semgrepignore"
SEMGREP_REGISTRY_TOOL = "semgrep-registry"   # the receipt id of the run with the Registry rules
MAX_RULESET_BYTES = 64 << 20
MAX_SEMGREP_FILE = MAX_SCANNED_FILE   # a larger head file is not given to semgrep: a coverage gap
# The time semgrep may spend on one rule in one file, and how many rules may
# run out of it before semgrep gives the file up. Its defaults (5 s and 3)
# time out on minified libraries and, under load, on ordinary large files:
# a timeout is a coverage gap, so the check would flap (ADR 0006).
SEMGREP_RULE_TIMEOUT_S = 30
SEMGREP_TIMEOUT_THRESHOLD = 3
# Code that semgrep 1.179.0 has no analyzer for, by the name of the file:
# only its regex rules read it. Components and pages that hold JavaScript
# (Vue, Svelte, Astro, HTML, EJS), the TypeScript of .mts and .cts, Python
# as .pyw and notebooks, code files whose extension is not in lower case
# (a.JS, a.PY) and scripts without an extension (#! on the first line).
_SEMGREP_NO_ANALYZER = frozenset({".vue", ".svelte", ".astro", ".html", ".htm", ".xhtml", ".ejs", ".mts", ".cts",
                                  ".pyw", ".ipynb"})
_SEMGREP_LOWER_ONLY = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".pyi"})
_BOM_CODECS = ((b"\x00\x00\xfe\xff", "utf-32-be"), (b"\xff\xfe\x00\x00", "utf-32-le"), (b"\xfe\xff", "utf-16-be"),
               (b"\xff\xfe", "utf-16-le"))
_WIDE_CODECS = {(2, 0): "utf-16-le", (2, 1): "utf-16-be", (4, 0): "utf-32-le", (4, 3): "utf-32-be"}
_PYTHON_SOURCE = (".py", ".pyw", ".pyi")
_NON_ASCII = re.compile(r"[^\x00-\x7f]")


def semgrep_text(data: bytes) -> bytes | None:
    """The UTF-8 copy semgrep is given of a head file it cannot read as it
    is, or None. semgrep 1.179.0 applies no regex rule at all to a file that
    is not valid UTF-8, one stray byte is enough, says nothing about it and
    lists the file as scanned (ADR 0006). Text in UTF-16 or UTF-32 (the
    files gitleaks cannot read) is decoded; in any other file every byte that
    is not part of valid UTF-8 becomes "?". Line numbers do not change."""
    for bom, codec in _BOM_CODECS:
        if data.startswith(bom):
            return data[len(bom):].decode(codec, "replace").encode("utf-8")
    head = data[:MAX_LINK_TARGET + 1]
    codec = _WIDE_CODECS.get(_wide_layout(head) or (0, 0)) if b"\0" in data else None
    if codec:
        return data.decode(codec, "replace").encode("utf-8")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", "surrogateescape").encode("utf-8", "replace")
    return None


def regex_only(path: str, head: bytes) -> bool:
    """Whether semgrep reads a head file with its regex rules only, by its
    name: code it has no analyzer for (_SEMGREP_NO_ANALYZER)."""
    stem, dot, ext = posixpath.basename(path).rpartition(".")
    if not dot or not stem:
        return head.startswith(b"#!")
    ext = "." + ext
    return ext.lower() in _SEMGREP_NO_ANALYZER or (ext.lower() in _SEMGREP_LOWER_ONLY and ext != ext.lower())


def python_encoding(path: str, data: bytes) -> str | None:
    """The source encoding a Python file declares (PEP 263), if Python reads
    other ASCII code from it than semgrep, which reads UTF-8: utf-7 turns
    "+AHM-" into "s", unicode_escape turns "\\x73" into "s". None if the two
    agree on every ASCII character, or if Python cannot run the file."""
    stem, dot, ext = posixpath.basename(path).rpartition(".")
    if dot and stem:
        if ("." + ext).lower() not in _PYTHON_SOURCE:
            return None
    elif not re.match(rb"#![^\n]*python", data):
        return None
    try:
        name, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        if name in ("utf-8", "utf-8-sig"):
            return None
        python = data.decode(name)
    except (SyntaxError, LookupError, UnicodeError, ValueError, TypeError):
        return None   # Python refuses to run the file
    semgrep = data.decode("utf-8", "surrogateescape")
    return None if _NON_ASCII.sub("", python) == _NON_ASCII.sub("", semgrep) else name


# The gate's own rules whose findings are about a variable: a finding of
# theirs below the threshold names it in the receipt and the job summary
# (findings.below_items). The name is the variable's only, read from the
# file semgrep was given at the start of the match, which is always the
# name in these rules: never a value.
SEMGREP_NAMED_RULES = frozenset({"sg-public-secret", "sg-public-key"})
MAX_NAME = 128
_SEMGREP_NAME = re.compile(rb"[A-Z][A-Za-z0-9_]*")
_WORD_BYTE = re.compile(rb"[A-Za-z0-9_]")
# The escapes of a line break or a tab written into a string (printf, echo
# -e, a template): the rules read a name right after them as a whole word.
_NAME_ESCAPES = (b"\\n", b"\\r", b"\\t")


def semgrep_name(data: bytes | None, start: object, end: object) -> str | None:
    """The variable name at the start of a match of semgrep (byte offsets
    start and end in the file it was given), or None: only a whole word of
    ASCII letters, digits and underscores that starts with a capital (the
    public prefix), at most MAX_NAME characters. A word right after the
    escape \\n, \\r or \\t counts as whole, as it does in the rules."""
    if data is None or not isinstance(start, int) or not isinstance(end, int) or isinstance(start, bool) \
            or isinstance(end, bool) or not 0 <= start < end <= len(data):
        return None
    m = _SEMGREP_NAME.match(data, start, min(end, start + MAX_NAME + 1))
    if not m or len(m.group()) > MAX_NAME:
        return None
    if _WORD_BYTE.match(data[start - 1:start] if start else b"") and data[max(start - 2, 0):start] not in _NAME_ESCAPES:
        return None
    if _WORD_BYTE.match(data[m.end():m.end() + 1]):
        return None
    return m.group().decode("ascii")


def semgrep_canaries() -> tuple[dict, ...]:
    """The files of canary/ and the rule each must trip, made at run time so
    that this file trips none of them. A canary counts only in the run of
    its source: the gate's in the run of the gate's rules, the Registry's in
    the run of the downloaded rulesets. A blocking canary counts only as a
    finding that fails under the policy; the canaries of the warning rules
    (sg-llm-no-output-limit, sg-public-key) count when they are reported at
    all, since those rules never block. Whether a canary of the Registry
    blocks is policy registry of lock.json. The sg-supabase-secret-key canary
    is a Vue component: it also shows that the regex rules read code semgrep
    has no analyzer for."""
    public, vite = "NEXT_" + "PUBLIC_", "VI" + "TE_"
    return (
        {"id": "semgrep-sg-public-secret", "expected_rule": "sg-public-secret", "blocking": True,
         "file": "web/public-secret.ts", "content": f"export const key = process.env.{public}SG_CANARY_SECRET_KEY;\n"},
        {"id": "semgrep-sg-service-role-client", "expected_rule": "sg-service-role-client", "blocking": True,
         "file": "web/client.tsx", "content": "'use client';\nexport const key = process.env.SUPABASE_" + "SERVICE_ROLE_KEY;\n"},
        {"id": "semgrep-sg-llm-no-output-limit", "expected_rule": "sg-llm-no-output-limit", "blocking": False,
         "file": "web/llm.ts",
         "content": "export const reply = (messages) => openai.chat.completions" + ".create({ model: \"m\", messages });\n"},
        {"id": "semgrep-sg-supabase-secret-key", "expected_rule": "sg-supabase-secret-key", "blocking": True,
         "file": "web/key.vue",
         "content": "<script setup>\nconst key = \"sb_" + "secret_security-gate-canary\";\n</script>\n"},
        {"id": "semgrep-sg-public-key", "expected_rule": "sg-public-key", "blocking": False,
         "file": "web/public-key.ts", "content": f"export const token = import.meta.env.{vite}SG_CANARY_TOKEN;\n"},
        {"id": "semgrep-registry", "expected_rule": SEMGREP_REGISTRY_CANARY_RULE, "blocking": None, "registry": True,
         "file": "registry.py", "content": "import subprocess\n\nsubprocess.call(command, " + "shell=True)\n"},
        {"id": "semgrep-registry-js", "expected_rule": SEMGREP_REGISTRY_JS_CANARY_RULE, "blocking": None,
         "registry": True, "file": "registry.js",
         "content": "const { spawn } = require(\"child_process\");\n\nspawn(command, [], { shell: " + "true });\n"},
    )


_RULE_ID = re.compile(r"[A-Za-z0-9._/-]+")
# A key of a block mapping written plainly (no quotes, tag, anchor, alias,
# merge key or flow style), and the value of an id: plain or in quotes of one
# kind, without escapes, with a comment after it at most.
_YAML_KEY = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*):(?:[ \t]+(.*))?")
_YAML_ID = re.compile(r"(['\"]?)([A-Za-z0-9._/-]+)\1(?:[ \t]+#.*)?")
# Line breaks of YAML other than \n and \r\n: a lone CR, NEL, LS and PS.
_YAML_BREAKS = re.compile("\r(?!\n)|[\x85\u2028\u2029]")


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("a key occurs twice")
    return dict(pairs)


# The Registry's own answer nests 19 levels deep (p/default, 15.10.2026). The
# limit is the gate's, not the json module's: how deep json.loads goes before a
# RecursionError differs between Python versions (3.14 parses what 3.11 refuses).
MAX_RULESET_JSON_DEPTH = 64


def _json_too_deep(text: str, limit: int) -> bool:
    """True when brackets outside strings nest deeper than `limit`."""
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def ruleset_rules(data: bytes) -> tuple[int, set[str]]:
    """(number of rules, rule ids) of a rules file: JSON {"rules": [...]} or
    block YAML, the items of the top-level sequence `rules:`. The Registry
    answers with either: the CDN in front of it keeps whichever format it
    cached first. The gate has no YAML parser, so it reads only the plain
    form in which both the Registry and the gate's rules file are written,
    and fails closed on anything else: 0 rules, which is inconclusive.

    Every rule must have exactly one id that the gate reads exactly as
    semgrep does: in JSON a string (no key twice in any object); in YAML a
    plain key `id` of the rule's mapping, at the indentation of its other
    keys, whose value is plain or quoted, without escapes, and may carry a
    comment. A rule whose keys are written in any other way (quoted, tagged,
    anchored, aliased, merged, in flow style, indented otherwise, a folded
    value), a second top-level key or document, or a line break YAML has and
    this reader does not make the file count 0 rules: semgrep would read an
    id this reader cannot see (ADR 0006)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return 0, set()
    if text.lstrip()[:1] == "{":
        if _json_too_deep(text, MAX_RULESET_JSON_DEPTH):
            return 0, set()
        try:
            doc = json.loads(text, object_pairs_hook=_unique_keys)
        except (ValueError, RecursionError):
            return 0, set()
        rules = doc.get("rules") if isinstance(doc, dict) else None
        ids = [r.get("id") if isinstance(r, dict) else None for r in rules] if isinstance(rules, list) else []
        if not ids or not all(isinstance(i, str) and _RULE_ID.fullmatch(i) for i in ids):
            return 0, set()
        return len(ids), set(ids)
    if _YAML_BREAKS.search(text):
        return 0, set()
    lines = [line.removesuffix("\r") for line in text.split("\n")]
    start = next((n for n, line in enumerate(lines) if line.lstrip(" ")[:1] not in ("", "#")), None)
    if start is None or lines[start].rstrip(" ") != "rules:":
        return 0, set()
    indent, rules = None, []    # rules: the ids of each rule
    for line in lines[start + 1:]:
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        lead = len(line) - len(stripped)
        if indent is None:
            indent = lead
        if lead == indent and stripped.startswith("- "):
            rules.append([])
            key = stripped[2:]
        elif lead == indent + 2 and rules and not (stripped == "-" or stripped.startswith("- ")):
            key = stripped
        elif lead > indent + 2 or (lead == indent + 2 and rules):
            continue    # a value: deeper, or an item of a sequence of the rule's key
        else:
            return 0, set()
        m = _YAML_KEY.fullmatch(key.rstrip(" \t"))
        if not m:
            return 0, set()
        if m.group(1) == "id":
            value = _YAML_ID.fullmatch(m.group(2) or "")
            if not value:
                return 0, set()
            rules[-1].append(value.group(2))
    if not rules or any(len(ids) != 1 for ids in rules):
        return 0, set()
    return len(rules), {ids[0] for ids in rules}


def semgrep_roots(paths: list[str]) -> list[list[str]]:
    """The head paths split into scanning roots so that no two paths of one
    root are the same file on a case- or normalization-insensitive file
    system (macOS): ".GitHub/x.yml" next to ".github/y.yml" goes into a
    second root. On Linux every path lands in the first root."""
    roots: list[tuple[dict[str, str], list[str]]] = []
    for path in paths:
        parts = path.split("/")
        prefixes = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
        keys = [unicodedata.normalize("NFC", prefix).casefold() for prefix in prefixes]
        root = next((r for r in roots if all(r[0].get(k, p) == p for k, p in zip(keys, prefixes, strict=True))), None)
        if root is None:
            root = ({}, [])
            roots.append(root)
        root[0].update(zip(keys, prefixes, strict=True))
        root[1].append(path)
    return [members for _, members in roots] or [[]]


def root_name(i: int) -> str:
    return "tree" if i == 0 else f"tree-{i}"


def semgrep_post_filter(findings: list[dict], owned: bytes | None, reference: bytes | None,
                        confirmed: bool) -> tuple[list, list]:
    """Remove exactly one semgrep finding ({rule, path, ...}, a head path):
    SEMGREP_PRT_RULE in the owned workflow, when that file equals the default
    branch's or its fingerprint was confirmed. Anything else is kept, as
    zizmor_post_filter does: two such findings, a renamed rule or a changed
    file stay red."""
    candidates = [i for i, f in enumerate(findings) if f["rule"] == SEMGREP_PRT_RULE and f["path"] == WORKFLOW_PATH]
    if len(candidates) != 1 or owned is None:
        return list(findings), []
    if reference is not None and owned == reference:
        basis = "same_as_default"
    elif confirmed:
        basis = "confirmed_fingerprint"
    else:
        return list(findings), []
    kept = [f for i, f in enumerate(findings) if i != candidates[0]]
    return kept, [{"tool": "semgrep", "rule": SEMGREP_PRT_RULE, "path": WORKFLOW_PATH, "basis": basis,
                   "file_sha256": sha256_hex(owned)}]


def judge_semgrep(report: bytes | None, stderr: str, code: int | None, given: list[list[str]], rules_given: int,
                  rule_ids: set[str], policy: dict, *, registry: bool, own_ids: frozenset[str] | set[str] = frozenset(),
                  owned: bytes | None = None, reference: bytes | None = None, confirmed: bool = False,
                  read: Callable[[str], bytes | None] | None = None) -> dict:
    """Pure: findings, canaries, coverage and the rule count from one
    semgrep run on the scanning roots tree/, tree-1/, ... (the head, see
    semgrep_roots) and canary/. The gate runs semgrep twice: with its own
    rules (registry False), whose findings block by their severity, and with
    the downloaded Registry rulesets (registry True), whose findings signal
    or block by policy registry. given: the head paths the gate wrote into
    each root; rules_given: how many rules it passed; rule_ids: the ids of
    those rules. A finding under another id is a tool error. own_ids, in the
    run of the Registry: the ids of the gate's rules, which a downloaded
    ruleset may not use. The post-filter (owned, reference, confirmed)
    applies to the run of the Registry, whose rule it removes. The findings
    of the gate's rules below the threshold are listed (below_items), with
    the variable name for SEMGREP_NAMED_RULES: read(path) gives the file
    semgrep was given under the path of its report, or None. Nothing else
    is read."""
    problems: list[tuple[str, str]] = []
    clash = set(own_ids) & rule_ids if registry else set()
    if clash:
        problems.append(("offline_db", (f"the downloaded Semgrep Registry rules have {len(clash)} rule id(s) of the "
                                        f"gate's own rules ({', '.join(shown(x) for x in sorted(clash)[:MAX_SHOWN])}): "
                                        f"those ids are the gate's, and a finding of the Registry under one would "
                                        f"read as the gate's in the receipt")))
    try:
        doc = json.loads((report or b"").decode("utf-8"))
        results, errors, paths = doc["results"], doc.get("errors") or [], doc.get("paths") or {}
        if not (isinstance(results, list) and isinstance(errors, list) and isinstance(paths, dict)):
            raise TypeError
    except (UnicodeDecodeError, ValueError, KeyError, TypeError):
        doc, results, errors, paths = None, [], [], {}
        problems.append(("tool_error", "semgrep wrote no readable JSON report"))
    counts = _SEMGREP_RULE_COUNT.findall(_ANSI.sub("", stderr))
    loaded = int(counts[-1].replace(",", "")) if counts else None
    if loaded is None:
        problems.append(("tool_error", "semgrep did not report how many rules it loaded"))
    elif loaded != rules_given:
        problems.append(("coverage_gap", f"semgrep loaded {loaded} rule(s), the gate gave it {rules_given}"))
    if doc is not None and doc.get("skipped_rules"):
        problems.append(("coverage_gap", f"semgrep skipped {len(doc['skipped_rules'])} rule(s) it was given"))
    roots = [root_name(i) + "/" for i in range(len(given))]

    def head_path(path: str) -> str | None:
        root = next((r for r in roots if path.startswith(r)), None)
        return path[len(root):] if root else None

    def severity_of(r: dict) -> str:
        return _SEMGREP_SEVERITY.get(str((r.get("extra") or {}).get("severity", "")).upper(), policy["unknown_severity"])

    # The canaries of this run: the gate's in the run of its rules, the
    # Registry's in the run of the Registry.
    canaries = [c for c in semgrep_canaries() if bool(c.get("registry")) == registry]
    hits: dict[str, list[str]] = {c["id"]: [] for c in canaries}
    raw, unknown, spans = [], set(), {}
    for r in results:
        try:
            rule, path, line = r["check_id"], r["path"], r["start"]["line"]
            if not (isinstance(rule, str) and isinstance(path, str) and isinstance(line, int)
                    and not isinstance(line, bool)):
                raise TypeError
        except (KeyError, TypeError):
            problems.append(("tool_error", "semgrep reported a finding without rule, path or line"))
            continue
        rel = head_path(path)
        if rule not in rule_ids:
            unknown.add(rule)
        elif path.startswith("canary/"):
            for c in canaries:
                if path == "canary/" + c["file"] and rule == c["expected_rule"]:
                    hits[c["id"]].append(severity_of(r))
        elif rel is not None:
            raw.append({"rule": rule, "path": rel, "line": line if line > 0 else None, "severity": severity_of(r)})
            start, end = r.get("start") or {}, r.get("end") or {}
            if not registry and rule in SEMGREP_NAMED_RULES and isinstance(end, dict):
                spans.setdefault((rule, rel, raw[-1]["line"]), (path, start.get("offset"), end.get("offset")))
        else:
            problems.append(("tool_error", "semgrep reported a file outside the scanned directories"))
    if unknown:
        problems.append(("tool_error", (f"semgrep reported {len(unknown)} rule id(s) that "
                                        + ("the downloaded rulesets do not have: " if registry
                                           else "the gate's rules do not have: ")
                                        + ", ".join(shown(x) for x in sorted(unknown)[:MAX_SHOWN])
                                        + (" ..." if len(unknown) > MAX_SHOWN else ""))))
    kept, removed = semgrep_post_filter(raw, owned, reference, confirmed) if registry else (raw, [])
    # At or above the threshold, a finding of the gate's rules fails; one of
    # the Registry's fails only under registry: block, else it is a signal.
    blocks = not registry or policy["registry"] == "block"
    items, signal, below_items, seen, below = [], [], [], set(), 0
    text: tuple[str, bytes | None] = ("", None)   # the last file read: one at a time, files are large
    for f in kept:
        item = dict(f, fingerprint=sha256_hex(canonical(["semgrep", f["rule"], f["path"], f["line"]])))
        if item["fingerprint"] in seen:
            continue
        seen.add(item["fingerprint"])
        if RANK[item["severity"]] < RANK[policy["min_severity"]]:
            below += 1
            if not registry and len(below_items) < MAX_ITEMS:
                name, span = None, spans.get((f["rule"], f["path"], f["line"]))
                if span and read is not None:
                    if text[0] != span[0]:
                        text = (span[0], read(span[0]))
                    name = semgrep_name(text[1], span[1], span[2])
                below_items.append(dict(item, name=name))
        elif blocks:
            items.append(item)
        else:
            signal.append(item)
    if doc is not None and code == 0 and results:
        problems.append(("tool_error", "semgrep exited 0 yet reported findings"))
    if doc is not None and code == 1 and not results:
        problems.append(("tool_error", "semgrep exited 1 yet reported no finding"))

    found = []
    for c in canaries:
        reported = hits[c["id"]]
        ok = any(RANK[sev] >= RANK[policy["min_severity"]] for sev in reported) if (
            blocks if registry else c["blocking"]) else bool(reported)
        found.append({"id": c["id"], "expected_rule": c["expected_rule"], "found": ok})
        if ok:
            continue
        if reported:
            problems.append(("canary_missed", (f"semgrep reported its {c['expected_rule']} canary at {reported[0]}, "
                                               f"below min_severity {policy['min_severity']} of lock.json, so the "
                                               f"canary could not fail the gate")))
        elif registry and rule_ids and c["expected_rule"] not in rule_ids:
            problems.append(("canary_missed", (f"the downloaded Semgrep Registry rules have no rule "
                                               f"{c['expected_rule']}, whose canary the gate checks: the Registry "
                                               f"changed under the gate")))
        else:
            problems.append(("canary_missed", f"semgrep did not report the {c['expected_rule']} canary of the gate"))

    # Coverage: semgrep lists every file it read in paths.scanned. A file the
    # gate gave it and it did not list, skipped for any reason but a partial
    # parse, or a per-file error such as a timeout is a gap. A file it could
    # not parse at all is scanned by its regex rules only: unparsed.
    scanned_raw = {p for p in paths.get("scanned") or [] if isinstance(p, str)}
    skipped = {}
    for sk in paths.get("skipped") or []:
        if isinstance(sk, dict) and isinstance(sk.get("path"), str):
            skipped.setdefault(sk["path"], str(sk.get("reason")))
    gaps: dict[str, str] = {}
    for root, members in zip(roots, given, strict=True):
        for path in members:
            if root + path not in scanned_raw:
                gaps[path] = skipped.get(root + path, "not scanned")
    for path, reason in skipped.items():
        if head_path(path) is not None and reason != _SEMGREP_PARTIAL:
            gaps.setdefault(head_path(path), reason)
    fatal, unparsed = set(), set()
    for e in errors:
        if not isinstance(e, dict):
            continue
        etype = e.get("type")
        etype = str(etype[0] if isinstance(etype, list) and etype else etype)
        path = e.get("path")
        if e.get("level") == "error":
            fatal.add(etype)
        elif etype in _SEMGREP_PARSE_ERRORS:
            if etype in _SEMGREP_UNPARSED and isinstance(path, str) and head_path(path) is not None:
                unparsed.add(head_path(path))
        elif isinstance(path, str) and head_path(path) is not None:
            gaps.setdefault(head_path(path), etype)
        else:
            fatal.add(etype)
    if fatal:
        problems.append(("tool_error", "semgrep reported errors: " + ", ".join(shown(x) for x in sorted(fatal))))
    if gaps:
        problems.append(("coverage_gap", f"semgrep did not fully scan {len(gaps)} file(s): "
                                         + "; ".join(f"{shown(p)} ({gaps[p]})" for p in sorted(gaps)[:MAX_SHOWN])
                                         + (" ..." if len(gaps) > MAX_SHOWN else "")))
    total = sum(len(members) for members in given)
    scanned = sum(1 for root, members in zip(roots, given, strict=True) for path in members
                  if root + path in scanned_raw)
    if total and not scanned:
        problems.append(("zero_scanned", f"semgrep scanned 0 of the {total} file(s) it was given"))
    return {"items": items, "signal": signal, "below": below, "below_items": below_items, "canaries": found,
            "removed": removed, "loaded": loaded, "scanned": scanned, "unparsed": sorted(unparsed - set(gaps)),
            "problems": problems}


def load_semgrep_rules(s: Scan) -> tuple[bytes | None, tuple[str, str] | None]:
    """The gate's rules, from the commit lock.json is read from."""
    entry = s.git.entry_at(s.config, SEMGREP_RULES_PATH)
    if entry is None:
        return None, ("invalid_document", f"{SEMGREP_RULES_PATH} is missing, so semgrep cannot run")
    mode, kind, oid = entry
    if kind != "blob" or mode not in FILE_MODES:
        return None, ("invalid_document", f"{SEMGREP_RULES_PATH} is not a regular file")
    try:
        data = s.git.blob_bytes(oid, MAX_LOCK_BYTES)
    except GitError as exc:
        return None, ("invalid_document", f"{SEMGREP_RULES_PATH}: {exc}")
    if not ruleset_rules(data)[0]:
        return None, ("invalid_document", f"{SEMGREP_RULES_PATH} has no rules list")
    return data, None


def run_semgrep(s: Scan) -> dict:
    name = "semgrep"
    if s.lock is not None and name not in s.lock["tools"]:
        return {"reasons": [("tool_missing", (f"semgrep did not run: {LOCK_PATH} has schema_version "
                                              f"{s.lock['schema_version']}, which pins no semgrep; update it to "
                                              f"schema_version {LOCK_SCHEMA_VERSION}"))]}
    own = None
    if s.lock is not None:
        own, problem = load_semgrep_rules(s)
        if problem:
            return {"reasons": [problem, ("tool_missing", f"semgrep did not run: {problem[1]}")]}
    version, ready = prepare(s, name)
    if ready:
        return {"reasons": ready}
    spec = s.spec(name)
    timeout = spec["timeout_s"]
    work = s.scratch / "semgrep"
    tree, canary_root, rules_dir, registry = (work / d for d in ("tree", "canary", "rules", "registry"))
    for d in (tree, canary_root, rules_dir, registry):
        d.mkdir(parents=True)
    # The head tree, every regular file but .semgrepignore files (reported by
    # gate-integrity), written from git objects. An empty .semgrepignore of
    # the gate's at each scanning root: without one semgrep skips tests/,
    # build/, dist/, vendor/, node_modules/ and more without a word.
    problems, files = [], {}
    for e in sorted(s.regular_files(), key=lambda e: e.path):
        if posixpath.basename(e.path).lower() == SEMGREP_IGNORE:
            continue
        if safe_join(tree, e.path) is None:
            problems.append(("coverage_gap", (f"{shown(e.path)} has a control character in its path and is not "
                                              f"scanned by semgrep")))
        elif s.blobs[e.oid].size > MAX_SEMGREP_FILE:
            problems.append(("coverage_gap", (f"{shown(e.path)} is larger than {MAX_SEMGREP_FILE} bytes and is not "
                                              f"scanned by semgrep")))
        else:
            files[e.path] = e.oid
    given = semgrep_roots(sorted(files))
    pairs, heads, root_dirs = [], [], []
    for i, members in enumerate(given):
        root = tree if i == 0 else work / root_name(i)
        root.mkdir(exist_ok=True)
        root_dirs.append(root)
        write_new_file(root / SEMGREP_IGNORE, b"")
        pairs += [(files[path], safe_join(root, path)) for path in members]
        heads += members
    clashed = set(s.git.write_blobs(pairs))
    for target in clashed:
        root = next(r for r in root_dirs if target.is_relative_to(r))
        path = target.relative_to(root).as_posix()
        given[root_dirs.index(root)].remove(path)
        problems.append(("coverage_gap", (f"{shown(path)} clashes with another path on this file system and is not "
                                          f"scanned by semgrep")))
    # What semgrep cannot read as it is: a UTF-8 copy in place of the file
    # (semgrep_text), and Python whose declared encoding semgrep does not
    # read (a gap). Code it has no analyzer for is listed in the receipt.
    transcoded, by_name, encodings = 0, set(), {}
    for (oid, target), path in zip(pairs, heads, strict=True):
        if target in clashed:
            continue
        if regex_only(path, s.blobs[oid].head):
            by_name.add(path)
        data = target.read_bytes()
        encoding = python_encoding(path, data)
        if encoding:
            encodings[path] = encoding
        text = semgrep_text(data)
        if text is not None:
            target.write_bytes(text)
            transcoded += 1
    if encodings:
        problems.append(("coverage_gap", (f"{len(encodings)} Python file(s) declare a source encoding in which "
                                          f"Python reads other code than semgrep checks: "
                                          + "; ".join(f"{shown(p)} ({encodings[p]})"
                                                      for p in sorted(encodings)[:MAX_SHOWN])
                                          + (" ..." if len(encodings) > MAX_SHOWN else "")
                                          + ". Save them as UTF-8")))
    write_new_file(canary_root / SEMGREP_IGNORE, b"")
    for c in semgrep_canaries():
        write_new_file(canary_root / c["file"], c["content"].encode())
    (rules_dir / "security-gate.yml").write_bytes(own)
    # 1. Download: network, and nothing but the output directory mounted.
    fetch_argv = ["curl", "-q", "--fail", "--silent", "--show-error", "--proto", "=https", "--max-time",
                  str(min(timeout, 600)), "--max-filesize", str(MAX_RULESET_BYTES)]
    for rs in spec["rulesets"]:
        fetch_argv += ["--output", f"out/{rs['name']}.yml", rs["source"]]
    fetch = s.docker.run(s.ref(name), fetch_argv, network=True, timeout=timeout, ok=(0,),
                         mounts=((registry, "/sg/out", False),))
    fetch_record = {"argv": fetch_argv, "network": "default", "exit_code": fetch.code if fetch.code is not None else -1,
                    "retried": fetch.retried, "duration_s": fetch.duration}
    fetched = [] if fetch.code == 0 else [
        ("offline_db", f"the Semgrep Registry download {fetch.detail or f'exited {fetch.code}'}")]
    rulesets, configs, registry_given, registry_ids = [], [], 0, set()
    for rs in spec["rulesets"]:
        entry = {"name": rs["name"], "source": rs["source"], "sha256": None, "rules": None, "min_rules": rs["min_rules"]}
        rulesets.append(entry)
        path = registry / f"{rs['name']}.yml"
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RULESET_BYTES:
                raise OSError("missing")
            data = path.read_bytes()
        except OSError:
            fetched.append(("offline_db", f"the {rs['name']} ruleset was not downloaded or cannot be read"))
            continue
        count, ids = ruleset_rules(data)
        entry.update(sha256=sha256_hex(data), rules=count)
        if count < rs["min_rules"]:
            fetched.append(("offline_db", (f"the {rs['name']} ruleset has {count} rule(s), fewer than min_rules "
                                           f"{rs['min_rules']} of lock.json")))
        # Of rules with one id in one call, semgrep 1.179.0 may drop all but
        # the last on files without the text the last one looks for: a rule
        # under the id of a pinned rule could silence it on the head and
        # still trip its canary. Ids are unique in the call of the Registry.
        if len(ids) != count:
            fetched.append(("offline_db", (f"the {rs['name']} ruleset has {count - len(ids)} rule(s) under an id "
                                           f"that another of its rules has: semgrep would drop such a rule on "
                                           f"some files without a word")))
        if ids & registry_ids:
            fetched.append(("offline_db", (f"the {rs['name']} ruleset has {len(ids & registry_ids)} rule id(s) of "
                                           f"another downloaded ruleset: semgrep would drop such a rule on some "
                                           f"files without a word")))
        if count:
            configs += ["--config", f"registry/{rs['name']}.yml"]
            registry_given += count
            registry_ids |= ids
    # 2. Two scans, no network, everything read-only but the report
    # directory: the gate's own rules alone, then the downloaded rulesets
    # alone. In one call, semgrep 1.179.0 lets a rule of a later --config
    # with the id of a gate's rule silence that rule on files without its
    # pattern (ADR 0006): a downloaded ruleset never shares a call with the
    # gate's rules.
    roots = [root_name(i) for i in range(len(given))]
    inputs = tuple((root, "/sg/" + roots[i], True) for i, root in enumerate(root_dirs)) + (
        (canary_root, "/sg/canary", True),)

    def scan(config: list[str], mount: tuple, report_dir: Path) -> tuple[list[str], Run, bytes | None]:
        report_dir.mkdir()
        argv = ["semgrep", "scan", *config, "--metrics=off", "--disable-version-check", "--oss-only",
                "--no-rewrite-rule-ids", "--disable-nosem", "--no-git-ignore", "--max-target-bytes", "0",
                "--no-exclude-binary-files", "--timeout", str(SEMGREP_RULE_TIMEOUT_S), "--timeout-threshold",
                str(SEMGREP_TIMEOUT_THRESHOLD), "--error", "--verbose", "--json", "--output", "out/semgrep.json",
                *roots, "canary"]
        run = s.docker.run(s.ref(name), argv, timeout=timeout, ok=(0, 1),
                           mounts=inputs + (mount, (report_dir, "/sg/out", False)))
        report_file = report_dir / "semgrep.json"
        return argv, run, report_file.read_bytes() if run.code is not None and report_file.is_file() else None

    def owned_at(commit: str) -> bytes | None:
        entry = s.git.entry_at(commit, WORKFLOW_PATH)
        if entry is None or entry[1] != "blob" or entry[0] not in FILE_MODES:
            return None
        return s.git.blob_bytes(entry[2], MAX_SCANNED_FILE)

    def receipt_of(tool_id: str, argv: list[str], run: Run, j: dict, extra: list, rules_sha256: str,
                   **more) -> tuple[dict, list[tuple[str, str, str]]]:
        limited = sorted(by_name | set(j["unparsed"]))
        receipt, reasons = tool_receipt(
            s, name, version, argv, run, tool_id=tool_id,
            scanned={"files": j["scanned"], "commits": None, "packages": None, "paths": [""],
                     "paths_truncated": False, "lockfiles": [], "unreadable": None, "transcoded": transcoded,
                     "regex_only": len(limited), "regex_only_paths": limited[:MAX_PATHS]},
            canaries=j["canaries"], markers=[], items=j["items"], below=j["below"], problems=extra + j["problems"],
            rules_loaded=j["loaded"], rules_sha256=rules_sha256, signal=j["signal"], below_items=j["below_items"],
            **more)
        return receipt, [(code, detail, tool_id) for code, detail in reasons]

    def given_file(path: str) -> bytes | None:
        """The file semgrep was given under the path of its report."""
        root, _, rel = path.partition("/")
        target = safe_join(root_dirs[roots.index(root)], rel) if root in roots else None
        try:
            if target is None or target.is_symlink() or not target.is_file() or target.stat().st_size > MAX_SEMGREP_FILE:
                return None
            return target.read_bytes()
        except OSError:
            return None

    own_given, own_ids = ruleset_rules(own)
    argv, run, report = scan(["--config", "rules/security-gate.yml"], (rules_dir, "/sg/rules", True), work / "out")
    j = judge_semgrep(report, run.err, run.code, given, own_given, own_ids, spec["policy"], registry=False,
                      read=given_file)
    own_receipt, reasons = receipt_of(name, argv, run, j, run_problem(name, run, (0, 1)) + problems,
                                      sha256_hex(canonical([["security-gate", sha256_hex(own)]])))
    if configs:
        argv, run, report = scan(configs, (registry, "/sg/registry", True), work / "out-registry")
        j = judge_semgrep(report, run.err, run.code, given, registry_given, registry_ids, spec["policy"],
                          registry=True, own_ids=own_ids, owned=owned_at(s.head), reference=owned_at(s.base),
                          confirmed=s.confirmed)
        extra = run_problem(name, run, (0, 1)) + problems + fetched
    else:   # nothing usable was downloaded: the reasons are in fetched
        argv, run = [], Run(code=None, detail="not run: no usable ruleset")
        j = {"items": [], "signal": [], "below": 0, "below_items": [], "removed": [], "loaded": None, "scanned": 0,
             "unparsed": [],
             "problems": [], "canaries": [{"id": c["id"], "expected_rule": c["expected_rule"], "found": False}
                                          for c in semgrep_canaries() if c.get("registry")]}
        extra = problems + fetched
    registry_receipt, more = receipt_of(SEMGREP_REGISTRY_TOOL, argv, run, j, extra, sha256_hex(canonical(
        [[rs["name"], rs["sha256"]] for rs in rulesets])), fetch=fetch_record, rulesets=rulesets)
    return {"receipts": [own_receipt, registry_receipt], "reasons": reasons + more, "post_filters": j["removed"]}


# Every tool the gate runs, in order.
TOOLS = (("gate-integrity", gate_integrity), ("gitleaks", run_gitleaks), ("osv-scanner", run_osv),
         ("zizmor", run_zizmor), ("semgrep", run_semgrep))


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
        "trusted": {"gate_sha": None, "skill_version": GATE_VERSION, "lock_sha256": None, "config_source": "default",
                    "head_lock_schema_version": None, "head_config_fingerprint": None, "confirmed": False},
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

    # The scanners' configuration: lock.json of the head once SG-TRUST-001
    # passed (then it equals the default branch's or a human confirmed it),
    # else the default branch's.
    config = head if sg001 == PASS else gate_sha
    lock, lock_bytes, problem = load_lock(git, config)
    # A confirmed new gate.py may bring a lock.json of a schema this gate does
    # not read. Then the scanners of the default branch judge the pull
    # request, lock.json and semgrep-rules.yml together, as if it left them
    # alone: the new ones take effect with the new gate, after the merge
    # (ADR 0003, 12). Only if that gate.py declares the schema: its one line
    # LOCK_SCHEMA_VERSIONS = (...) is read as data, never run, and can only
    # refuse the fallback, never choose a configuration. A gate.py that does
    # not declare it (unchanged, a comment or a mode changed, another tuple,
    # another line) would not read that lock.json after the merge, and it
    # stays inconclusive; so does any other problem.
    ahead = lock_schema_ahead(lock_bytes) if problem and config == head and LOCK_PATH in changed_paths else None
    if ahead is not None and ahead not in head_lock_schemas(git, entries, changed):
        problem = (problem[0], (f"{problem[1]}; {GATE_PATH} of the head does not declare schema_version {ahead} "
                                f"(exactly one line LOCK_SCHEMA_VERSIONS = (...) that lists it), so no gate would "
                                f"read it after the merge"))
    elif ahead is not None:
        default_lock = load_lock(git, gate_sha)
        if default_lock[2] is None:
            config = gate_sha
            lock, lock_bytes, problem = default_lock
            tr["config_source"] = "default_newer_schema"
            tr["head_lock_schema_version"] = ahead
        else:
            problem = (problem[0], (f"{problem[1]}; {LOCK_PATH} of the default branch cannot judge the pull "
                                    f"request instead: {default_lock[2][1]}"))
    tr["lock_sha256"] = sha256_hex(lock_bytes) if lock_bytes is not None else None
    if problem:
        add_reason(receipt, problem[0], problem[1])

    scan = Scan(git=git, entries=entries, blobs=blobs, head=head, base=gate_sha, scratch=scratch / "scan",
                lock=lock, docker=Docker(scratch / "docker"), confirmed=confirmed,
                self_file=Path(__file__).read_bytes(), config=config)
    for name, tool in TOOLS:
        try:
            result = tool(scan)
        except (GitError, OSError) as exc:
            add_reason(receipt, "tool_error", f"{type(exc).__name__}: {exc}" if isinstance(exc, GitError)
                       else f"{type(exc).__name__} while preparing the scan", name)
            continue
        receipt["tools"] += result.get("receipts") or ([result["receipt"]] if "receipt" in result else [])
        for code, detail, *tool_id in result["reasons"]:
            add_reason(receipt, code, detail, tool_id[0] if tool_id else name)
        receipt["post_filters"] += result.get("post_filters", [])
        if "coverage" in result:
            receipt["coverage"] = result["coverage"]
    sub["canary_commit"] = scan.canary_commit


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


# Text of the pull request (paths, rule ids) in the job summary is plain
# text: no link, image, autolink, HTML, emphasis or table cell of its own.
_MD_ESCAPE = re.compile(r"([\\\[\]()*_~|])")


def md(text: str) -> str:
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")
    return _MD_ESCAPE.sub(r"\\\1", text)


# What this version of the gate does not check, said in every summary.
NOT_CHECKED = ("composite actions, dependabot.yml and anything else outside .github/workflows/ (zizmor audits "
               "workflows only); secrets that no built-in rule of gitleaks knows; code only through the gate's own "
               "Semgrep rules and the Semgrep Registry rules of lock.json, whose findings only signal and never fail "
               "the gate unless lock.json sets them to block, and only through their regex rules where semgrep has "
               "no analyzer for the code (Vue, Svelte, Astro and HTML components, .mts, .cts, scripts without an "
               "extension, notebooks) or cannot parse it; values that reach the browser or app bundle without a "
               "documented public prefix (a custom envPrefix or publicPrefix, next.config env, Nuxt "
               "runtimeConfig.public, Astro envField, SvelteKit public: true, Angular environments, DefinePlugin "
               "and EnvironmentPlugin, Expo extra) or with the bare PUBLIC_ prefix elsewhere than after env., right "
               "before = in an environment file, in an import from $env/static/public or $env/dynamic/public and "
               "in a workflow; the variable a public one is fed from, but for $X and ${X} as the whole value, "
               "process.env.X and a secret, variable or env of a workflow, whose names are read; whether a public "
               "key the gate does not know as publishable is a secret (sg-public-key only warns); row level "
               "security of Supabase migrations and Firebase rules; new packages (whether they exist and how old "
               "they are)")


def config_notice(receipt: dict) -> str | None:
    """What a reviewer must know when the default branch's scanners judged a
    confirmed lock.json of a newer schema, or None."""
    tr = receipt["trusted"]
    if tr["config_source"] != "default_newer_schema":
        return None
    return (f"this gate (v{tr['skill_version']}) cannot read lock.json schema_version {tr['head_lock_schema_version']} "
            f"of the head, so the pull request was judged by the scanners of the default branch (its {LOCK_PATH} "
            f"and {SEMGREP_RULES_PATH}). The new scanners take effect after the merge; the first pull request after "
            f"it shows whether they find their canaries")


def report(receipt: dict) -> None:
    outcome = receipt["outcome"]
    print(f"security-gate: {outcome.upper()} (exit {receipt['exit_code']})")
    print(f"security-gate: not checked by this version: {NOT_CHECKED}")
    notice = config_notice(receipt)
    if notice:
        print("::warning title=security-gate configuration::" + annotate(notice))
    for r in receipt["reasons"]:
        level = "error" if outcome != PASS else "notice"
        print(f"::{level} title=security-gate {r['code']}::" + annotate(r["detail"]))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary:
        return
    lines = [f"## security-gate: {outcome}", ""]
    lines += [f"- self-check: {receipt['self_check']['outcome']}",
              f"- SG-TRUST-001: {receipt['trust_checks'][0]['outcome']}"]
    if notice:
        lines.append(f"- scanner configuration: {notice}")
    for t in receipt["tools"]:
        scanned = t["scanned"]
        counts = ", ".join(f"{scanned[k]} {k}" for k in ("files", "commits", "packages") if scanned[k] is not None)
        if scanned.get("unreadable"):
            counts += f" ({scanned['unreadable']} more file(s) it cannot read)"
        notes = []
        if scanned.get("transcoded"):
            notes.append(f"{scanned['transcoded']} of the files as a UTF-8 copy")
        if scanned.get("regex_only"):
            more = scanned["regex_only"] - min(5, len(scanned["regex_only_paths"]))
            notes.append(f"{scanned['regex_only']} only with regex rules: "
                         + ", ".join(md(shown(p)) for p in scanned["regex_only_paths"][:5])
                         + (f" and {more} more" if more else ""))
        canaries = sum(1 for c in t["canaries"] if c["found"])
        below = t["findings"]["below_threshold"]
        lines.append(f"- {t['id']} {t['version']}: {t['outcome']}, {t['findings']['total']} finding(s)"
                     + (f" and {below} below the threshold (not blocking)" if below else "")
                     + f", {counts or 'nothing'} scanned" + (f" ({'; '.join(notes)})" if notes else "")
                     + f", canaries {canaries}/{len(t['canaries'])}")
        listed = t["findings"].get("below_items") or []
        if listed:
            more = below - min(5, len(listed))
            lines.append(f"  - {below} below the threshold, not blocking: "
                         + "; ".join(md(f"{shown(i['rule'])} {shown(i['path'])}" + (f":{i['line']}" if i["line"] else "")
                                        + (f" {i['name']}" if i.get("name") else "")) for i in listed[:5])
                         + (f" and {more} more (receipt)" if more else ""))
        signal = t["findings"]["signal_items"]
        if t["findings"]["signal"]:
            more = t["findings"]["signal"] - min(5, len(signal))
            lines.append(f"  - {t['findings']['signal']} registry finding(s), signal only: "
                         + "; ".join(md(f"{shown(i['rule'])} {shown(i['path'])}" + (f":{i['line']}" if i["line"] else ""))
                                     for i in signal[:5])
                         + (f" and {more} more (receipt)" if more else ""))
    if receipt["reasons"]:
        lines += ["", "| reason | tool | detail |", "|---|---|---|"]
        lines += [f"| {r['code']} | {r['tool'] or ''} | {md(r['detail'])} |" for r in receipt["reasons"]]
    lines += ["", f"Not checked by this version: {NOT_CHECKED}.", "", f"Receipt: artifact `{RECEIPT_ARTIFACT}`.", ""]
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
