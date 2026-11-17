"""Database dumps committed to the repository (#3548, epic #3546).

docs/FEATURE_PLAN_SECRETS_AND_DUMPS.md, section 5. The check reads the
checked-out tree and the files added or changed in the commits the secrets
layer reads, finds database dumps by name and by content, and tells test
data (Drupal ships test dumps) from real data.

Only counts leave this module: how many email addresses and password hashes
a file holds, its size and format, and which rule decided. Never an
address, a hash or a line of the file.

The check runs in a child process with a time limit (``run_isolated``), like
the setup files check: a large or odd file never holds up the scan.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import lzma
import multiprocessing
import os
import re
import subprocess
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO, Any, Iterator, Optional

# Stored size above which a dump counts as real data (plan 5.3).
TEST_MAX_BYTES = 1_000_000
# Decompressed bytes read from each candidate for the real data signs.
READ_BYTES = 8 * 1024 * 1024
# Bytes read from a file that does not have a dump's name.
SNIFF_BYTES = 64 * 1024
# The most files without a dump's name read for content, tree and history
# together. Past it the check is incomplete: the agent passes do not run and
# nothing is closed.
MAX_SNIFFED = 200_000
# The most entries of one zip file read; past it the file is read in part.
MAX_ZIP_ENTRIES = 100
# A zip file is read whole to reach its directory; one from history larger
# than this is reported unread.
SEEKABLE_MAX = 64 * 1024 * 1024
# The most dumps reported; the check is cut short past it.
MAX_DUMPS = 200
# The longest the check may run.
SECONDS_MAX = 300.0
CHUNK = 1024 * 1024

CLASS_REAL = "real"
CLASS_TEST = "test"
# Which rule decided the class (plan 5.3).
DECIDED_REAL_DATA = "real_data"
DECIDED_COMPOSER = "composer"
DECIDED_TEST_FOLDER = "test_folder"
DECIDED_DEFAULT = "default"
DECIDED_UNREAD = "unread"

FORMAT_MYSQL = "mysql"
FORMAT_POSTGRESQL = "postgresql"
FORMAT_POSTGRESQL_CUSTOM = "postgresql_custom"
FORMAT_SQLITE = "sqlite"
FORMAT_DRUPAL_PHP = "drupal_php"
FORMAT_SQL = "sql"
FORMATS = (
    FORMAT_MYSQL,
    FORMAT_POSTGRESQL,
    FORMAT_POSTGRESQL_CUSTOM,
    FORMAT_SQLITE,
    FORMAT_DRUPAL_PHP,
    FORMAT_SQL,
)
COMPRESSIONS = ("gzip", "bzip2", "xz", "zstd", "zip")

# Names that make a file a candidate whatever it holds. ``.db`` counts only
# with the SQLite header.
_SQL_NAMES = (".sql", ".mysql", ".pgsql", ".psql")
_PLAIN_NAMES = _SQL_NAMES + (".dump", ".pgdump", ".sqlite", ".sqlite3")
_COMPRESSED = {
    ".gz": "gzip",
    ".bz2": "bzip2",
    ".xz": "xz",
    ".zst": "zstd",
    ".zip": "zip",
}

_MAGIC_SQLITE = b"SQLite format 3\x00"
_MAGIC_PGDMP = b"PGDMP"
_MAGIC_GZIP = b"\x1f\x8b"
_MAGIC_BZIP2 = b"BZh"
_MAGIC_XZ = b"\xfd7zXZ\x00"
_MAGIC_ZSTD = b"\x28\xb5\x2f\xfd"
_MAGIC_ZIP = b"PK\x03\x04"

_HEADERS = (
    (b"-- MySQL dump", FORMAT_MYSQL),
    (b"-- MariaDB dump", FORMAT_MYSQL),
    (b"-- PostgreSQL database dump", FORMAT_POSTGRESQL),
)
# Data rows: a schema file with none of these is not a dump of any data.
_ROWS = re.compile(
    rb"(?i)\b(?:INSERT(?:\s+(?:IGNORE|LOW_PRIORITY|DELAYED|HIGH_PRIORITY))*"
    rb"|REPLACE(?:\s+(?:LOW_PRIORITY|DELAYED))*)\s+INTO\b"
    rb"|\bCOPY\s+[^;\n]{1,512}\bFROM\s+stdin\b"
)
_PHP_ROWS = b"->insert("
_PHP_SCHEMA = b"->schema()->createTable("

# Real data signs (plan 5.3). Counted, never kept.
_EMAIL = re.compile(
    rb"[A-Za-z0-9._%+-]{1,64}@((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    rb"[A-Za-z]{2,24})\b"
)
_RESERVED_DOMAINS = (b"example.com", b"example.org", b"example.net", b"localhost")
_RESERVED_SUFFIXES = (b".example", b".test", b".invalid", b".localhost")
_HASH = re.compile(
    rb"\$S\$[./0-9A-Za-z]{52}"
    rb"|\$[PH]\$[./0-9A-Za-z]{31}"
    rb"|\$2[by]\$\d\d\$[./0-9A-Za-z]{53}"
    rb"|\$argon2id?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{8,}\$[A-Za-z0-9+/]{16,}"
)
# The longest match either pattern can make: kept between chunks so a match
# across a chunk boundary is counted once.
_OVERLAP = 512

# The site's own test folders (plan 5.3, rule 3).
TEST_SEGMENTS = frozenset({"tests", "test", "fixtures", "__fixtures__", "testdata"})
# Composer-installed code when composer.json says nothing else (rule 2).
_CONTRIB_SEGMENTS = (
    ("modules", "contrib"),
    ("themes", "contrib"),
    ("profiles", "contrib"),
    ("drush", "Commands", "contrib"),
)
WEB_ROOTS = ("web", "docroot", "public_html", "html")


class CheckFailed(Exception):
    """The check could not finish; the message is a short code."""


@dataclass
class Dump:
    path: str
    blob: str
    format: str
    compression: Optional[str]
    size: int
    emails: int
    password_hashes: int
    readable: bool
    data_class: str
    decided_by: str
    in_web_root: bool
    history_commit: Optional[str] = None


@dataclass
class Result:
    dumps: list[Dump]
    # More dumps than were kept, or files that could not be read in full:
    # the check is incomplete, so it closes nothing.
    truncated: bool = False
    # Files in the tree that may hold a dump but could not be told apart
    # (an archive read only in part): deleted before the agent passes with
    # the dumps, never reported.
    withheld: list[str] = field(default_factory=list)
    # The tree may still hold a dump the check did not read: the agent
    # passes do not run (plan 5.6).
    unsafe: bool = False


class _Unsure(Exception):
    """An archive that could not be read far enough to tell."""


# --- reading ----------------------------------------------------------------


def _compression_of(name: str, head: bytes) -> Optional[str]:
    lower = name.lower()
    for suffix, kind in _COMPRESSED.items():
        if lower.endswith(suffix):
            return kind
    for magic, kind in (
        (_MAGIC_GZIP, "gzip"),
        (_MAGIC_BZIP2, "bzip2"),
        (_MAGIC_XZ, "xz"),
        (_MAGIC_ZSTD, "zstd"),
        (_MAGIC_ZIP, "zip"),
    ):
        if head.startswith(magic):
            return kind
    return None


def _open(raw: IO[bytes], compression: Optional[str]) -> Optional[IO[bytes]]:
    """A stream of the decompressed bytes, or None when they cannot be read
    here (zstd needs a newer Python than the runner's)."""
    if compression is None:
        return raw
    if compression == "gzip":
        return gzip.GzipFile(fileobj=raw)  # type: ignore[return-value]
    if compression == "bzip2":
        return bz2.BZ2File(raw)  # type: ignore[return-value]
    if compression == "xz":
        return lzma.LZMAFile(raw)  # type: ignore[return-value]
    # A zip file is read entry by entry (``_zip_signs``).
    return None


def _chunks(stream: IO[bytes], limit: int) -> Iterator[bytes]:
    left = limit
    while left > 0:
        chunk = stream.read(min(CHUNK, left))
        if not chunk:
            return
        left -= len(chunk)
        yield chunk


def _reserved(domain: bytes) -> bool:
    domain = domain.lower()
    return domain in _RESERVED_DOMAINS or domain.endswith(_RESERVED_SUFFIXES)


@dataclass
class Signs:
    format: Optional[str]
    rows: bool
    emails: int
    password_hashes: int
    readable: bool
    complete: bool
    read: int = 0


def _merge(parts: list[Signs], complete: bool) -> Signs:
    """One archive's signs from its entries'."""
    return Signs(
        format=next((p.format for p in parts if p.format), None),
        rows=any(p.rows for p in parts),
        emails=sum(p.emails for p in parts),
        password_hashes=sum(p.password_hashes for p in parts),
        readable=all(p.readable for p in parts),
        complete=complete and all(p.complete for p in parts),
        read=sum(p.read for p in parts),
    )


def _zip_signs(raw: IO[bytes], limit: int) -> Signs:
    """Every entry of a zip file, within one read limit: a dump can follow a
    README in the same archive."""
    try:
        archive = zipfile.ZipFile(raw)
        entries = [i for i in archive.infolist() if not i.is_dir()]
    except (OSError, EOFError, ValueError, zipfile.BadZipFile):
        return Signs(None, True, 0, 0, False, False)
    parts: list[Signs] = []
    left = limit
    for entry in entries[:MAX_ZIP_ENTRIES]:
        if left <= 0:
            return (
                _merge(parts, complete=False)
                if parts
                else Signs(None, True, 0, 0, True, False)
            )
        try:
            with archive.open(entry) as stream:
                part = read_signs(stream, left)
        except (OSError, EOFError, ValueError, zipfile.BadZipFile, RuntimeError):
            part = Signs(None, True, 0, 0, False, False)
        parts.append(part)
        left -= part.read
    if not parts:
        return Signs(None, False, 0, 0, True, True)
    merged = _merge(parts, complete=len(entries) <= MAX_ZIP_ENTRIES)
    if merged.format is None and any(_named(e.filename) for e in entries):
        # ``backup.zip`` holding ``backup.sql`` with rows and no header.
        merged.format = FORMAT_SQL
    return merged


def read_signs(stream: Optional[IO[bytes]], limit: int) -> Signs:
    """The dump format, whether it holds data rows, and the counts of real
    data signs in the first ``limit`` decompressed bytes."""
    if stream is None:
        return Signs(None, True, 0, 0, False, False)
    fmt: Optional[str] = None
    rows = False
    php_schema = False
    emails = hashes = 0
    tail = b""
    first = True
    complete = True
    read = 0
    try:
        for chunk in _chunks(stream, limit):
            read += len(chunk)
            if first:
                fmt = _format_of(chunk)
                first = False
            window = tail + chunk
            # Counted only in the new bytes, plus what straddles the join.
            start = max(0, len(tail) - _OVERLAP)
            for match in _EMAIL.finditer(window, start):
                if match.end() > len(tail) and not _reserved(match.group(1)):
                    emails += 1
            for match in _HASH.finditer(window, start):
                if match.end() > len(tail):
                    hashes += 1
            if not rows:
                rows = bool(_ROWS.search(window)) or _PHP_ROWS in window
            php_schema = php_schema or _PHP_SCHEMA in window
            tail = window[-_OVERLAP:]
        else:
            complete = stream.read(1) == b""
    except (OSError, EOFError, ValueError, zipfile.BadZipFile, lzma.LZMAError):
        return Signs(fmt, True, emails, hashes, False, False, read)
    if fmt is None and php_schema and rows:
        fmt = FORMAT_DRUPAL_PHP
    return Signs(fmt, rows, emails, hashes, True, complete, read)


def _format_of(start: bytes) -> Optional[str]:
    if start.startswith(_MAGIC_SQLITE):
        return FORMAT_SQLITE
    if start.startswith(_MAGIC_PGDMP):
        return FORMAT_POSTGRESQL_CUSTOM
    head = start[:4096]
    for marker, fmt in _HEADERS:
        if marker in head:
            return fmt
    if _PHP_SCHEMA in start and _PHP_ROWS in start:
        return FORMAT_DRUPAL_PHP
    return None


def _named(name: str) -> bool:
    """A dump's name, with or without a compression suffix (plan 5.1)."""
    lower = PurePosixPath(name).name.lower()
    for suffix in _COMPRESSED:
        if lower.endswith(suffix):
            lower = lower[: -len(suffix)]
            return lower.endswith(_SQL_NAMES)
    return lower.endswith(_PLAIN_NAMES)


def _maybe_sqlite(name: str) -> bool:
    return PurePosixPath(name).name.lower().endswith(".db")


# --- where a file sits ------------------------------------------------------


def _installer_folders(repo: Path, paths: dict) -> list[str]:
    """The folders of the packages composer.lock installs through
    ``installer-paths``. A pattern such as ``web/modules/{$name}`` also
    covers ``web/modules/custom``, so each package's own folder is worked
    out; never the pattern's parent."""
    rules = [
        (key, [c for c in conditions if isinstance(c, str)])
        for key, conditions in paths.items()
        if isinstance(key, str) and isinstance(conditions, list)
    ]
    try:
        lock = json.loads((repo / "composer.lock").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        lock = None
    folders: list[str] = []
    if not isinstance(lock, dict):
        # No lock file: only a pattern with no placeholder (``web/core``) or
        # one whose fixed part ends in a ``contrib`` folder.
        for key, _ in rules:
            fixed = key.split("{", 1)[0]
            if "{" not in key or fixed.rstrip("/").endswith("/contrib"):
                folders.append(_folder(fixed))
        return folders
    packages = [
        p
        for group in ("packages", "packages-dev")
        for p in (lock.get(group) or [])
        if isinstance(p, dict) and isinstance(p.get("name"), str) and "/" in p["name"]
    ]
    for package in packages:
        name = package["name"]
        vendor, _, project = name.partition("/")
        kind = package.get("type")
        for key, conditions in rules:
            if (
                name in conditions
                or f"type:{kind}" in conditions
                or f"vendor:{vendor}" in conditions
            ):
                folders.append(
                    _folder(
                        key.replace("{$name}", project).replace("{$vendor}", vendor)
                    )
                )
                break
    return folders


def composer_paths(repo: Path) -> tuple[list[str], Optional[str]]:
    """The folders Composer installs into, and the web root, from
    composer.json (plan 5.3 rule 2 and 5.4)."""
    prefixes = ["vendor/"]
    web_root: Optional[str] = None
    try:
        data = json.loads((repo / "composer.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        data = None
    if isinstance(data, dict):
        config = data.get("config")
        if isinstance(config, dict) and isinstance(config.get("vendor-dir"), str):
            prefixes = [_folder(config["vendor-dir"])]
        extra = data.get("extra")
        if isinstance(extra, dict):
            paths = extra.get("installer-paths")
            if isinstance(paths, dict):
                prefixes.extend(_installer_folders(repo, paths))
            scaffold = extra.get("drupal-scaffold")
            locations = (
                scaffold.get("locations") if isinstance(scaffold, dict) else None
            )
            root = locations.get("web-root") if isinstance(locations, dict) else None
            if isinstance(root, str):
                web_root = _folder(root)
    if web_root is None:
        for name in WEB_ROOTS:
            if (repo / name).is_dir():
                web_root = name + "/"
                break
    return [p for p in prefixes if p], web_root


def _folder(value: str) -> str:
    parts = [p for p in value.strip().split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        return ""
    return "/".join(parts) + "/" if parts else ""


def _composer_installed(
    path: str, prefixes: list[str], web_root: Optional[str]
) -> bool:
    if any(path.startswith(prefix) for prefix in prefixes):
        return True
    parts = path.split("/")
    # Drupal core and libraries at the web root or the repository root.
    roots = {""} | ({web_root} if web_root else set())
    for root in roots:
        if path.startswith(root + "core/") or path.startswith(root + "libraries/"):
            return True
    for segments in _CONTRIB_SEGMENTS:
        width = len(segments)
        for index in range(len(parts) - width):
            if tuple(parts[index : index + width]) == segments:
                return True
    return False


def classify(
    path: str,
    signs: Signs,
    size: int,
    prefixes: list[str],
    web_root: Optional[str],
) -> tuple[str, str]:
    """``(class, decided_by)``, first match wins (plan 5.3)."""
    installed = _composer_installed(path, prefixes, web_root)
    in_tests = any(part.lower() in TEST_SEGMENTS for part in path.split("/")[:-1])
    if installed:
        # Core's fixtures hold fake password hashes and made-up addresses on
        # domains that are not reserved (checked on Drupal 10.3, November
        # 2026), and some are large: in a package's own test folder nothing
        # counts. Elsewhere in a package, only email addresses do.
        if signs.emails and not in_tests:
            return CLASS_REAL, DECIDED_REAL_DATA
        if not in_tests and not (signs.readable and signs.complete):
            # Outside a package's tests and not read in full: never test.
            return CLASS_REAL, DECIDED_UNREAD
        return CLASS_TEST, DECIDED_COMPOSER
    if signs.emails or signs.password_hashes or size > TEST_MAX_BYTES:
        return CLASS_REAL, DECIDED_REAL_DATA
    if in_tests and not (signs.readable and signs.complete):
        # Real data could sit past what was read: never called test data.
        return CLASS_REAL, DECIDED_UNREAD
    if in_tests:
        return CLASS_TEST, DECIDED_TEST_FOLDER
    return CLASS_REAL, DECIDED_DEFAULT


def _in_web_root(path: str, web_root: Optional[str]) -> bool:
    if web_root is None:
        return False
    return web_root == "" or path.startswith(web_root)


# --- git --------------------------------------------------------------------


def _git(repo: Path, *args: str, stdin: Optional[bytes] = None) -> bytes:
    done = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=stdin,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if done.returncode != 0:
        raise CheckFailed("git_failed")
    return done.stdout


def _is_checkout(repo: Path) -> bool:
    try:
        return _git(repo, "rev-parse", "--is-inside-work-tree").strip() == b"true"
    except (CheckFailed, OSError, subprocess.TimeoutExpired):
        return False


def _blob_id(path: Path) -> str:
    """The id git would give the file's content."""
    digest = hashlib.sha1(
        f"blob {path.stat().st_size}\0".encode(), usedforsecurity=False
    )
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _walked(repo: Path) -> dict[str, str]:
    """Every regular file in a folder that is not a git checkout, with the
    id git would give it. Never links, never ``.git``."""
    files: dict[str, str] = {}
    for folder, names, filenames in os.walk(repo):
        names[:] = [n for n in names if n != ".git"]
        for name in filenames:
            path = Path(folder, name)
            if path.is_symlink() or not path.is_file():
                continue
            files[path.relative_to(repo).as_posix()] = ""
    return files


def _tracked(repo: Path) -> tuple[dict[str, str], bool]:
    """Regular files in the index and their blob ids; never links or
    submodules. True as well when a name could not be read as UTF-8: that
    file is not checked."""
    out = _git(repo, "ls-files", "-s", "-z")
    files: dict[str, str] = {}
    undecodable = False
    for entry in out.split(b"\0"):
        if not entry:
            continue
        meta, _, name = entry.partition(b"\t")
        fields = meta.split(b" ")
        if len(fields) != 3 or fields[0] not in (b"100644", b"100755"):
            continue
        try:
            files[name.decode("utf-8")] = fields[1].decode()
        except UnicodeDecodeError:
            undecodable = True
    return files, undecodable


def _history(repo: Path, commits: int) -> dict[str, tuple[str, str]]:
    """Paths added or changed in the last ``commits`` commits, newest first:
    ``{path: (commit, blob)}`` for the newest version of each."""
    if commits <= 0:
        return {}
    # The last ``commits`` commits first: with a diff filter, ``log -n``
    # would count only the commits that match it and reach further back.
    recent = _git(repo, "rev-list", f"-n{commits}", "HEAD")
    if not recent.strip():
        return {}
    out = _git(
        repo,
        "log",
        "--stdin",
        "--no-walk=unsorted",
        "--diff-filter=AM",
        "--no-renames",
        "--raw",
        "--no-abbrev",
        "--format=%x01%H",
        "-z",
        stdin=recent,
    )
    found: dict[str, tuple[str, str]] = {}
    for record in out.split(b"\x01"):
        if not record:
            continue
        commit, _, rest = record.partition(b"\0")
        tokens = rest.lstrip(b"\n").split(b"\0")
        for meta, name in zip(tokens[0::2], tokens[1::2]):
            meta = meta.strip()
            if not meta.startswith(b":"):
                continue
            fields = meta.split(b" ")
            if len(fields) < 5 or fields[1] not in (b"100644", b"100755"):
                continue
            try:
                path = name.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if path not in found:
                found[path] = (commit.decode(), fields[3].decode())
    return found


def _blob_size(repo: Path, blob: str) -> int:
    return int(_git(repo, "cat-file", "-s", blob).strip() or 0)


class _BlobStream(io.RawIOBase):
    """A blob's bytes from ``git cat-file``, read lazily, never more than
    the caller asks for."""

    def __init__(self, repo: Path, blob: str) -> None:
        self._process = subprocess.Popen(
            ["git", "-C", str(repo), "cat-file", "blob", blob],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        assert self._process.stdout is not None
        data = self._process.stdout.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.kill()
        self._process.wait()
        if self._process.stdout is not None:
            self._process.stdout.close()
        super().close()


# --- the check --------------------------------------------------------------


def _inspect(
    name: str, opener: Any, size: int, named: bool, read_bytes: int
) -> Optional[tuple[Signs, Optional[str]]]:
    """The signs of one file, or None when it is not a dump."""
    with opener() as raw:
        head = raw.read(16)
    compression = _compression_of(name, head)
    if not named and not (compression or _maybe_sqlite(name)):
        # A file without a dump's name: only its first bytes, for a header.
        with opener() as raw:
            start = raw.read(SNIFF_BYTES)
        if _format_of(start) is None:
            return None
    if _maybe_sqlite(name) and not named and not head.startswith(_MAGIC_SQLITE):
        return None
    with opener() as raw:
        buffered = io.BufferedReader(raw) if isinstance(raw, io.RawIOBase) else raw
        if compression == "zip":
            signs = _zip_signs(buffered, read_bytes)
        else:
            try:
                stream = _open(buffered, compression)
            except (OSError, EOFError, zipfile.BadZipFile, lzma.LZMAError):
                stream = None
            signs = read_signs(stream, read_bytes)
    if not named and signs.format is None and compression is not None:
        if not (signs.readable and signs.complete):
            # An archive read only in part, or not at all: it may hold a dump.
            raise _Unsure
    if not named and signs.format is None:
        # A compressed file of another kind (an image archive, say).
        return None
    if (
        signs.readable
        and signs.complete
        and not signs.rows
        and signs.format not in (FORMAT_SQLITE, FORMAT_POSTGRESQL_CUSTOM)
    ):
        # A schema with no data rows is not a dump of any data. One read
        # only in part may have its rows further on: it stays a dump.
        return None
    return signs, compression


def _history_opener(repo: Path, blob: str, size: int) -> tuple[Any, bool]:
    """How to read a blob from history, and whether it can be read in full.

    A zip file needs to seek to its directory, which a pipe cannot: it is
    read into memory when small enough."""
    with _BlobStream(repo, blob) as stream:
        head = stream.read(len(_MAGIC_ZIP))
    if head.startswith(_MAGIC_ZIP):
        if size > SEEKABLE_MAX:
            return (lambda: _BlobStream(repo, blob)), False
        data = _git(repo, "cat-file", "blob", blob)
        return (lambda: io.BytesIO(data)), True
    return (lambda: _BlobStream(repo, blob)), True


def check(
    repo: Path,
    history_commits: int,
    read_bytes: int = READ_BYTES,
) -> Result:
    """Every dump in the tree and in recent history (plan 5.1-5.4)."""
    prefixes, web_root = composer_paths(repo)
    # A scan always clones the repository; a plain folder has no history and
    # its blob ids are worked out for the dumps found only.
    checkout = _is_checkout(repo)
    tracked, unsafe = _tracked(repo) if checkout else (_walked(repo), False)
    truncated = unsafe
    dumps: list[Dump] = []
    withheld: list[str] = []
    sniffed = 0

    def add(
        path: str,
        blob: str,
        size: int,
        signs: Signs,
        compression: Optional[str],
        commit: Optional[str],
    ) -> bool:
        nonlocal truncated
        if len(dumps) >= MAX_DUMPS:
            truncated = True
            return False
        data_class, decided = classify(path, signs, size, prefixes, web_root)
        dumps.append(
            Dump(
                path=path,
                blob=blob,
                format=signs.format or FORMAT_SQL,
                compression=compression,
                size=size,
                emails=signs.emails,
                password_hashes=signs.password_hashes,
                readable=signs.readable,
                data_class=data_class,
                decided_by=decided,
                in_web_root=commit is None and _in_web_root(path, web_root),
                history_commit=commit,
            )
        )
        return True

    for path, blob in sorted(tracked.items()):
        named = _named(path)
        if not named:
            if sniffed >= MAX_SNIFFED:
                truncated = unsafe = True
                continue
            sniffed += 1
        file = repo / path
        try:
            if file.is_symlink() or not file.is_file():
                continue
            size = file.stat().st_size
            if size == 0:
                continue
            found = _inspect(path, lambda: open(file, "rb"), size, named, read_bytes)
        except _Unsure:
            # Kept from the agent; the other files' results still stand.
            withheld.append(path)
            continue
        except OSError:
            truncated = unsafe = True
            continue
        if found is None:
            continue
        if not blob:
            blob = _blob_id(file)
        if not add(path, blob, size, found[0], found[1], None):
            unsafe = True
            break

    history = _history(repo, history_commits) if checkout else {}
    for path, (commit, blob) in history.items():
        if path in tracked:
            continue
        # A dump under any name is looked for in history too, as in the tree.
        named = _named(path)
        if not named:
            if sniffed >= MAX_SNIFFED:
                truncated = True
                continue
            sniffed += 1
        try:
            size = _blob_size(repo, blob)
            if size == 0:
                continue
            opener, whole = _history_opener(repo, blob, size)
            found = _inspect(path, opener, size, named, read_bytes)
        except (
            _Unsure,
            CheckFailed,
            ValueError,
            OSError,
            subprocess.SubprocessError,
        ):
            truncated = True
            continue
        if not whole and found is None:
            # A large zip file from history that could not be opened: it may
            # hold a dump under another name.
            truncated = True
        if found is None:
            continue
        if not add(path, blob, size, found[0], found[1], commit):
            break
    return Result(dumps=dumps, truncated=truncated, withheld=withheld, unsafe=unsafe)


def remove_from_tree(repo: Path, result: Result) -> list[str]:
    """Delete every dump found in the tree from the job's workspace, before
    the agent passes (plan 5.6). The workspace is thrown away after the job
    and nothing is pushed. Returns the paths removed."""
    removed = []
    root = repo.resolve()
    paths = [d.path for d in result.dumps if d.history_commit is None]
    for path in paths + list(result.withheld):
        target = (repo / path).resolve()
        if root not in target.parents:
            continue
        try:
            target.unlink()
        except FileNotFoundError:
            continue
        removed.append(path)
    return removed


def _child(conn: Any, repo: str, history_commits: int, read_bytes: int) -> None:
    try:
        result = check(Path(repo), history_commits, read_bytes)
        conn.send(
            (
                "ok",
                json.dumps(
                    {
                        "truncated": result.truncated,
                        "dumps": [asdict(d) for d in result.dumps],
                        "withheld": result.withheld,
                        "unsafe": result.unsafe,
                    }
                ),
            )
        )
    except CheckFailed as exc:
        conn.send(("failed", str(exc)[:64]))
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        conn.send(("failed", type(exc).__name__))
    finally:
        conn.close()


def run_isolated(
    repo_dir: Path,
    history_commits: int,
    seconds: float,
    read_bytes: int = READ_BYTES,
) -> Result:
    """``check`` in a child process killed after ``seconds``."""
    if seconds <= 0:
        raise CheckFailed("timed_out")
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_child,
        args=(child, str(repo_dir), history_commits, read_bytes),
        daemon=True,
    )
    process.start()
    child.close()
    try:
        if not parent.poll(seconds):
            raise CheckFailed("timed_out")
        status, payload = parent.recv()
    except EOFError:
        raise CheckFailed("ended") from None
    finally:
        parent.close()
        if process.is_alive():
            process.kill()
        process.join(5)
    if status != "ok":
        raise CheckFailed(payload)
    data = json.loads(payload)
    return Result(
        dumps=[Dump(**item) for item in data["dumps"]],
        truncated=bool(data["truncated"]),
        withheld=[str(p) for p in data["withheld"]],
        unsafe=bool(data["unsafe"]),
    )
