#!/usr/bin/env python3
"""Sentinel secret scan for GitHub Actions.

Finds secrets (Gitleaks, with Sentinel's rules) and committed database dumps
(Sentinel's dump check) in the commits of a pull request or push and in the
checked-out tree.

Standalone (no ``site-uuid``): fails on real findings and writes a job
summary. Honours the repository's ``.gitleaksignore``.

Linked (``site-uuid`` given, ``id-token: write``): asks GitHub for an OpenID
Connect token, sends one report to Sentinel and fails only on findings
Sentinel does not answer ``skip`` for (marked safe there, or test data).
Ignores ``.gitleaksignore`` and inline ``gitleaks:allow``, as Sentinel's own
scan does: Sentinel's safe marks take their place.

Never printed, written or sent: a secret's value. Sentinel gets the file,
line, rule, the first four and last two characters, the length and the
value's SHA-256. The job summary shows the first four and last two
characters only. Each value is masked in the log before anything else runs.

Standard library only. Settings come from the environment (``action.yml``).
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import dumps  # noqa: E402  (Sentinel's dump check, copied verbatim)

GITLEAKS_VERSION = "8.30.1"
# SHA-256 of each release archive, from gitleaks_8.30.1_checksums.txt.
GITLEAKS_SHA256 = {
    "x64": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    "arm64": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
}
GITLEAKS_URL = (
    "https://github.com/gitleaks/gitleaks/releases/download/"
    "v{version}/gitleaks_{version}_linux_{arch}.tar.gz"
)
RULES = HERE / "gitleaks.toml"

DEFAULT_API_URL = "https://ingest.sentinelconnector.io"
DEFAULT_AUDIENCE = "sentinel-secret-scan"
DEFAULT_HISTORY = 50
# Where linked mode keeps the repository's .gitleaksignore while Gitleaks
# runs: the name Sentinel's scan uses, so both give one fingerprint.
IGNORE_ASIDE = ".gitleaksignore.sentinel-aside"
MAX_RANGE = 10_000
# Sentinel takes at most this many findings in one report.
MAX_FINDINGS = 500
DUMP_SECONDS = 300.0
# The same limits as Sentinel's scan (app/patching/scan/result.py).
SHORT_SECRET = 12
SECRET_MIN = 4
RULE = re.compile(r"^[a-z0-9]{1,16}(-[a-z0-9]{1,16}){0,7}$")
UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
API_URL = re.compile(
    r"^(https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?"
    r"|http://(localhost|127\.0\.0\.1|[a-z0-9.-]+\.localhost)(:[0-9]{1,5})?)$"
)
ZERO = "0" * 40


class Stop(Exception):
    """A setting or tool problem: say it and fail the step."""


@dataclass
class Secret:
    rule: Optional[str]
    path: str
    line: Optional[int]
    value: str = field(repr=False)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.value.encode()).hexdigest()

    @property
    def preview(self) -> dict[str, Any]:
        if len(self.value) < SHORT_SECRET:
            return {"prefix": "", "suffix": "", "length": len(self.value)}
        return {
            "prefix": self.value[:4],
            "suffix": self.value[-2:],
            "length": len(self.value),
        }

    def shown(self) -> str:
        p = self.preview
        if not p["prefix"]:
            return f"({p['length']} characters)"
        return f"{p['prefix']}…{p['suffix']} ({p['length']} characters)"

    def report(self) -> dict[str, Any]:
        return {
            "kind": "secret",
            "rule": self.rule,
            "path": self.path,
            "line": self.line,
            "preview": self.preview,
            "value_sha256": self.digest,
        }


# Settings -------------------------------------------------------------------


def env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


@dataclass
class Settings:
    repo: Path
    site_uuid: str
    api_url: str
    audience: str
    history: int
    fail: bool
    gitleaks: str

    @property
    def linked(self) -> bool:
        return bool(self.site_uuid)


def settings() -> Settings:
    workspace = Path(env("GITHUB_WORKSPACE", os.getcwd()))
    repo = (workspace / env("SENTINEL_WORKING_DIRECTORY", ".")).resolve()
    if not (repo / ".git").exists():
        raise Stop(
            "The working directory is not a Git checkout. Check out the "
            "repository first, with fetch-depth: 0."
        )
    site_uuid = env("SENTINEL_SITE_UUID")
    if site_uuid and not UUID.match(site_uuid):
        raise Stop("site-uuid must be the site's UUID from the site page in Sentinel.")
    api_url = env("SENTINEL_API_URL", DEFAULT_API_URL).rstrip("/")
    if not API_URL.match(api_url):
        raise Stop(
            "api-url must be a base URL with no path, such as "
            f"{DEFAULT_API_URL}. Plain http:// is allowed only for localhost."
        )
    try:
        history = int(env("SENTINEL_HISTORY_COMMITS", str(DEFAULT_HISTORY)))
    except ValueError:
        raise Stop("history-commits must be a whole number.") from None
    if not 1 <= history <= 10_000:
        raise Stop("history-commits must be between 1 and 10000.")
    fail = env("SENTINEL_FAIL", "true").lower() not in ("false", "0", "no", "off")
    return Settings(
        repo=repo,
        site_uuid=site_uuid.lower(),
        api_url=api_url,
        audience=env("SENTINEL_AUDIENCE", DEFAULT_AUDIENCE),
        history=history,
        fail=fail,
        gitleaks=env("SENTINEL_GITLEAKS"),
    )


# Gitleaks -------------------------------------------------------------------


def install_gitleaks() -> str:
    """Download the pinned release and check its SHA-256 before using it."""
    machine = platform.machine().lower()
    arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(
        machine
    )
    if sys.platform != "linux" or arch is None:
        raise Stop(f"Gitleaks is installed for Linux x64 or arm64 runners only, not {sys.platform} {machine}.")
    url = GITLEAKS_URL.format(version=GITLEAKS_VERSION, arch=arch)
    try:
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
            data = response.read(64 * 1024 * 1024)
    except (urllib.error.URLError, OSError):
        raise Stop("Gitleaks could not be downloaded from GitHub. Nothing was scanned.") from None
    if hashlib.sha256(data).hexdigest() != GITLEAKS_SHA256[arch]:
        raise Stop("The Gitleaks download did not match its checksum. Nothing was scanned.")
    target = Path(env("RUNNER_TEMP", tempfile.gettempdir())) / "sentinel-gitleaks"
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.getmember("gitleaks")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise Stop("The Gitleaks download had no program in it.")
        binary = target / "gitleaks"
        binary.write_bytes(extracted.read())
    binary.chmod(0o755)
    return str(binary)


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return done.stdout.strip() if done.returncode == 0 else ""


def reachable(repo: Path, sha: str) -> bool:
    """A commit this checkout has (a shallow clone may not)."""
    if not SHA.match(sha or "") or sha == ZERO:
        return False
    done = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"],
        capture_output=True,
        check=False,
    )
    return done.returncode == 0


def event() -> dict[str, Any]:
    path = env("GITHUB_EVENT_PATH")
    if not path:
        return {}
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


def _reading(repo: Path, wanted: set[str]) -> tuple[int, bool]:
    """How many commits from the checkout's HEAD the dump check reads to
    take in ``wanted``, and whether it can. HEAD is GitHub's merge commit
    for a pull request, so base branch commits may fall among them."""
    order = git(repo, "rev-list", f"-n{MAX_RANGE}", "HEAD").split()
    last = [i for i, sha in enumerate(order) if sha in wanted]
    commits = last[-1] + 1 if last else max(1, min(len(wanted), MAX_RANGE))
    # A range that reaches past the limit is never read as complete.
    return commits, wanted <= set(order[:commits])


def commit_range(repo: Path, history: int) -> tuple[list[str], int, str]:
    """Gitleaks' --log-opts for the commits this run is about, how many
    commits the dump check reads, and what that covers: ``whole`` (the
    run's commits, or the last history-commits when the run names none),
    ``over_limit`` (more commits than the check reads) or ``window`` (the
    run names commits this checkout does not have)."""
    payload = event()
    payload = payload if isinstance(payload, dict) else {}
    base = head = ""
    pull = payload.get("pull_request")
    if isinstance(pull, dict):
        base = str((pull.get("base") or {}).get("sha") or "")
        head = str((pull.get("head") or {}).get("sha") or "")
    else:
        base, head = str(payload.get("before") or ""), str(payload.get("after") or "")
    if reachable(repo, base) and reachable(repo, head):
        wanted = set(git(repo, "rev-list", f"{base}..{head}").split())
        commits, whole = _reading(repo, wanted)
        return [f"{base}..{head}"], commits, "whole" if whole else "over_limit"
    if not pull and base == ZERO and reachable(repo, head):
        # A new branch: the commits on it and on no other branch the
        # checkout has. (A force push whose old commits are gone cannot
        # tell which commits are new, so it reads a window and is not sent.)
        ref = str(payload.get("ref") or "")
        mine = "refs/remotes/origin/" + ref.removeprefix("refs/heads/")
        others = [
            r
            for r in git(repo, "for-each-ref", "--format=%(refname)", "refs/remotes/").split()
            if r not in (mine, "refs/remotes/origin/HEAD")
        ]
        if others:
            wanted = set(git(repo, "rev-list", head, "--not", *others).split())
            commits, whole = _reading(repo, wanted)
            spec = " ".join([head, "--not", *others])
            return [spec], commits, "whole" if whole else "over_limit"
    named = bool(base or head)
    return [f"-n {history}"], history, "window" if named else "whole"


def run_gitleaks(cfg: Settings, mode: str, extra: list[str]) -> list[dict[str, Any]]:
    # The report comes back on a pipe ("-" is standard output), so the
    # values in it are never written to the runner's disk.
    command = [
        cfg.gitleaks,
        mode,
        *extra,
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--exit-code",
        "0",
        "--no-banner",
        "--log-level",
        "error",
        "--config",
        str(RULES),
    ]
    if cfg.linked:
        # As Sentinel's scan: the repository cannot allow a match away.
        command += ["--gitleaks-ignore-path", os.devnull, "--ignore-gitleaks-allow"]
    command.append(".")
    done = subprocess.run(
        command,
        cwd=cfg.repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if done.returncode != 0:
        raise Stop(f"Gitleaks could not finish ({mode}). Nothing was reported.")
    try:
        found = json.loads(done.stdout.decode() or "[]")
    except ValueError:
        raise Stop("Gitleaks wrote a report that could not be read.") from None
    return found if isinstance(found, list) else []


@contextlib.contextmanager
def ignore_file_aside(cfg: Settings) -> Iterator[Optional[str]]:
    """Linked mode: the repository's ``.gitleaksignore`` is renamed while
    Gitleaks runs. Gitleaks 8.30.1 reads it from the folder it scans even
    with ``--gitleaks-ignore-path``, and a commit must not be able to hide a
    finding from Sentinel. It stays in the repository under the name
    Sentinel's own scan uses, so the tree pass still reads what it holds,
    and is renamed back however the scan ends. A link stays a link. Yields
    the name it took, or None."""
    path = cfg.repo / ".gitleaksignore"
    if not cfg.linked or not os.path.lexists(path):
        yield None
        return
    # A repository cannot keep its file in place by taking the name.
    aside, n = cfg.repo / IGNORE_ASIDE, 0
    while os.path.lexists(aside):
        n += 1
        aside = cfg.repo / f"{IGNORE_ASIDE}-{n}"
    os.rename(path, aside)
    try:
        yield aside.name
    finally:
        os.rename(aside, path)


def from_another_parent(repo: Path, row: dict[str, Any]) -> bool:
    """A match a merge shows against its first parent that its other parent
    already had: it came in from the branch merged, not from this run's
    commits, so it is not this run's finding. A value added while resolving
    the merge is in no parent and stays."""
    commit = str(row.get("Commit") or "")
    path = str(row.get("File") or "")
    # The whole match (the assignment, not only the value): a parent that
    # merely mentions the value elsewhere did not have this finding.
    value = str(row.get("Match") or row.get("Secret") or "").encode()
    if not SHA.match(commit) or not path or not value:
        return False
    parents = git(repo, "rev-list", "--parents", "-n1", commit).split()[2:]
    for parent in parents:
        done = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "blob", f"{parent}:{path}"],
            capture_output=True,
            check=False,
        )
        if done.returncode == 0 and value in done.stdout:
            return True
    return False


def secrets_of(rows: list[dict[str, Any]]) -> list[Secret]:
    out: dict[tuple[Optional[str], str, str], Secret] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        value = str(row.get("Secret") or row.get("Match") or "").strip()
        if len(value) < SECRET_MIN:
            continue
        rule = str(row.get("RuleID") or "").strip() or None
        if rule and not RULE.match(rule):
            rule = None
        path = normalise(str(row.get("File") or ""))
        if value in path:
            # As Sentinel's scan: a path that holds the value is dropped.
            path = ""
        line = row.get("StartLine")
        line = line if isinstance(line, int) and line >= 1 else None
        secret = Secret(rule=rule, path=path, line=line, value=value)
        out.setdefault((rule, path, secret.digest), secret)
    return list(out.values())


def normalise(path: str) -> str:
    text = path.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def mask(values: list[str]) -> None:
    """Ask GitHub to hide each value in this job's log, before anything
    else is printed."""
    for value in values:
        if "\n" not in value and "\r" not in value:
            print(f"::add-mask::{value}", flush=True)


# Dumps ----------------------------------------------------------------------


def find_dumps(
    cfg: Settings, commits: int
) -> tuple[list[dumps.Dump], Optional[str], int]:
    """The dumps found, why the check did not finish (or None), and how many
    files it could not read (Sentinel's scan reports those as no finding)."""
    try:
        result = dumps.run_isolated(cfg.repo, commits, DUMP_SECONDS)
    except dumps.CheckFailed as exc:
        return [], str(exc) or "failed", 0
    note = "incomplete" if result.truncated else None
    return result.dumps, note, len(result.withheld)


def dump_report(item: dumps.Dump) -> dict[str, Any]:
    return {
        "kind": "database_dump",
        "path": item.path,
        "format": item.format,
        "compression": item.compression,
        "size": item.size,
        "emails": item.emails,
        "password_hashes": item.password_hashes,
        "readable": item.readable,
        "data_class": item.data_class,
        "decided_by": item.decided_by,
        "in_web_root": item.in_web_root,
        "blob": item.blob,
    }


# Sentinel -------------------------------------------------------------------


def oidc_token(audience: str) -> Optional[str]:
    """The run's GitHub token for Sentinel, or None where GitHub gives none
    (no ``id-token: write``, or a pull request from a fork)."""
    url, bearer = env("ACTIONS_ID_TOKEN_REQUEST_URL"), env("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        return None
    joined = url + ("&" if "?" in url else "?") + urllib.parse.urlencode({"audience": audience})
    request = urllib.request.Request(joined, headers={"Authorization": f"Bearer {bearer}"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            value = json.loads(response.read(64 * 1024)).get("value")
    except (urllib.error.URLError, OSError, ValueError, AttributeError):
        return None
    if isinstance(value, str) and value:
        print(f"::add-mask::{value}", flush=True)
        return value
    return None


class NotSent(Exception):
    """Sentinel did not take the report; the message says why, in plain words."""


def send(cfg: Settings, token: str, body: dict[str, Any]) -> list[str]:
    url = f"{cfg.api_url}/api/v1/sites/{cfg.site_uuid}/security-scan/ci-report"
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            answer = json.loads(response.read(1024 * 1024))
    except urllib.error.HTTPError as exc:
        reasons = {
            404: "Sentinel did not accept it. Check that the site takes reports "
            "from GitHub Actions (site page, Deep scan, Secrets and database "
            "dumps) and that this is the site's repository.",
            422: "Sentinel could not read the report.",
            429: "Too many reports for this site this hour.",
        }
        raise NotSent(reasons.get(exc.code, f"Sentinel answered {exc.code}.")) from None
    except (urllib.error.URLError, OSError, ValueError):
        raise NotSent("Sentinel could not be reached.") from None
    results = answer.get("results") if isinstance(answer, dict) else None
    if not isinstance(results, list) or len(results) != len(body["findings"]):
        raise NotSent("Sentinel's answer could not be read.")
    return [str((r or {}).get("result")) for r in results]


def pull_request_number() -> Optional[int]:
    pull = event().get("pull_request")
    number = pull.get("number") if isinstance(pull, dict) else None
    return number if isinstance(number, int) and number >= 1 else None


# Summary --------------------------------------------------------------------


def cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").replace("`", "'")


def summary(rows: list[tuple[str, str, str, str]], notes: list[str]) -> str:
    lines = ["## Sentinel secret scan", ""]
    failing = sum(1 for r in rows if r[3] == "Failing")
    lines.append(
        f"{failing} failing finding{'s' if failing != 1 else ''}, "
        f"{len(rows) - failing} not failing."
        if rows
        else "No secrets or database dumps found."
    )
    lines.append("")
    if rows:
        lines += ["| Finding | File | Detail | Status |", "|---|---|---|---|"]
        lines += [f"| {cell(a)} | {cell(b)} | {cell(c)} | {d} |" for a, b, c, d in rows]
        lines.append("")
    lines += [f"- {note}" for note in notes]
    return "\n".join(lines) + "\n"


def write_summary(text: str) -> None:
    path = env("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)
    print(text)


# Run ------------------------------------------------------------------------


def main() -> int:
    try:
        cfg = settings()
        if not cfg.gitleaks:
            cfg.gitleaks = install_gitleaks()
        log_opts, commits, covered = commit_range(cfg.repo, cfg.history)
        with ignore_file_aside(cfg) as moved:
            # --text: a repository's .gitattributes (binary, -diff) cannot
            # keep a file's changes out of the patches Gitleaks reads. A
            # merge's changes against its first parent are read too.
            opts = f"--text --diff-merges=first-parent {log_opts[0]}"
            rows = [
                row
                for row in run_gitleaks(cfg, "git", ["--log-opts", opts])
                if not (isinstance(row, dict) and from_another_parent(cfg.repo, row))
            ]
            tree = run_gitleaks(cfg, "dir", [])
        # Only the tree pass reads the renamed file; history has real paths.
        for row in tree:
            if moved and isinstance(row, dict) and normalise(str(row.get("File") or "")) == moved:
                row["File"] = ".gitleaksignore"
        rows += tree
        found = secrets_of(rows)
        del rows
        mask([s.value for s in found])
    except Stop as exc:
        print(f"::error::{exc}", flush=True)
        return 1

    found_dumps, dump_note, unread = find_dumps(cfg, commits)
    if covered == "over_limit" and not dump_note:
        dump_note = "incomplete"
    notes: list[str] = []
    if covered == "window":
        notes.append(
            f"This run's commits are not all in the checkout (a force push, or "
            f"fetch-depth other than 0), so only the last {cfg.history} commits "
            "were read."
        )
    if unread:
        notes.append(
            f"{unread} compressed file{'s' if unread != 1 else ''} could not be "
            "read to check for a database dump, as in Sentinel's own scan."
        )
    if dump_note:
        notes.append(
            "The database dump check did not finish"
            + (" in full" if dump_note == "incomplete" else "")
            + ", so the check fails."
        )

    # No path reported or shown may hold a value found in this run.
    values = [s.value for s in found]
    for secret in found:
        if any(v in secret.path for v in values):
            secret.path = ""
    hidden = [d for d in found_dumps if any(v in d.path for v in values)]
    found_dumps = [d for d in found_dumps if d not in hidden]
    if hidden:
        notes.append(
            f"{len(hidden)} database dump{'s' if len(hidden) != 1 else ''} "
            "not shown or reported: the path holds a secret. Rename the file."
        )

    secrets_part = [s.report() for s in found]
    dumps_part = [dump_report(d) for d in found_dumps]
    findings = (secrets_part + dumps_part)[:MAX_FINDINGS]
    left_out = len(secrets_part) + len(dumps_part) - len(findings)

    # Standalone: real dumps and every secret fail; test dumps do not.
    answers = [
        "skip" if f["kind"] == "database_dump" and f["data_class"] == "test" else "report"
        for f in findings
    ]
    # A partial report is never sent: Sentinel would read what it leaves
    # out (an unfinished dump check, findings over the limit, a dump whose
    # path holds a secret) as gone.
    partial = bool(dump_note or left_out or hidden or covered == "window")
    if cfg.linked and partial:
        notes.append("Not reported to Sentinel: this run's result is not complete.")
    elif cfg.linked:
        token = oidc_token(cfg.audience)
        if token is None:
            notes.append(
                "Not reported to Sentinel: GitHub gave this run no token "
                "(a pull request from a fork, or no id-token: write). "
                "The check uses this run's findings."
            )
        else:
            body = {
                "ref": env("GITHUB_REF"),
                "commit": env("GITHUB_SHA"),
                "pull_request": pull_request_number(),
                "findings": findings,
            }
            try:
                answers = send(cfg, token, body)
                notes.append("Reported to Sentinel. Findings marked safe there are skipped.")
            except NotSent as exc:
                notes.append(f"Not reported to Sentinel: {exc} The check uses this run's findings.")
    if left_out:
        notes.append(f"{left_out} more findings were not reported; they fail the check.")

    table: list[tuple[str, str, str, str]] = []
    failing = left_out + len(hidden) + (1 if dump_note else 0)
    for item, answer in zip(findings, answers):
        bad = answer != "skip"
        failing += bad
        if item["kind"] == "secret":
            secret = next(s for s in found if s.digest == item["value_sha256"])
            what = f"Secret ({item['rule'] or 'unnamed rule'})"
            where = item["path"] or "(the path holds the secret)"
            if item["line"]:
                where += f":{item['line']}"
            detail = secret.shown()
        else:
            test = item["data_class"] == "test"
            what = "Database dump" + (" (test data)" if test else "")
            where = item["path"]
            detail = f"{item['emails']} email addresses, {item['password_hashes']} password hashes"
        status = "Failing" if bad else ("Marked safe" if cfg.linked and answer == "skip" and item["kind"] == "secret" else "Not failing")
        table.append((what, where, detail, status))
    write_summary(summary(table, notes))
    if dump_note:
        # The check did not finish: never a pass, whatever fail-on-findings says.
        print("::error::The database dump check did not finish.", flush=True)
        return 1
    if failing and cfg.fail:
        print("::error::The secret scan failed. See the job summary.", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
