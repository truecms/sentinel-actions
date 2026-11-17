"""Tests for secret-scan/scan.py.

Each test makes a throwaway Git repository and runs the script as the
action does. Gitleaks is the real program: set SENTINEL_TEST_GITLEAKS to its
path (CI installs the pinned release). GitHub's token endpoint and Sentinel
are a local HTTP server.

Run: SENTINEL_TEST_GITLEAKS=/path/to/gitleaks python3 -m unittest discover tests/secret-scan
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "secret-scan" / "scan.py"
GITLEAKS = os.environ.get("SENTINEL_TEST_GITLEAKS", "")
SITE = "6f0d2a44-1b3c-4d5e-8f70-123456789abc"
# Built in two parts so this file holds no whole token for a scanner to find.
VALUE = "sk_" + "live_51HxQPLANTEDvalue00424242abcd"
SECRET_LINE = f'$stripe = "{VALUE}";\n'
DUMP = (
    "-- MySQL dump 10.13  Distrib 8.0.36\n"
    "CREATE TABLE `users_field_data` (`uid` int, `mail` varchar(254));\n"
    "INSERT INTO `users_field_data` VALUES "
    "(1,'jane.citizen@acme-health.com.au'),(2,'li.wei@acme-health.com.au');\n"
)


def sh(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def make_repo(files: dict[str, str]) -> Path:
    repo = Path(tempfile.mkdtemp(prefix="secret-scan-test-"))
    sh(repo, "init", "-q")
    sh(repo, "config", "user.email", "test@example.com")
    sh(repo, "config", "user.name", "Test")
    (repo / "README.md").write_text("base\n")
    sh(repo, "add", "-A")
    sh(repo, "commit", "-qm", "base")
    for name, text in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    if files:
        sh(repo, "add", "-A")
        sh(repo, "commit", "-qm", "change")
    return repo


class Stub(BaseHTTPRequestHandler):
    """GitHub's token endpoint and Sentinel's report route."""

    answer: list[str] = []
    status = 200
    seen: list[dict] = []

    def log_message(self, *args):  # noqa: D401 - quiet
        pass

    def do_GET(self):  # noqa: N802
        Stub.seen.append({"path": self.path, "auth": self.headers.get("Authorization")})
        body = json.dumps({"value": "header.payload.signature"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        Stub.seen.append(
            {"path": self.path, "auth": self.headers.get("Authorization"), "raw": raw}
        )
        if Stub.status != 200:
            self.send_response(Stub.status)
            self.end_headers()
            return
        count = len(json.loads(raw)["findings"])
        answers = (Stub.answer or ["report"]) * count
        body = json.dumps({"results": [{"result": a} for a in answers[:count]]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


@unittest.skipUnless(GITLEAKS, "set SENTINEL_TEST_GITLEAKS to a Gitleaks 8.30.1 binary")
class ScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Stub.answer, Stub.status, Stub.seen = [], 200, []

    def run_scan(self, repo: Path, linked=False, token=True, event=None, **extra):
        temp = Path(tempfile.mkdtemp(prefix="secret-scan-run-"))
        summary = temp / "summary.md"
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", str(temp)),
            "GITHUB_WORKSPACE": str(repo),
            "GITHUB_STEP_SUMMARY": str(summary),
            "GITHUB_REF": "refs/pull/12/merge",
            "GITHUB_SHA": sh(repo, "rev-parse", "HEAD"),
            "RUNNER_TEMP": str(temp),
            "SENTINEL_GITLEAKS": GITLEAKS,
            **extra,
        }
        if event is not None:
            path = temp / "event.json"
            path.write_text(json.dumps(event))
            environment["GITHUB_EVENT_PATH"] = str(path)
        if linked:
            environment["SENTINEL_SITE_UUID"] = SITE
            environment["SENTINEL_API_URL"] = f"http://127.0.0.1:{self.port}"
            if token:
                environment["ACTIONS_ID_TOKEN_REQUEST_URL"] = (
                    f"http://127.0.0.1:{self.port}/token?api-version=2.0"
                )
                environment["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "request-token"
        done = subprocess.run(
            [sys.executable, str(SCRIPT)],
            env=environment,
            capture_output=True,
            text=True,
            timeout=300,
        )
        text = summary.read_text() if summary.exists() else ""
        return done, text

    def assert_value_hidden(self, done, text):
        """The value only ever appears in GitHub's own mask command."""
        for line in (done.stdout + done.stderr).splitlines():
            if VALUE in line:
                self.assertEqual(line, f"::add-mask::{VALUE}")
        self.assertNotIn(VALUE, text)
        for request in Stub.seen:
            self.assertNotIn(VALUE.encode(), request.get("raw", b""))

    def test_standalone_fails_on_a_secret_and_shows_only_its_ends(self):
        repo = make_repo({"web/sites/default/settings.local.php": "<?php\n" + SECRET_LINE})
        done, text = self.run_scan(repo)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("stripe-access-token", text)
        self.assertIn("web/sites/default/settings.local.php:2", text)
        self.assertIn(f"sk_l…cd ({len(VALUE)} characters)", text)
        self.assertIn(f"::add-mask::{VALUE}", done.stdout)
        self.assert_value_hidden(done, text)
        self.assertEqual(Stub.seen, [])

    def test_a_clean_repository_passes(self):
        repo = make_repo({"src/app.txt": "nothing here\n"})
        done, text = self.run_scan(repo)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("No secrets or database dumps found.", text)

    def test_fail_on_findings_false_only_writes_the_summary(self):
        repo = make_repo({"settings.php": SECRET_LINE})
        done, text = self.run_scan(repo, SENTINEL_FAIL="false")
        self.assertEqual(done.returncode, 0)
        self.assertIn("1 failing finding", text)

    def test_standalone_honours_gitleaksignore_and_linked_does_not(self):
        repo = make_repo({"settings.php": SECRET_LINE})
        head = sh(repo, "rev-parse", "HEAD")
        (repo / ".gitleaksignore").write_text(
            f"{head}:settings.php:stripe-access-token:1\nsettings.php:stripe-access-token:1\n"
        )
        done, _ = self.run_scan(repo)
        self.assertEqual(done.returncode, 0, done.stdout)
        Stub.answer = ["report"]
        done, text = self.run_scan(repo, linked=True)
        self.assertEqual(done.returncode, 1, text)
        self.assertEqual(len(json.loads(Stub.seen[-1]["raw"])["findings"]), 1)
        # The file is back where it was.
        self.assertTrue((repo / ".gitleaksignore").exists())

    def test_linked_does_not_follow_a_linked_gitleaksignore(self):
        repo = make_repo({"settings.php": SECRET_LINE})
        (repo / "ignores.txt").write_text("settings.php:stripe-access-token:1\n")
        os.symlink("ignores.txt", repo / ".gitleaksignore")
        Stub.answer = ["report"]
        done, text = self.run_scan(repo, linked=True)
        self.assertEqual(done.returncode, 1, text)
        self.assertEqual(len(json.loads(Stub.seen[-1]["raw"])["findings"]), 1)
        # The link is back, still a link to the same file.
        self.assertEqual(os.readlink(repo / ".gitleaksignore"), "ignores.txt")
        self.assertTrue((repo / "ignores.txt").is_file())

    def test_an_unfinished_dump_check_fails_and_is_not_reported(self):
        repo = make_repo({})
        temp = Path(tempfile.mkdtemp(prefix="secret-scan-run-"))
        summary = temp / "summary.md"
        environment = {
            "GITHUB_WORKSPACE": str(repo),
            "GITHUB_STEP_SUMMARY": str(summary),
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": sh(repo, "rev-parse", "HEAD"),
            "RUNNER_TEMP": str(temp),
            "SENTINEL_GITLEAKS": GITLEAKS,
            "SENTINEL_SITE_UUID": SITE,
            "SENTINEL_API_URL": f"http://127.0.0.1:{self.port}",
            "ACTIONS_ID_TOKEN_REQUEST_URL": f"http://127.0.0.1:{self.port}/token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-token",
            # Advisory mode still fails a check that did not finish.
            "SENTINEL_FAIL": "false",
        }
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            import scan  # noqa: PLC0415

            with mock.patch.dict(os.environ, environment), mock.patch.object(
                scan, "find_dumps", return_value=([], "incomplete", 0)
            ), contextlib.redirect_stdout(io.StringIO()):
                code = scan.main()
        finally:
            sys.path.remove(str(SCRIPT.parent))
        self.assertEqual(code, 1)
        self.assertEqual(Stub.seen, [])
        self.assertIn("did not finish in full", summary.read_text())

    def test_a_dump_whose_path_holds_a_found_secret_is_never_shown_or_sent(self):
        repo = make_repo({"settings.php": SECRET_LINE, f"backup/{VALUE}.sql": DUMP})
        Stub.answer = ["report"]
        done, text = self.run_scan(repo, linked=True)
        self.assertEqual(done.returncode, 1, text)
        # Nothing is sent: a report without the dump would read it as gone.
        self.assertEqual([c for c in Stub.seen if "raw" in c], [])
        self.assertIn("the path holds a secret", text)
        self.assertIn("this run's result is not complete", text)
        self.assert_value_hidden(done, text)

    def test_linked_sends_the_report_and_skips_what_sentinel_marked_safe(self):
        repo = make_repo({"settings.php": SECRET_LINE})
        Stub.answer = ["skip"]
        event = {"pull_request": {"number": 12}}
        done, text = self.run_scan(repo, linked=True, event=event)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        token_call, report_call = Stub.seen
        self.assertIn("audience=sentinel-secret-scan", token_call["path"])
        self.assertEqual(token_call["auth"], "Bearer request-token")
        self.assertEqual(report_call["path"], f"/api/v1/sites/{SITE}/security-scan/ci-report")
        self.assertEqual(report_call["auth"], "Bearer header.payload.signature")
        body = json.loads(report_call["raw"])
        self.assertEqual(body["ref"], "refs/pull/12/merge")
        self.assertEqual(body["pull_request"], 12)
        [finding] = body["findings"]
        self.assertEqual(finding["kind"], "secret")
        self.assertEqual(finding["preview"], {"prefix": "sk_l", "suffix": "cd", "length": len(VALUE)})
        self.assertRegex(finding["value_sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("Marked safe", text)
        self.assert_value_hidden(done, text)

    def test_with_no_token_nothing_is_sent_and_the_check_still_runs(self):
        repo = make_repo({"settings.php": SECRET_LINE})
        done, text = self.run_scan(repo, linked=True, token=False)
        self.assertEqual(done.returncode, 1)
        self.assertEqual(Stub.seen, [])
        self.assertIn("GitHub gave this run no token", text)

    def test_a_refused_report_falls_back_to_this_runs_findings(self):
        repo = make_repo({"settings.php": SECRET_LINE})
        Stub.status = 404
        done, text = self.run_scan(repo, linked=True)
        self.assertEqual(done.returncode, 1)
        self.assertIn("Sentinel did not accept it", text)
        self.assert_value_hidden(done, text)

    def test_a_path_that_holds_the_secret_is_never_shown_or_sent(self):
        repo = make_repo({f"keys/{VALUE}.txt": SECRET_LINE})
        done, text = self.run_scan(repo, linked=True)
        self.assertIn("(the path holds the secret)", text)
        self.assert_value_hidden(done, text)

    def test_a_pull_request_reads_only_its_own_commits(self):
        repo = make_repo({"old.php": SECRET_LINE})
        (repo / "old.php").unlink()
        sh(repo, "commit", "-qam", "remove")
        base = sh(repo, "rev-parse", "HEAD")
        (repo / "new.txt").write_text("fine\n")
        sh(repo, "add", "-A")
        sh(repo, "commit", "-qm", "pr")
        head = sh(repo, "rev-parse", "HEAD")
        event = {"pull_request": {"number": 3, "base": {"sha": base}, "head": {"sha": head}}}
        done, text = self.run_scan(repo, event=event)
        self.assertEqual(done.returncode, 0, text)

    def test_a_pull_request_reads_dumps_in_all_its_commits(self):
        """GitHub checks out a merge commit; base commits newer than the
        pull request's must not push its commits out of the dump check."""
        repo = make_repo({})
        sh(repo, "checkout", "-qb", "feature")
        (repo / "backup.sql").write_text(DUMP)
        sh(repo, "add", "-A")
        sh(repo, "commit", "-qm", "add dump")
        sh(repo, "rm", "-q", "backup.sql")
        sh(repo, "commit", "-qm", "remove dump")
        head = sh(repo, "rev-parse", "HEAD")
        sh(repo, "checkout", "-q", "-")
        for n in range(5):
            # Base commits dated after the pull request's come first in HEAD's log.
            (repo / f"base{n}.txt").write_text(f"{n}\n")
            sh(repo, "add", "-A")
            date = f"2099-01-0{n + 1}T00:00:00"
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-qm", f"base {n}"],
                check=True,
                env={**os.environ, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date},
            )
        tip = sh(repo, "rev-parse", "HEAD")
        sh(repo, "merge", "-q", "--no-ff", "-m", "merge", "feature")
        event = {"pull_request": {"number": 4, "base": {"sha": tip}, "head": {"sha": head}}}
        done, text = self.run_scan(repo, event=event)
        self.assertEqual(done.returncode, 1, text)
        self.assertIn("Database dump", text)

    def test_a_real_dump_fails_and_a_test_dump_does_not(self):
        repo = make_repo({"backup/site.sql": DUMP})
        done, text = self.run_scan(repo)
        self.assertEqual(done.returncode, 1, text)
        self.assertIn("Database dump", text)
        self.assertIn("2 email addresses", text)
        self.assertNotIn("jane.citizen", text + done.stdout)

        fixture = (
            "-- MySQL dump 10.13\nCREATE TABLE `node` (`nid` int);\n"
            "INSERT INTO `node` VALUES (1);\n"
        )
        repo = make_repo({"web/modules/custom/x/tests/fixtures/events.sql": fixture})
        done, text = self.run_scan(repo)
        self.assertEqual(done.returncode, 0, text)
        self.assertIn("Database dump (test data)", text)

    def test_bad_settings_stop_with_a_plain_message(self):
        repo = make_repo({})
        done, _ = self.run_scan(repo, SENTINEL_SITE_UUID="not-a-uuid")
        self.assertEqual(done.returncode, 1)
        self.assertIn("site-uuid must be the site's UUID", done.stdout)
        done, _ = self.run_scan(repo, SENTINEL_API_URL="http://example.com")
        self.assertIn("api-url must be a base URL", done.stdout)


class CopiesTest(unittest.TestCase):
    """The rules and the dump check are Sentinel's own, copied verbatim; a
    check in the Sentinel repository compares their SHA-256 with this
    release's."""

    def test_the_dump_check_needs_only_the_standard_library(self):
        source = (ROOT / "secret-scan" / "dumps.py").read_text()
        self.assertNotIn("from app", source)
        self.assertNotIn("import app", source)

    def test_the_rules_are_sentinels(self):
        rules = (ROOT / "secret-scan" / "gitleaks.toml").read_text()
        self.assertIn("Sentinel's Gitleaks configuration", rules)


if __name__ == "__main__":
    unittest.main()
