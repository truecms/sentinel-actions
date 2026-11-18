# Secret scan

Finds secrets and committed database dumps in each pull request and push, in
your own GitHub Actions. It works on its own, or reports to
[Sentinel](https://sentinelconnector.io) so the findings show on your site's
Deep scan.

- Secrets: [Gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1, downloaded
  from its GitHub release and checked against its SHA-256 before it runs,
  with Sentinel's rules ([`gitleaks.toml`](gitleaks.toml)). Your repository's
  own `.gitleaks.toml` is never read.
- Database dumps: Sentinel's dump check ([`dumps.py`](dumps.py)). It tells
  real data from test data, such as the dumps Drupal ships in its test
  folders. Test dumps never fail the check.
- It reads the commits of the pull request or push, and the checked-out files.
- It never prints, stores or sends a secret's value. Each value is masked in
  the job log first. The job summary shows the rule, the file, the line and
  the first four and last two characters only.

Files: [`action.yml`](action.yml), [`scan.py`](scan.py) (the script it
runs, Python standard library only), [`examples/`](examples).

## On its own

```yaml
name: Secrets
on: [pull_request, push]
permissions:
  contents: read
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: truecms/sentinel-actions/secret-scan@v1.2.0
```

It fails when it finds a secret or a dump of real data. To accept a finding,
add it to `.gitleaksignore` in your repository, as Gitleaks describes. Nothing
leaves the runner except the Gitleaks download from GitHub.

## With Sentinel

On the site's page in Sentinel, open the Patching tab, then Deep scan, then
**Secrets and database dumps**. An organisation administrator turns on
**Accept reports from GitHub Actions**, then copies the workflow file shown
there. It is the same as above with two changes:

```yaml
permissions:
  contents: read
  id-token: write   # lets GitHub prove the repository to Sentinel
# ...
      - uses: truecms/sentinel-actions/secret-scan@v1.2.0
        with:
          site-uuid: <your site's UUID>
```

- **No key, no secret.** GitHub signs a token for each run. Sentinel checks
  the signature and accepts the report only from the repository mapped to
  the site.
- **What is sent:** for a secret, the rule, file, line, the first four and
  last two characters, the length and the SHA-256 of the value; for a dump,
  its path, format, size and counts of email addresses and password hashes.
  Never the value, never a line of a dump.
- **Mark as safe in Sentinel:** a finding marked safe on the site is skipped
  here, so the check passes. In this mode `.gitleaksignore` and inline
  `gitleaks:allow` comments are ignored: a commit cannot hide a finding from
  Sentinel. Mark it safe in Sentinel instead.
- **Pull requests from forks** are checked but not reported: GitHub gives
  them no token. The check uses its own findings.
- If Sentinel cannot be reached or does not accept the report, the check
  uses its own findings and says why in the summary.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `site-uuid` | empty | The site's UUID in Sentinel. Empty: run on your own, send nothing. |
| `api-url` | production | Sentinel API base URL. |
| `audience` | `sentinel-secret-scan` | The audience of the GitHub token. Change it only if Sentinel tells you to. |
| `working-directory` | `.` | The repository root, if it is not the workspace. |
| `history-commits` | `50` | Commits read when the run has no pull request or push range. |
| `fail-on-findings` | `true` | `false` writes the summary without failing the step. |

Linux runners only (x64 or arm64), with Python 3.10 or later and Git, as on
GitHub's `ubuntu-latest`.

## Limits

The dump check is Sentinel's own, so it has the same limits as the Deep scan:

- In history it reads each version of the files the run's commits added or
  changed, merges included, until it finds a dump at that path.
- For a pull request it reads back from GitHub's merge commit far enough to
  take in every commit of the pull request, so it can also find a dump in a
  base branch commit made since the branch started.
- A compressed file it cannot open is listed as unread in the summary, not
  as a finding.
- If the check does not finish, the step fails and nothing is sent to
  Sentinel.
