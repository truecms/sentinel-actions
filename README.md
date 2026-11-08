# Sentinel actions

CI actions and templates for [Sentinel](https://sentinelconnector.io), for
GitHub Actions and GitLab CI. Each runs in your own pipeline and your own site
image, and sends Sentinel only what that check needs.

| Action | What it does | GitHub Actions | GitLab CI |
|---|---|---|---|
| [Upgrade scan](upgrade-scan) | Drupal upgrade readiness from Upgrade Status, without installing it on production. | `truecms/sentinel-actions/upgrade-scan@v1.0.0` | `upgrade-scan/gitlab.yml` |

Each action folder has:

- the GitHub action (`action.yml`) and the GitLab template (`gitlab.yml`),
- `examples/` with a complete GitHub workflow and GitLab job,
- `prompts/` with an AI prompt you paste into your coding assistant, opened in
  your repository, to add the job for you.

## Pin a release

Releases cover the whole repository: `v1.0.0`, `v1.1.0` and so on. Use a tag
you have reviewed, or a full commit SHA:

```yaml
- uses: truecms/sentinel-actions/upgrade-scan@<full commit SHA>
```

GitLab templates download their script from the same tag and check its
SHA-256 before they run it.

## Secrets

Every credential goes into a CI secret (GitHub repository secret, or a masked
and protected GitLab CI/CD variable). Never write one into a file, a commit or
an AI chat. The actions never print them.

## Development

```bash
shellcheck scripts/*.sh */scan.sh tests/*/stubs/*
bats tests/*/*.bats
```

To release: run `scripts/pin-release.sh vX.Y.Z`, commit, then tag `vX.Y.Z`.

## Licence

MIT. See [LICENSE](LICENSE). Report security problems as described in
[SECURITY.md](SECURITY.md).
