# Private Drupal database images for CI

This example builds a MariaDB image containing a sanitised Drupal SQL dump. It is a starting point, not a general-purpose anonymiser. Every site must supply and test its own sanitisation and verification scripts. Never run those scripts against the production database itself. Prefer synthetic data when possible.

## Before you start

1. Create an empty, **private** GHCR container package named `drupal-db`, connect it to this application repository, and give its Actions workflow package access. The workflow refuses to push when it cannot confirm the package is private. A first-time package may need a harmless empty image pushed manually to establish it; check its visibility before use. Keep registry permissions limited: anyone who can pull the package can inspect its database layers.
2. Copy `db-image-refresh.yml` to `.github/workflows/db-image-refresh.yml`; copy `export-ssh.sh` to `.github/db-image/export.sh` and make it executable. Configure the remote command for your host and Drupal installation. It runs on the remote host and writes SQL to stdout; diagnostics must go to stderr. Confirm your host permits the export and the account can do nothing beyond what is required. Replace this adapter with your hosting provider's supported backup API when SSH/Drush is unavailable.
3. Set the repository variable `DB_EXPORT_SSH_TARGET` to the SSH user and hostname. Set Actions secrets `DB_EXPORT_SSH_KEY` and `DB_EXPORT_KNOWN_HOSTS` to a dedicated read-only key and a host key verified independently with the host provider. The example uses strict host-key checking; never use `ssh-keyscan` without independently verifying its fingerprint. Restrict who can modify and run the workflow and protect the default branch. Do not run it on untrusted pull requests.
4. Add executable `.github/db-image/sanitize.sh` and `.github/db-image/verify.sh`. The first receives `(raw.sql.gz, sanitized.sql.gz)` and must import the raw dump into a disposable, isolated database, run the project's reviewed sanitiser, then export a new gzip dump. The second receives the sanitized dump and must import it into a fresh disposable database, check that it boots and assert the organisation's privacy rules. Both must exit nonzero on failure; no example script can infer all sensitive fields.
5. Check the sanitiser and verifier against a representative **synthetic** fixture, including intentional failures. Review users and passwords, sessions, logs, webforms, custom entities, configuration secrets, tokens and backups. Drush `sql:sanitize` can help, but does not establish that every site's custom data is safe. Decide how to handle uploaded files separately; this example does not package files. Document access, retention, expiry, consent and incident response for production-derived data.
6. Set the MariaDB version in the workflow to match the source and consumer, preferably pin an audited digest. Validate restoration and application tests. Run manually first; enable the schedule after review.

The raw dump and SSH key live only in a temporary runner directory and are removed on normal success or failure. Use an ephemeral isolated runner; do not upload dumps as artifacts or caches, print contents, or expose them to untrusted workflows. Abrupt runner loss can prevent cleanup. The sanitised SQL is copied into the image, so privacy review is required even after sanitisation. The GHCR privacy check requires a token allowed to read package metadata and is not a substitute for governance or a guarantee against subsequent visibility changes.

## Consuming in CI or locally

Authenticate to GHCR with a token authorised to read this specific private package, then pull a reviewed immutable image digest. For example, after logging in with `docker login ghcr.io`:

```sh
# Replace the owner and digest and use a disposable password.
image='ghcr.io/OWNER/drupal-db@sha256:REPLACE_WITH_DIGEST'
docker run --rm --name drupal-db-example \
  -e MARIADB_DATABASE=drupal -e MARIADB_USER=drupal \
  -e MARIADB_PASSWORD=local-only -e MARIADB_ROOT_PASSWORD=local-only \
  "$image"
```

The official MariaDB entrypoint imports the compressed SQL only into a **new empty data directory**. The dump must target the configured database and be compatible with the selected server version. Existing volumes are not reinitialised; use a fresh disposable volume and never reuse a production volume. Connect the application to the database using its normal stack configuration, wait for readiness and run its tests. DDEV, Lando and Vortex each have their own database image/import configuration; adapt it rather than assuming a single Compose service name. Do not run production-derived images on untrusted pull requests or share them with unauthorised developers.

A local login generally needs a token with the appropriate GHCR package read permission. GitHub Actions can use `GITHUB_TOKEN` only where the package grants that repository access; other consumers need an appropriately scoped credential. Follow [GitHub's container registry documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

## Adapter contract

- `export.sh OUTPUT`: create a non-empty gzip SQL export; use `DB_SSH_KEY_FILE`, `DB_KNOWN_HOSTS_FILE` and `HOST_TARGET` if using the SSH example.
- `sanitize.sh INPUT OUTPUT`: produce a **new** gzip SQL file from an isolated imported copy, never modify the source database.
- `verify.sh INPUT`: restore the sanitised file independently and fail unless all site-specific safety and database checks pass.

Do not commit real databases, private keys, host names or customer-specific examples to this repository.
