# Private Drupal database images for CI

A manually triggered GitHub Actions example that exports a Drupal SQL database, sanitises a disposable copy, independently restores and checks the output, and builds a private GHCR image. Choose SSH, Platform.sh, Upsun or Quant Cloud as the source. These are examples that require project setup and review, not a guarantee that every site's data is safe.

## Set up the example

1. Copy `db-image-refresh.yml` to `.github/workflows/db-image-refresh.yml` and copy all of the example `*.sh` files into `.github/db-image/`. Make them executable (`chmod +x .github/db-image/*.sh`).
2. Create an empty, **private** GHCR package called `<repository>-drupal-db` (lowercase application repository name), connect it to that repository, and give its Actions workflow access. Use a separate package for each site. The workflow refuses to publish when it cannot prove the package is private. A new package may need a harmless empty image pushed manually first; check privacy before use. Anyone who can pull the image can inspect its layers.
3. Configure the source in **Settings → Secrets and variables → Actions**, as described below. Protect the workflow and default branch; do not execute it for untrusted pull requests. Tokens belong in **secrets**, not variables or committed files. Grant only the source permissions needed and restrict who can change workflows or read secret-bearing environments.
4. Implement and review `.github/db-image/site-sanitize.sh` and `site-verify.sh`. Both included files deliberately fail until replaced. They receive the name of a disposable local database container as their only argument. Run SQL inside it with `docker exec "$1" mariadb -uroot -ptemporary-local-only drupal ...`; never use a production connection. The verifier must exit nonzero when any site-specific sensitive data remains. Test both against representative synthetic data, including intentionally failing examples.
5. Review and match the `DB_IMAGE` in `db-lib.sh` and the image in the workflow to the source database version, preferably using a reviewed digest. Run manually with synthetic data first; enable the commented schedule only after an authorised end-to-end review. Configure hosting-specific network and authentication requirements before using production data.

## Choose a source and configure credentials

Set the Actions **variable** `DB_EXPORT_SOURCE` to exactly one of `ssh`, `platform`, `upsun` or `quant`. Only the selected source runs.

| Source | GitHub secrets | GitHub variables | Notes |
| --- | --- | --- | --- |
| SSH / Drush | `DB_EXPORT_SSH_KEY`, `DB_EXPORT_KNOWN_HOSTS` | `DB_EXPORT_SSH_TARGET` | Use a dedicated restricted account and independently verify host keys. Adapt the remote Drush command to the site's working directory. |
| Platform.sh | `PLATFORM_API_TOKEN` | `PLATFORM_PROJECT_ID`, `PLATFORM_ENVIRONMENT`, optional `PLATFORM_APPLICATION`, `PLATFORM_RELATIONSHIP` | The workflow maps the secret to `PLATFORMSH_CLI_TOKEN` for the official `platform` CLI. |
| Upsun | `UPSUN_API_TOKEN` | `PLATFORM_PROJECT_ID`, `PLATFORM_ENVIRONMENT`, optional `PLATFORM_APPLICATION`, `PLATFORM_RELATIONSHIP` | The workflow maps the secret to `UPSUN_CLI_TOKEN` for the official `upsun` CLI. For Upsun Fixed, use the Platform.sh-compatible CLI if that is what your project supports. |
| Quant Cloud | `QUANT_API_KEY`, `QUANT_ORGANIZATION` | `QUANT_APPLICATION`, `QUANT_ENVIRONMENT` | The official backup action creates a new database backup, waits for it and downloads the exact returned backup ID. The provider may retain that backup: apply its own retention and access policy. |

The Platform.sh and Upsun CLI installers run in CI before the provider token is passed to the export step. Review vendor installers and versions under your own supply-chain policy. Database access may also require provider-approved SSH certificates, host-key trust, network access and permissions; configure these according to your provider's documentation. Never use unchecked `ssh-keyscan` output as proof of a host key. The Platform.sh, Upsun and Quant integrations are not exercised against live services by this example's automated tests.

For an already authenticated operator, the Quant Cloud CLI can create and download a backup locally with explicit scope and a specific backup ID:

```sh
quant-cloud backup create --org ORGANISATION --app APPLICATION --env ENVIRONMENT --type database --description 'CI snapshot'
# Wait for this exact backup to be completed, then use its actual ID:
quant-cloud backup download BACKUP_ID --org ORGANISATION --app APPLICATION --env ENVIRONMENT --type database --output ./private-temp
```

Do not choose `latest`: it can refer to a different backup. The workflow uses the vendor's backup action for unattended API-key authentication and the exact-ID handoff rather than assuming that the CLI accepts a token environment variable. Protect and remove local downloads and follow the provider's backup retention policy.

## What the included sanitiser does

`sanitize.sh` imports a gzip SQL dump into an isolated MariaDB container with no network or exposed ports. It verifies that basic Drupal tables exist, blocks user accounts, replaces common user names, emails and password hashes, clears common cache/session/runtime tables, invokes your site-specific scrub, then writes a new gzip SQL dump. `verify.sh` restores that output into a **fresh** isolated database, checks the baseline rules, and invokes your site-specific verifier. Both remove their disposable containers and volumes on normal completion or failure.

Database import output and site-hook output are suppressed because failed SQL and diagnostic output can contain private values. A failed step reports a generic error; investigate with synthetic fixtures or in an approved private environment, not public CI logs. Never enable shell tracing around sensitive data.

This baseline is **not a complete sanitiser**. Drupal sites can store personal information or credentials in content, custom entities, webform submissions, comments, configuration, custom tables, logs, integrations and files. It does not cover those surfaces automatically. Inventory the entire site, scrub or remove every relevant surface, test assertions with intentionally unsafe fixtures, and obtain the data owner's review. Use synthetic data whenever possible. Uploaded files are not included or sanitised by this example. Never run a sanitiser or verifier against production.

The raw dump, provider SSH material and signed URLs are sensitive. Do not print or upload them as artifacts, caches or logs; use an isolated ephemeral runner. The temporary workspace is removed on normal success or failure, but a terminated runner can prevent cleanup. Provider backups may persist after the job. The sanitised SQL remains in image layers, so keep packages private and control retention and access. Review package visibility separately because it can be changed after the pre-push check.

## Consuming in CI or locally

Authenticate to GHCR with credentials authorised to read the private package. Pull the reviewed immutable image digest. For example, after `docker login ghcr.io`:

```sh
image='ghcr.io/OWNER/REPOSITORY-drupal-db@sha256:REPLACE_WITH_DIGEST'
docker run --rm --name drupal-db-example \
  -e MARIADB_DATABASE=drupal -e MARIADB_USER=drupal \
  -e MARIADB_PASSWORD=local-only -e MARIADB_ROOT_PASSWORD=local-only \
  "$image"
```

MariaDB imports the compressed SQL only when initialising a **new empty** data directory. Existing volumes keep their old contents; use a fresh disposable volume and never reuse a production volume. Connect your app using its normal stack settings, wait for the database, run your tests and remove the environment. Adapt the configuration to DDEV, Lando, Vortex or Compose. Do not expose the package to untrusted pull requests or unauthorised developers.

This example publishes to GHCR. A private registry such as Amazon ECR, Docker Hub, Azure Container Registry or Google Artifact Registry can be used after replacing and independently testing the login, permission, privacy check, image naming and push steps; do not assume the GHCR checks apply unchanged. Prefer short-lived scoped credentials where the provider supports them.

References: [GitHub Container Registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry), [Platform.sh CLI](https://docs.platform.sh/administration/cli/reference.html), [Upsun CI setup](https://support.platform.sh/hc/en-us/articles/33580745610258-How-to-setup-Github-actions-to-work-with-Platform-sh-environments) and [Drush sanitise](https://www.drush.org/latest/commands/sql_sanitize/).
