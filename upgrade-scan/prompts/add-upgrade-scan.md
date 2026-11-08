# AI prompt: add the Sentinel upgrade scan to this repository

Copy everything below the line into your AI coding assistant (Claude Code,
Codex, Copilot or similar), opened in your Drupal site's repository. Replace
the Site UUID first. Never paste your scan key into the chat.

---

Add the Sentinel upgrade scan to this Drupal repository's CI. It runs the
Drupal Upgrade Status scan in our own CI and sends only counts to Sentinel.
The instructions and examples are in
https://github.com/truecms/sentinel-actions/tree/v1.0.0/upgrade-scan
(read the README there first).

Site UUID: REPLACE_WITH_SITE_UUID

Do this:

1. Work out where this repository runs CI: GitHub Actions (`.github/workflows/`)
   or GitLab CI (`.gitlab-ci.yml`). If both or neither, ask me.
2. Find how CI already builds and runs this site: the image it uses, where the
   site lives inside it (for example `/app`), and how tests get a database. Reuse
   that. The scan needs our own site image with PHP, Composer, Drush, bash and
   curl, and a database copy that is sanitised and thrown away after the job.
   If CI has no database for the site, tell me. Do not invent one or point at
   any real database.
3. Check `composer.lock` has `drupal/sentinel_connector` at 1.6.0 or later. If
   it is older, tell me; do not upgrade it as part of this change.
4. Add one new job, copied from the matching example in that folder:
   - GitHub: a new workflow file, using
     `truecms/sentinel-actions/upgrade-scan@v1.0.0`, `site-uuid` set to the UUID
     above and `scan-key: ${{ secrets.SENTINEL_SCAN_KEY }}`.
   - GitLab: include `upgrade-scan/gitlab.yml` at `v1.0.0` and a
     `sentinel-upgrade-scan` job with our image, the database service,
     `SENTINEL_UPGRADE_SCAN: '1'` and `SENTINEL_SITE_UUID`.
   - Run it on a weekly schedule and by hand only, never on every push.
   - Set the working directory if the site is not at the job's start folder.
   - Set `SENTINEL_UPGRADE_SCAN` only in this job, never globally.
5. Never write the scan key into any file, commit, log or message. It goes
   only into a CI secret named `SENTINEL_SCAN_KEY` (GitHub: repository secret;
   GitLab: masked and protected CI/CD variable), which I will add myself.
6. Do not change other jobs, `composer.json`, `composer.lock` or Drupal
   configuration.
7. Open the change as a branch and pull or merge request. In its description,
   list what I must do: add the `SENTINEL_SCAN_KEY` secret (create the key on
   the site page in Sentinel), add a GitLab pipeline schedule if on GitLab, and
   run the job once by hand to check it.

When you finish, tell me what you added and anything you could not settle.
