# Releasing Nostrfi Relay

A release is two things in this repository:

1. a **milestone** named after the version (`0.1.0`, never `v0.1.0`), which holds the release's
   scope; and
2. a **release PR** titled `chore(release): <version>`, which
   [release-please](https://github.com/googleapis/release-please) opens and keeps up to date on
   every push to `master`.

Merging the release PR is the release. Nothing else creates a `v*` tag, and nobody pushes one by
hand.

## Version authority

The release PR decides the version, from the Conventional Commits merged since the last release.
release-please owns these files; never edit them by hand:

| File | What it holds |
| --- | --- |
| `.release-please-manifest.json` | The last released version |
| `version.txt` | The current version (the release build checks it against the tag) |
| `CHANGELOG.md` | The changelog, one section per release |

Builds get their version from the tag. A CI run on a `v1.2.3` tag builds `1.2.3` into the binary
(the NIP-11 `version` field) and the image labels. Every other run is a development build,
versioned `dev-<shortsha>`.

## Commits

This repository squash-merges, so **the PR title is the commit** and must be a
[Conventional Commit](https://www.conventionalcommits.org/):

| Type | Changelog | Version effect |
| --- | --- | --- |
| `feat` | Features | minor |
| `fix` | Bug Fixes | patch |
| `perf` | Performance Improvements | patch |
| `revert` | Reverts | patch |
| `docs`, `chore`, `refactor`, `test`, `build`, `ci` | hidden | none |
| `!` after the type, or a `BREAKING CHANGE:` footer | Breaking Changes | major (minor while `0.x`) |

Put the issue in the title, `(#123)`, so the changelog links to it. To fix a merged commit's
message, edit **the merged PR's body**, not the release PR:

```text
BEGIN_COMMIT_OVERRIDE
fix(search): the corrected message
END_COMMIT_OVERRIDE
```

## Forcing a version

Merge a commit with a `Release-As: 1.0.0` footer. The setup commit used `Release-As: 0.1.0` for
the first release.

## Milestones

| Item | Milestone |
| --- | --- |
| Issue scoped into the release | The version's milestone |
| PR that fixes an issue | Same milestone as the issue |
| `feat`/`fix`/`perf` PR with no issue | The open release PR's version |
| `docs`/`ci`/`chore`/`test`/`refactor` PR | None needed |
| The release PR | The version's milestone |

If release-please computes a different version from the milestone, rename the milestone or force
the planned version before merging. An issue that will miss the release moves to the next
milestone first.

## Release checklist

1. Every issue in the milestone is closed or moved on.
2. Get CI to run on the release PR. release-please opens it with `GITHUB_TOKEN`, which starts no
   workflows: close and reopen the PR, or push an empty commit to its branch.
3. Review the version, `version.txt`, and the `CHANGELOG.md` section.
4. Approve and merge. Whoever merges owns the release.

## What happens after the merge

The `Release` workflow (`.github/workflows/release.yml`):

1. creates the `v<version>` tag and a **draft** GitHub release, and relabels the PR
   `autorelease: tagged`;
2. closes the milestone named after the version (a missing milestone is only a notice);
3. builds `relay-linux-amd64.tar.gz` from the tag, after checking `version.txt` matches it;
4. starts the CI workflow on the tag and waits for it to finish. CI pushes both images as
   `<version>` and `sha-<shortsha>`, and moves `<major.minor>` and `latest` only if this is the
   newest release in that line (a rebuild of an older release never moves them back);
5. attaches the archive (after checking its SHA-256) and publishes the release as latest, but
   only once the binary and the images have both succeeded.

If a step fails, the release stays a draft that only maintainers see.

## Retrying a failed release

Fix the cause, then re-run the failed jobs, or run the `Release` workflow by hand
(**Actions → Release → Run workflow**) with the tag, for example `v0.1.0`:

- **binary**: build, attach, and publish. Only acts while the release is still a draft; a
  published release is left as it is.
- **images**: rebuild and push the container images for the tag.

**Never delete and recreate a released tag.**

## Hotfixes

Fix on a `fix/` branch from `master` and merge. release-please adds the fix to the open release PR,
or opens one.

The release PR always takes the largest change since the last release. If unreleased `feat`
commits are already on `master`, the release stays a minor release and ships those features with
the fix; a `fix` does not turn it into a patch release. To ship only the fix in that case, ask the
owner first: it needs a release branch cut from the last release tag, which is an exception to
this process.

## Secrets

None beyond the default `GITHUB_TOKEN`. Repository setting **Actions → General → Allow GitHub
Actions to create and approve pull requests** must stay on.
