# Release documentation automation

`update-release-docs.yml` runs when a Tempo node release is published. It opens
a draft PR against `tempoxyz/docs` with a dated row in the Node Operator Updates
table. The PR includes the release notes and asks a maintainer to confirm network
applicability, summarize operator impact, and classify priority before merging.
The node release notes page already reads GitHub releases; merging the PR also
triggers a docs rebuild.

Merge the companion `.github/sts/tempo-releases.sts.yaml` policy in `tempoxyz/docs`
before enabling the workflow. The Tempo GitHub STS app must have access to `docs`
with contents and pull-request write permissions. No stored token is needed.

The workflow skips package and Zones tags, includes node prereleases, and uses one
branch per tag. Reruns skip existing PRs, including closed PRs, and existing table
entries. If a run stopped after creating a branch, a rerun preserves edits there
and finishes opening the PR.

To backfill a published release, run **Update release docs** from `main` with its
tag, such as `v1.16.1`. Publishing with a workflow's `GITHUB_TOKEN` does not trigger
another workflow; use an app token for publication or run this manual backfill.

Run the helper tests with:

```sh
node --test .github/scripts/update-release-docs.test.js
```
