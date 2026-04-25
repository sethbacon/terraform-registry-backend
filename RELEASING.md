# Releasing

Releases are fully automated via `release-please.yml` and `release.yml`.

## How it works

1. **Developers merge PRs to `main`** with Conventional Commit titles (`feat:`, `fix:`, etc.).

2. **release-please maintains an open release PR** titled `chore(main): release X.Y.Z`.
   - It accumulates `CHANGELOG.md` entries from merged PR titles.
   - It bumps the version in `deployments/helm/Chart.yaml` (`appVersion` + `version`).
   - `feat:` → minor bump, `fix:` / `perf:` / `security:` → patch bump, `feat!:` or `BREAKING CHANGE:` → major bump.
   - The PR auto-updates as more commits land on `main`. Review it at any time to preview what will ship.

3. **When ready to release**, review and squash-merge the release-please PR. That is the only required human action.

4. **release-please pushes a `v*.*.*` tag** using the `terraform-registry-release-bot` GitHub App token (this bypasses the `GITHUB_TOKEN` downstream-trigger restriction).

5. **`release.yml` fires automatically** from the tag push. It:
   - Runs CI as a gate.
   - Builds multi-platform Go binaries via GoReleaser.
   - Signs checksum files with cosign (keyless, Sigstore).
   - Pushes Docker image to `ghcr.io` (tagged with version + latest).
   - Attaches SLSA Level 3 provenance to both binaries and the container image.
   - Creates the GitHub Release with all assets attached atomically.
   - Updates the wiki Home page version badge.

## Cutting a release

1. Find the open release-please PR (`chore(main): release X.Y.Z`) in the PR list.
2. Review the CHANGELOG entries and version bump — adjust by merging additional `fix:` or `feat:` commits if needed.
3. Squash-merge the release PR.
4. Watch `release.yml` run in the Actions tab. No manual dispatch required.

## Hotfix flow

1. Create a `fix/` branch from `main`.
2. Merge the fix PR with a `fix: ...` Conventional Commit title.
3. release-please updates the open release PR with the patch bump.
4. Merge the release PR to ship.

## Manual fallback

If `release-please.yml` fails or the App token is unavailable:

```bash
# Create the release commit manually
git checkout main
git pull

# Edit version in deployments/helm/Chart.yaml (appVersion + version)
# Edit CHANGELOG.md with the new section

git add deployments/helm/Chart.yaml CHANGELOG.md
git commit -m "chore: release vX.Y.Z"
git push origin main

git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

`release.yml` fires from the tag push automatically (provided the tag is reachable from `main`).

## GitHub App key rotation

The `terraform-registry-release-bot` App private key is stored as `RELEASE_DISPATCH_APP_KEY` in repository secrets. The Client ID is stored as `RELEASE_DISPATCH_APP_ID` in repository variables.

To rotate the key:
1. Go to GitHub → Settings → Developer settings → GitHub Apps → `terraform-registry-release-bot` → Private keys.
2. Generate a new key and download it.
3. Update `RELEASE_DISPATCH_APP_KEY` in repository secrets with the new key content.
4. Delete the old private key from the App settings.

## Rollback procedure

To undo a release after the tag has been pushed:

```bash
# Revert the release commit on main
git revert HEAD --no-edit   # or the specific release commit SHA
git push origin main
```

release-please will propose a new release PR on the next `main` push. The already-published GitHub Release and Docker image can be deleted manually from the GitHub Releases page and `ghcr.io` if necessary.

## Deployment config bump (after release)

These files reference specific image tags and are updated manually after each release:

**Helm chart** (in `deployments/helm/`):
- `Chart.yaml` — release-please auto-bumps `appVersion` and `version` on release.
- `values.yaml` — update `frontend.image.tag` when releasing a new frontend version.
- `values-aks.yaml`, `values-eks.yaml`, `values-gke.yaml` — update `backend.image.tag` and/or `frontend.image.tag`.

**Kustomize overlays** (in `deployments/kubernetes/overlays/`):
- `eks/kustomization.yaml` — update `newTag` for backend and/or frontend.
- `gke/kustomization.yaml` — update `newTag` for backend and/or frontend.
