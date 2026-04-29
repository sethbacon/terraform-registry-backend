# Backend ↔ Frontend Compatibility

The backend and frontend are released as a matched pair. Image tags
shipped in this repo's helm charts and kustomize overlays always pin
to a tested combination of versions.

## Versioning policy

- **Major and minor versions track together.** A backend at `X.Y.*`
  is expected to work with any frontend at `X.Y.*`. Patch versions
  on either side are independently releasable; minor and major bumps
  on either side are coordinated.
- Mixing across minors (e.g. backend `0.15.x` with frontend `0.16.x`)
  is **not supported** and may produce undefined behavior — the API
  contract is allowed to evolve in any minor release.
- The compatibility matrix below records the canonical pair shipped
  in each release. When this file is updated, the corresponding helm
  values and kustomize overlays are updated in the same commit.

## Compatibility matrix

| Release line | Backend image tag | Frontend image tag | Notes                                                               |
| ------------ | ----------------- | ------------------ | ------------------------------------------------------------------- |
| `0.18.x`     | `v0.18.2`         | `v0.18.2`          | Current stable: CVE polling, scanner improvements, migration fixes. |
| `0.15.x`     | `v0.15.0`         | `v0.15.1`          | First aligned release. Frontend includes i18n updates. (historical) |

## Where versions live

- `deployments/helm/values.yaml` — default chart `frontend.image.tag`.
- `deployments/helm/values-aks.yaml`, `values-eks.yaml`, `values-gke.yaml` —
  cloud-specific overlays pin both `backend.image.tag` and `frontend.image.tag`.
- `deployments/kubernetes/overlays/eks/kustomization.yaml`,
  `gke/kustomization.yaml` — kustomize image transformers pin both tags.

## Updating a release

1. Cut the backend release via the normal release-please flow.
2. Cut the frontend release via its own release-please flow
   (in the [terraform-registry-frontend](https://github.com/sethbacon/terraform-registry-frontend) repo).
3. Open a PR in this repo bumping the helm + kustomize tags to the
   new pair, and add a row to the matrix above.
