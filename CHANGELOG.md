<!-- markdownlint-disable MD013 MD024 MD041 -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1](https://github.com/sethbacon/terraform-registry-backend/compare/v2.0.0...v2.0.1) (2026-06-06)


### Bug Fixes

* **deps:** bump terraform-suite-identity to v0.11.2 ([#454](https://github.com/sethbacon/terraform-registry-backend/issues/454)) ([b50fde2](https://github.com/sethbacon/terraform-registry-backend/commit/b50fde2ddb4051a66efc073449f29a4c14f239d3))

## [2.0.0](https://github.com/sethbacon/terraform-registry-backend/compare/v1.5.0...v2.0.0) (2026-06-06)


### ⚠ BREAKING CHANGES

* **deps:** Cutover deployments have their feature-table FK targets changed from public.{users,organizations} to identity.{users,organizations}. This drops and recreates 22 constraints. Non-cutover deployments are unaffected (migration is a no-op).
* Cutover deployments have their feature-table FK targets changed from public.{users,organizations} to identity.{users,organizations}. This drops and recreates 22 constraints. Non-cutover deployments are unaffected (migration is a no-op).

### Features

* repoint feature-table FKs to the identity schema ([#451](https://github.com/sethbacon/terraform-registry-backend/issues/451)) ([206e2b3](https://github.com/sethbacon/terraform-registry-backend/commit/206e2b3dc0c0e23268855ac5e86c63861261ee91))


### Bug Fixes

* **deps:** bump terraform-suite-identity to v0.11.1 ([#453](https://github.com/sethbacon/terraform-registry-backend/issues/453)) ([b886093](https://github.com/sethbacon/terraform-registry-backend/commit/b8860937bb29fe4151e9ed41e3e65bdf519925e9))

## [1.5.0](https://github.com/sethbacon/terraform-registry-backend/compare/v1.4.2...v1.5.0) (2026-06-06)


### Features

* **identity:** identity-schema cutover behind a flag ([#448](https://github.com/sethbacon/terraform-registry-backend/issues/448)) ([5edf015](https://github.com/sethbacon/terraform-registry-backend/commit/5edf01534d56b8c6469a6a520af88ccfeae642aa))
* integrate shared identity migrations (feature-flagged) ([#439](https://github.com/sethbacon/terraform-registry-backend/issues/439)) ([6258902](https://github.com/sethbacon/terraform-registry-backend/commit/6258902f16c6ae5dc9cad8ce1a46579372fa0fb2)), closes [#438](https://github.com/sethbacon/terraform-registry-backend/issues/438)


### Documentation

* document the shared identity schema and clean up redundant tests ([#449](https://github.com/sethbacon/terraform-registry-backend/issues/449)) ([18d8a10](https://github.com/sethbacon/terraform-registry-backend/commit/18d8a1025e0f0f3440618f5738a6a9f2fd79e222))


### Refactor

* **auth:** delegate API key gen/validation to the identity module ([#443](https://github.com/sethbacon/terraform-registry-backend/issues/443)) ([4cb4012](https://github.com/sethbacon/terraform-registry-backend/commit/4cb4012411dac2ad447bbff6c6996036bd3202e1))
* **auth:** delegate JWT to the identity TokenManager ([#445](https://github.com/sethbacon/terraform-registry-backend/issues/445)) ([ea247cb](https://github.com/sethbacon/terraform-registry-backend/commit/ea247cbeba362501059c92fd29c1b18c2783a747))
* **auth:** delegate OIDC provider to the identity module ([#446](https://github.com/sethbacon/terraform-registry-backend/issues/446)) ([4cb2751](https://github.com/sethbacon/terraform-registry-backend/commit/4cb2751ebd4cb5edb5d953cc537c909a6f02689a))
* **auth:** delegate scope-checking to the identity module ([#442](https://github.com/sethbacon/terraform-registry-backend/issues/442)) ([441c996](https://github.com/sethbacon/terraform-registry-backend/commit/441c9961fb12c2331e79e0eb6919bb19233ab043))
* **identity:** delegate the identity data layer to the shared module ([#447](https://github.com/sethbacon/terraform-registry-backend/issues/447)) ([b5a6a6f](https://github.com/sethbacon/terraform-registry-backend/commit/b5a6a6f8af8fe14d0c9246b715a81817d6882d72))

## [1.4.2](https://github.com/sethbacon/terraform-registry-backend/compare/v1.4.1...v1.4.2) (2026-05-30)


### Bug Fixes

* **mirror:** persist requires_approval and auto_approve_rules from API ([#436](https://github.com/sethbacon/terraform-registry-backend/issues/436)) ([3ac4d4d](https://github.com/sethbacon/terraform-registry-backend/commit/3ac4d4df42bb1ef375efbb418540761c4303fc2b))

## [1.4.1](https://github.com/sethbacon/terraform-registry-backend/compare/v1.4.0...v1.4.1) (2026-05-30)


### Bug Fixes

* **docs:** add version-approval troubleshooting sections ([#434](https://github.com/sethbacon/terraform-registry-backend/issues/434)) ([047c8f0](https://github.com/sethbacon/terraform-registry-backend/commit/047c8f0e0388d3de64d0fb45b714e82f4d8d6d60))

## [1.4.0](https://github.com/sethbacon/terraform-registry-backend/compare/v1.3.4...v1.4.0) (2026-05-29)


### Features

* **api-test:** report live-spec endpoint coverage ([#433](https://github.com/sethbacon/terraform-registry-backend/issues/433)) ([d47c1b3](https://github.com/sethbacon/terraform-registry-backend/commit/d47c1b3c4c1a0ede6a65477f2682a76109c69d7a))
* **mirror:** version approval gate for provider and terraform mirrors ([#431](https://github.com/sethbacon/terraform-registry-backend/issues/431)) ([4223c4b](https://github.com/sethbacon/terraform-registry-backend/commit/4223c4b3f9f6a44789df0c2f97f331be05a3cc50))

## [1.3.4](https://github.com/sethbacon/terraform-registry-backend/compare/v1.3.3...v1.3.4) (2026-05-29)


### Bug Fixes

* **mirror:** run gpg_verified backfill independently of key backfill ([#429](https://github.com/sethbacon/terraform-registry-backend/issues/429)) ([626b5d5](https://github.com/sethbacon/terraform-registry-backend/commit/626b5d5ca47bb224eb17a7c69a96bbea26a34d3a))

## [1.3.3](https://github.com/sethbacon/terraform-registry-backend/compare/v1.3.2...v1.3.3) (2026-05-29)


### Bug Fixes

* **mirror:** resolve expired GPG keys for verification and backfill gpg_verified ([#427](https://github.com/sethbacon/terraform-registry-backend/issues/427)) ([2dea4af](https://github.com/sethbacon/terraform-registry-backend/commit/2dea4af19365fc3f39c897a201195d6f43d211fb))

## [1.3.2](https://github.com/sethbacon/terraform-registry-backend/compare/v1.3.1...v1.3.2) (2026-05-29)


### Bug Fixes

* **mirror:** backfill GPG key for existing provider versions on re-sync ([#425](https://github.com/sethbacon/terraform-registry-backend/issues/425)) ([57fcb4f](https://github.com/sethbacon/terraform-registry-backend/commit/57fcb4f1eaf0c11a061b16da1655530bebec6695))

## [1.3.1](https://github.com/sethbacon/terraform-registry-backend/compare/v1.3.0...v1.3.1) (2026-05-28)


### Bug Fixes

* **mirror:** substitute expired GPG key in provider download responses ([#423](https://github.com/sethbacon/terraform-registry-backend/issues/423)) ([4981d91](https://github.com/sethbacon/terraform-registry-backend/commit/4981d9149e1fbac9eacb57d57b268d03909039b6))

## [1.3.0](https://github.com/sethbacon/terraform-registry-backend/compare/v1.2.6...v1.3.0) (2026-05-28)


### Features

* **mirror:** auto-refresh release signing keys with pre-expiry warning ([#419](https://github.com/sethbacon/terraform-registry-backend/issues/419)) ([0cda46f](https://github.com/sethbacon/terraform-registry-backend/commit/0cda46fc80f41f9576123b27c34813788031f9e5)), closes [#418](https://github.com/sethbacon/terraform-registry-backend/issues/418)

## [1.2.6](https://github.com/sethbacon/terraform-registry-backend/compare/v1.2.5...v1.2.6) (2026-05-28)


### Bug Fixes

* **mirror:** refresh expired HashiCorp Releases GPG key snapshot ([#416](https://github.com/sethbacon/terraform-registry-backend/issues/416)) ([1fc2071](https://github.com/sethbacon/terraform-registry-backend/commit/1fc2071834e9e1c49420c04f00e124d571b0b93b)), closes [#415](https://github.com/sethbacon/terraform-registry-backend/issues/415)

## [1.2.5](https://github.com/sethbacon/terraform-registry-backend/compare/v1.2.4...v1.2.5) (2026-05-28)


### Bug Fixes

* **ci:** add --output-bundle for cosign v3 compatibility ([#412](https://github.com/sethbacon/terraform-registry-backend/issues/412)) ([7b7e6b1](https://github.com/sethbacon/terraform-registry-backend/commit/7b7e6b12c9683a1ac80cd91c5e90334f0c560501))
* **ci:** upgrade all GitHub Actions to Node 24 and latest versions ([#408](https://github.com/sethbacon/terraform-registry-backend/issues/408)) ([5713664](https://github.com/sethbacon/terraform-registry-backend/commit/5713664d135ad7ad4d844c285ea2a96924a20dc0))
* **ci:** use cosign v3 --bundle flag for sign-blob ([#413](https://github.com/sethbacon/terraform-registry-backend/issues/413)) ([a9ace6c](https://github.com/sethbacon/terraform-registry-backend/commit/a9ace6c84675973d7e2a41ff39016d926999115a))
* provider upload signature ([#406](https://github.com/sethbacon/terraform-registry-backend/issues/406)) ([ef974ec](https://github.com/sethbacon/terraform-registry-backend/commit/ef974ecefd9885f94c4b89fd3e3be0e19ad193f2))
* **providers:** accept SHA256SUMS + signature files on upload ([#405](https://github.com/sethbacon/terraform-registry-backend/issues/405)) ([5d18fd0](https://github.com/sethbacon/terraform-registry-backend/commit/5d18fd08ed4e1af52e2ee93e477b61fd024557ff))
* **terraform-binaries:** persist and serve SHA256SUMS + GPG signature ([#403](https://github.com/sethbacon/terraform-registry-backend/issues/403)) ([0c3de84](https://github.com/sethbacon/terraform-registry-backend/commit/0c3de848ac659b77890563c35fdaaa0119189094))
* **webhooks:** look up SCM link by id, not module_id ([#410](https://github.com/sethbacon/terraform-registry-backend/issues/410)) ([e46b687](https://github.com/sethbacon/terraform-registry-backend/commit/e46b68768db88200488109b516140fb0c005be78)), closes [#409](https://github.com/sethbacon/terraform-registry-backend/issues/409)

## [1.2.4](https://github.com/sethbacon/terraform-registry-backend/compare/v1.2.3...v1.2.4) (2026-05-26)


### Bug Fixes

* **ci:** SHA-pin actions, bump backend dependencies, harden archiver path check ([#399](https://github.com/sethbacon/terraform-registry-backend/issues/399)) ([c2d2dd5](https://github.com/sethbacon/terraform-registry-backend/commit/c2d2dd5efb67505767e31dc94372668c522dbb31))

## [1.2.3](https://github.com/sethbacon/terraform-registry-backend/compare/v1.2.2...v1.2.3) (2026-05-22)


### Bug Fixes

* **security:** enforce scanner Tool allowlist on save and startup-reload paths ([#395](https://github.com/sethbacon/terraform-registry-backend/issues/395)) ([7ace7fd](https://github.com/sethbacon/terraform-registry-backend/commit/7ace7fd91ed5e233584de0044792037d77a08744))

## [1.2.2](https://github.com/sethbacon/terraform-registry-backend/compare/v1.2.1...v1.2.2) (2026-05-22)


### Bug Fixes

* **archiver:** enforce cumulative 100 MB extraction limit; remove dead IsAbs branch ([#389](https://github.com/sethbacon/terraform-registry-backend/issues/389)) ([bb3946c](https://github.com/sethbacon/terraform-registry-backend/commit/bb3946ced48e66b477beeadaf576efb4f6dc1e74)), closes [#390](https://github.com/sethbacon/terraform-registry-backend/issues/390)
* **jobs:** handle uuid.Parse error in mirror_sync; fix N+1 ListVersions query ([#391](https://github.com/sethbacon/terraform-registry-backend/issues/391)) ([999ac07](https://github.com/sethbacon/terraform-registry-backend/commit/999ac07e28f852e10654399671a156a533e478f6))
* **jobs:** reset started flag and reinitialize stopChan on scanner lifecycle ([#388](https://github.com/sethbacon/terraform-registry-backend/issues/388)) ([43a9cd5](https://github.com/sethbacon/terraform-registry-backend/commit/43a9cd52944a467270e6caec239bbc517aafd847))

## [1.2.1](https://github.com/sethbacon/terraform-registry-backend/compare/v1.2.0...v1.2.1) (2026-05-21)


### Bug Fixes

* **swagger:** clarify dual-mount auth on PUT ui-theme endpoint ([#379](https://github.com/sethbacon/terraform-registry-backend/issues/379)) ([a614953](https://github.com/sethbacon/terraform-registry-backend/commit/a61495339db75430cb46a4fba9a0c44963af0a6f))


### Documentation

* **swagger:** document PUT /api/v1/setup/ui-theme alongside the admin variant ([#378](https://github.com/sethbacon/terraform-registry-backend/issues/378)) ([f79dfbb](https://github.com/sethbacon/terraform-registry-backend/commit/f79dfbb428889e33dd73e80329021e5920a0d9e4))

## [1.2.0](https://github.com/sethbacon/terraform-registry-backend/compare/v1.1.10...v1.2.0) (2026-05-19)


### Features

* **api:** per-org quotas dashboard endpoint (roadmap D3.4 recovery) ([#355](https://github.com/sethbacon/terraform-registry-backend/issues/355)) ([#376](https://github.com/sethbacon/terraform-registry-backend/issues/376)) ([5d38653](https://github.com/sethbacon/terraform-registry-backend/commit/5d386533e2ff292c8214ab8cfcad23aca52ec191))
* **api:** UI theme config endpoints (roadmap G5.1 recovery) ([#356](https://github.com/sethbacon/terraform-registry-backend/issues/356)) ([#375](https://github.com/sethbacon/terraform-registry-backend/issues/375)) ([7e273b1](https://github.com/sethbacon/terraform-registry-backend/commit/7e273b1e4aaace7e332c504554b414be09b8cc9f))

## [1.1.10](https://github.com/sethbacon/terraform-registry-backend/compare/v1.1.9...v1.1.10) (2026-05-18)


### Bug Fixes

* **api:** validate module namespace/name/system against Terraform segment rules ([#365](https://github.com/sethbacon/terraform-registry-backend/issues/365)) ([#372](https://github.com/sethbacon/terraform-registry-backend/issues/372)) ([42b2c85](https://github.com/sethbacon/terraform-registry-backend/commit/42b2c859ec4d58006f2e5ac4cf9dcd1c750e601e))
* **deps:** bump go to 1.26.3 and golang.org/x/net to v0.54.0 ([#358](https://github.com/sethbacon/terraform-registry-backend/issues/358)) ([#374](https://github.com/sethbacon/terraform-registry-backend/issues/374)) ([d8e6c85](https://github.com/sethbacon/terraform-registry-backend/commit/d8e6c854c30c5187d33239b1982fdf44a64026f1))

## [1.1.9](https://github.com/sethbacon/terraform-registry-backend/compare/v1.1.8...v1.1.9) (2026-05-16)


### Bug Fixes

* persist SHA256 from SUMS file to terraform_version_platforms ([#368](https://github.com/sethbacon/terraform-registry-backend/issues/368)) ([#369](https://github.com/sethbacon/terraform-registry-backend/issues/369)) ([e016196](https://github.com/sethbacon/terraform-registry-backend/commit/e016196bdce7b63d3b8a15b641901246aadab8a5))

## [1.1.8](https://github.com/sethbacon/terraform-registry-backend/compare/v1.1.7...v1.1.8) (2026-05-12)


### Bug Fixes

* support org rename with cascade to modules and providers ([e9f8de4](https://github.com/sethbacon/terraform-registry-backend/commit/e9f8de45586a129ac7e826fe760173adf3713835)), closes [#364](https://github.com/sethbacon/terraform-registry-backend/issues/364)

## [1.1.7](https://github.com/sethbacon/terraform-registry-backend/compare/v1.1.6...v1.1.7) (2026-05-11)


### Bug Fixes

* **swagger:** correct spec for strict OpenAPI 3 validators ([#362](https://github.com/sethbacon/terraform-registry-backend/issues/362)) ([f772779](https://github.com/sethbacon/terraform-registry-backend/commit/f772779251064ba32dfd13826ad11bc340c18e3c))

## [1.1.6](https://github.com/sethbacon/terraform-registry-backend/compare/v1.1.5...v1.1.6) (2026-05-08)


### Bug Fixes

* **swagger:** dedupe identical type definitions via [@name](https://github.com/name) overrides ([#354](https://github.com/sethbacon/terraform-registry-backend/issues/354)) ([e764298](https://github.com/sethbacon/terraform-registry-backend/commit/e7642980cbca52891d563566d0084e6986aae6d2))

## [1.1.5](https://github.com/sethbacon/terraform-registry-backend/compare/v1.1.4...v1.1.5) (2026-05-08)


### Bug Fixes

* **swagger:** emit OpenAPI 3 alongside Swagger 2.0 ([#352](https://github.com/sethbacon/terraform-registry-backend/issues/352)) ([79c1aab](https://github.com/sethbacon/terraform-registry-backend/commit/79c1aab8035a3dda14554d1f5116102f65a89534))

## [1.1.4](https://github.com/sethbacon/terraform-registry-backend/compare/v1.1.3...v1.1.4) (2026-05-08)


### Bug Fixes

* **api:** wire up GDPR user export/erase handlers (roadmap C3.4 recovery) ([#350](https://github.com/sethbacon/terraform-registry-backend/issues/350)) ([9492e00](https://github.com/sethbacon/terraform-registry-backend/commit/9492e00f3754c52335d882cde0ced50078cb901d))

## [1.1.3](https://github.com/sethbacon/terraform-registry-backend/compare/v1.1.2...v1.1.3) (2026-05-07)


### Bug Fixes

* **swagger:** correct @Router annotations on 4 mis-documented routes ([#348](https://github.com/sethbacon/terraform-registry-backend/issues/348)) ([d38bb0a](https://github.com/sethbacon/terraform-registry-backend/commit/d38bb0ac557837fd26b0595faab1437e9bb1ea7d))

## [1.1.2](https://github.com/sethbacon/terraform-registry-backend/compare/v1.1.1...v1.1.2) (2026-05-07)


### Bug Fixes

* **api:** terraform-mirror version deprecate/undeprecate endpoints ([#345](https://github.com/sethbacon/terraform-registry-backend/issues/345)) ([5a8c003](https://github.com/sethbacon/terraform-registry-backend/commit/5a8c00364659821764cfb3126b4dfc16450137b1))

## [1.1.1](https://github.com/sethbacon/terraform-registry-backend/compare/v1.1.0...v1.1.1) (2026-05-07)


### Bug Fixes

* **api:** add status filter and pagination to scanning stats endpoint ([#340](https://github.com/sethbacon/terraform-registry-backend/issues/340)) ([ed2b4b0](https://github.com/sethbacon/terraform-registry-backend/commit/ed2b4b0c4dae86a6576962ec6051a845a4bbf372))
* **api:** allow namespace update in PUT /api/v1/admin/modules/{id} ([#341](https://github.com/sethbacon/terraform-registry-backend/issues/341)) ([7901c81](https://github.com/sethbacon/terraform-registry-backend/commit/7901c81a6f0ad43752678e79073e49ca2cffdcc6))

## [1.1.0](https://github.com/sethbacon/terraform-registry-backend/compare/v1.0.5...v1.1.0) (2026-05-06)


### Features

* **api:** add GET /api/v1/modules/{namespace}/{name}/{system}/{version} ([#335](https://github.com/sethbacon/terraform-registry-backend/issues/335)) ([01323f2](https://github.com/sethbacon/terraform-registry-backend/commit/01323f2661d090611d9f8fd818de9ba97ea98dd2))

## [1.0.5](https://github.com/sethbacon/terraform-registry-backend/compare/v1.0.4...v1.0.5) (2026-05-05)


### Bug Fixes

* stable provider version sorts before pre-release with same numeric parts ([#330](https://github.com/sethbacon/terraform-registry-backend/issues/330)) ([3f809f1](https://github.com/sethbacon/terraform-registry-backend/commit/3f809f11cf73c7087a76226c6b943671bb423dab))

## [1.0.4](https://github.com/sethbacon/terraform-registry-backend/compare/v1.0.3...v1.0.4) (2026-05-04)


### Bug Fixes

* address code scanning false-positive alerts ([#328](https://github.com/sethbacon/terraform-registry-backend/issues/328)) ([139af2d](https://github.com/sethbacon/terraform-registry-backend/commit/139af2db9436cfb8ae822a9efe941e421219195d))
* **analyzer:** recover from terraform-config-inspect panics in AnalyzeDir ([#327](https://github.com/sethbacon/terraform-registry-backend/issues/327)) ([e0df552](https://github.com/sethbacon/terraform-registry-backend/commit/e0df552b9d9c908e5b05cfffe8a26baafad8fc56)), closes [#321](https://github.com/sethbacon/terraform-registry-backend/issues/321)

## [1.0.3](https://github.com/sethbacon/terraform-registry-backend/compare/v1.0.2...v1.0.3) (2026-05-04)


### Bug Fixes

* **users:** include memberships inline in list and search responses ([a0a0b35](https://github.com/sethbacon/terraform-registry-backend/commit/a0a0b35f8c8731da61ec78c84f7ba79a205b26c7)), closes [#324](https://github.com/sethbacon/terraform-registry-backend/issues/324)

## [1.0.2](https://github.com/sethbacon/terraform-registry-backend/compare/v1.0.1...v1.0.2) (2026-05-02)


### Bug Fixes

* cve active query column, scm 409 conflict check, storage activate uuid, api-test delay and cleanup ([#322](https://github.com/sethbacon/terraform-registry-backend/issues/322)) ([e68fd3d](https://github.com/sethbacon/terraform-registry-backend/commit/e68fd3d70e7e1e87833d6e4e38bf92d2b8635bf2))

## [1.0.1](https://github.com/sethbacon/terraform-registry-backend/compare/v1.0.0...v1.0.1) (2026-05-02)


### Bug Fixes

* **scm:** implement RegisterWebhook and RemoveWebhook for ADO, GitHub, GitLab ([#319](https://github.com/sethbacon/terraform-registry-backend/issues/319)) ([079e597](https://github.com/sethbacon/terraform-registry-backend/commit/079e597afa728eec7561cccb04bf9618adcb1c62))

## [1.0.0](https://github.com/sethbacon/terraform-registry-backend/compare/v0.18.2...v1.0.0) (2026-04-29)


### Documentation

* 1.0.0 release prep (Release-As: 1.0.0) ([#316](https://github.com/sethbacon/terraform-registry-backend/issues/316)) ([0bc340b](https://github.com/sethbacon/terraform-registry-backend/commit/0bc340b3f15385287a26dcba40b05b9242d0f4c3))

## [0.18.2](https://github.com/sethbacon/terraform-registry-backend/compare/v0.18.1...v0.18.2) (2026-04-29)

### Bug Fixes

* **scanner:** fall back to {install_dir}/{tool} when binary_path is missing ([#314](https://github.com/sethbacon/terraform-registry-backend/issues/314)) ([1998e8f](https://github.com/sethbacon/terraform-registry-backend/commit/1998e8ff662626c979c6713e461ea7929d6e423f))

## [0.18.1](https://github.com/sethbacon/terraform-registry-backend/compare/v0.18.0...v0.18.1) (2026-04-29)

### Bug Fixes

* **db:** quote `references` reserved keyword in migration 032 and repository SQL ([#311](https://github.com/sethbacon/terraform-registry-backend/issues/311)) ([48c6390](https://github.com/sethbacon/terraform-registry-backend/commit/48c6390b04f8f4b7fa0a60f073ec4edb5488a5d2)), closes [#310](https://github.com/sethbacon/terraform-registry-backend/issues/310)
* double-quote the column as `"references"` everywhere it appears. ([48c6390](https://github.com/sethbacon/terraform-registry-backend/commit/48c6390b04f8f4b7fa0a60f073ec4edb5488a5d2))

## [0.18.0](https://github.com/sethbacon/terraform-registry-backend/compare/v0.17.1...v0.18.0) (2026-04-29)

### Features

* **cve:** add daily CVE polling for binaries, providers, and scanner ([#308](https://github.com/sethbacon/terraform-registry-backend/issues/308)) ([05f37ca](https://github.com/sethbacon/terraform-registry-backend/commit/05f37caac1e8c977914cab78f14f9bdd05ea50f2))

## [0.17.1](https://github.com/sethbacon/terraform-registry-backend/compare/v0.17.0...v0.17.1) (2026-04-28)

### Bug Fixes

* **scanner:** pass --cache-dir to trivy version probe ([#306](https://github.com/sethbacon/terraform-registry-backend/issues/306)) ([80531c0](https://github.com/sethbacon/terraform-registry-backend/commit/80531c0da76c7058a187002e3111a9180f60deb7))

### Documentation

* update CLAUDE.md with accurate type list, Go version, and migration count ([#305](https://github.com/sethbacon/terraform-registry-backend/issues/305)) ([8b6c26f](https://github.com/sethbacon/terraform-registry-backend/commit/8b6c26f329f1f3ae16630a3bbc1c76e33a1a767d))

## [0.17.0](https://github.com/sethbacon/terraform-registry-backend/compare/v0.16.1...v0.17.0) (2026-04-28)

### Features

* **deployments:** document backend/frontend version compatibility ([#293](https://github.com/sethbacon/terraform-registry-backend/issues/293)) ([b5deb51](https://github.com/sethbacon/terraform-registry-backend/commit/b5deb518d6d3d88663c558b1e48cf8665c8f938a))

### Bug Fixes

* **security:** resolve CodeQL path-injection and SSRF findings ([#304](https://github.com/sethbacon/terraform-registry-backend/issues/304)) ([287cdb8](https://github.com/sethbacon/terraform-registry-backend/commit/287cdb8e5ad281167d10143db4fdbb828538e315))

### Security

* bump Go to 1.26.2 and fix OSV scanner args ([#303](https://github.com/sethbacon/terraform-registry-backend/issues/303)) ([99d28ae](https://github.com/sethbacon/terraform-registry-backend/commit/99d28ae2db54e7ff1f7d7a8f87a77d783cf4654e)), closes [#290](https://github.com/sethbacon/terraform-registry-backend/issues/290)

## [0.16.1](https://github.com/sethbacon/terraform-registry-backend/compare/v0.16.0...v0.16.1) (2026-04-28)

### Bug Fixes

* **scanning:** store actual scanner tool name on scan completion ([#299](https://github.com/sethbacon/terraform-registry-backend/issues/299)) ([b7cab50](https://github.com/sethbacon/terraform-registry-backend/commit/b7cab503f6f13cb96ea4cc83e4bce926bce4e5d2)), closes [#298](https://github.com/sethbacon/terraform-registry-backend/issues/298)

## [0.16.0](https://github.com/sethbacon/terraform-registry-backend/compare/v0.15.0...v0.16.0) (2026-04-28)

### Features

* **scanning:** add GET scan-by-ID endpoint ([#296](https://github.com/sethbacon/terraform-registry-backend/issues/296)) ([6b49124](https://github.com/sethbacon/terraform-registry-backend/commit/6b49124adcb808e8c89a4f34ac90b12702605155)), closes [#294](https://github.com/sethbacon/terraform-registry-backend/issues/294)

## [0.15.0](https://github.com/sethbacon/terraform-registry-backend/compare/v0.14.3...v0.15.0) (2026-04-27)

### chore

* bump image tags and align version with frontend ([#291](https://github.com/sethbacon/terraform-registry-backend/issues/291)) ([30bbd70](https://github.com/sethbacon/terraform-registry-backend/commit/30bbd70047906d77d566c8fe6be5f17fd3faa6fb))

## [0.14.3](https://github.com/sethbacon/terraform-registry-backend/compare/v0.14.2...v0.14.3) (2026-04-26)

### Bug Fixes

* **scanner:** use writable cache dir for trivy on read-only filesystems ([#288](https://github.com/sethbacon/terraform-registry-backend/issues/288)) ([ce99ceb](https://github.com/sethbacon/terraform-registry-backend/commit/ce99ceba59274e0fc71e4efb1dccf0a43dbc49a2)), closes [#287](https://github.com/sethbacon/terraform-registry-backend/issues/287)

## [0.14.2](https://github.com/sethbacon/terraform-registry-backend/compare/v0.14.1...v0.14.2) (2026-04-26)

### Bug Fixes

* use draft releases for Immutable Releases compatibility ([#285](https://github.com/sethbacon/terraform-registry-backend/issues/285)) ([3b0f426](https://github.com/sethbacon/terraform-registry-backend/commit/3b0f42607da0b3716c5009d01bdf25f0495d1c49)), closes [#284](https://github.com/sethbacon/terraform-registry-backend/issues/284)

## [0.14.1](https://github.com/sethbacon/terraform-registry-backend/compare/v0.14.0...v0.14.1) (2026-04-26)

### Bug Fixes

* use gh release upload instead of delete+create for Immutable Releases ([#282](https://github.com/sethbacon/terraform-registry-backend/issues/282)) ([15a2f1c](https://github.com/sethbacon/terraform-registry-backend/commit/15a2f1cb4244fdec222149cd0a2371012be258e0))

## [0.14.0](https://github.com/sethbacon/terraform-registry-backend/compare/v0.13.2...v0.14.0) (2026-04-26)

### Features

* **config:** add system-wide default language setting ([#280](https://github.com/sethbacon/terraform-registry-backend/issues/280)) ([4c6a27b](https://github.com/sethbacon/terraform-registry-backend/commit/4c6a27b39c123cc4c8b979bc5043f650ae5f5884)), closes [#265](https://github.com/sethbacon/terraform-registry-backend/issues/265)

## [0.13.2](https://github.com/sethbacon/terraform-registry-backend/compare/v0.13.1...v0.13.2) (2026-04-25)

### Bug Fixes

* replace SLSA generator workflows with GitHub Artifact Attestations and fix duplicate GoReleaser archives ([#277](https://github.com/sethbacon/terraform-registry-backend/issues/277)) ([c05118c](https://github.com/sethbacon/terraform-registry-backend/commit/c05118ca068345fd7ad68236422814b37575bad4))

## [0.13.1](https://github.com/sethbacon/terraform-registry-backend/compare/v0.13.0...v0.13.1) (2026-04-25)

### chore

* trigger 0.13.1 release to backfill missing artifacts ([#275](https://github.com/sethbacon/terraform-registry-backend/issues/275)) ([8fbca39](https://github.com/sethbacon/terraform-registry-backend/commit/8fbca39d3adf88960b3788f274f4f6713bfe29d5))

## [0.13.0](https://github.com/sethbacon/terraform-registry-backend/compare/v0.12.0...v0.13.0) (2026-04-25)

### Features

* **admin:** expose scanner binary_path and detected_version in config endpoint ([#272](https://github.com/sethbacon/terraform-registry-backend/issues/272)) ([8a994fb](https://github.com/sethbacon/terraform-registry-backend/commit/8a994fb1de0e95f6803ef62cacd00cc7cea296b9))
* **scanner:** capture scanner stderr as execution_log ([#270](https://github.com/sethbacon/terraform-registry-backend/issues/270)) ([11fbb25](https://github.com/sethbacon/terraform-registry-backend/commit/11fbb25c0da4e6556e54babf40f808bb23f5519a))

## [Unreleased]

## [0.12.0] - 2026-04-24

### Changed

* chore: add fuzz testing workflow and fuzz tests for analyzer and SCM connectors
* chore: extend CODEOWNERS with security-team review for security docs
* chore: update ROADMAP with Phase 4 completion status
* chore: bump deployment configs for v0.11.1 backend + v0.12.0 frontend

## [0.11.1] - 2026-04-24

### Fixed

* fix: security scanning configured via setup wizard silently broken — JSON tag mismatch discarded binary path on restart, scanner goroutine never started, re-scan idempotency broken for existing records
* fix: FuzzParseDelivery panics on nil BitbucketDCConnector receiver in seed corpus run

## [0.11.0] - 2026-04-24

## [0.10.5] - 2026-04-23

### Fixed

* fix: audit log resource_type now correctly shows "organization" for /api/v1/organizations routes (org CRUD and member management)

## [0.10.4] - 2026-04-23

### Fixed

* fix: audit log resource_type now correctly shows "module", "provider", and "storage" instead of "unknown" for admin module/provider CRUD and storage config routes

## [0.10.3] - 2026-04-23

### Added

* feat: add replacement_source to module version deprecation for Terraform CLI >=1.10 protocol compliance

### Fixed

* fix: scanning setup wizard leaves scanning disabled after config save — validate binary_path and update in-memory config on save

## [0.10.2] - 2026-04-22

### Added

* feat: add scanner auto-install for trivy, terrascan, and checkov via setup wizard and admin API with SHA256 verification

## [0.10.1] - 2026-04-21

### Fixed

* fix(db): use UUID type for organization_id in org_quotas migration to match organizations table schema

## [0.10.0] - 2026-04-21

## [0.9.1] - 2026-04-20

### Fixed

* fix(setup): detect unconfigured features added after initial setup and re-trigger the setup wizard — registries that completed setup before scanning was added now correctly show the setup banner and allow configuring scanning without requiring a full re-setup (#215)
* fix(setup): `SetupTokenMiddleware` now allows setup API requests when `setup_completed` is true but pending features remain unconfigured
* fix(setup): server startup generates a new setup token when pending feature setup is detected
* fix(setup): `CompleteSetup` handler supports pending-feature-only completion flow, validating only the unconfigured features

## [0.9.0] - 2026-04-20

### Fixed

* fix(coverfilter): make `pathSuffixMatches` normalize backslashes to forward slashes explicitly so the Windows-path test input passes on Linux runners — `filepath.ToSlash` is a no-op on Linux and left `\`-separated paths unchanged, causing `TestPathSuffixMatches` to fail in the weekly scheduled build (#211)
* fix(ci): bump pinned `google/osv-scanner-action` SHA to v2.3.5 — the prior pin was removed upstream and caused the scheduled OSV scan to fail with `Unable to resolve action ... unable to find version` (#211)

## [0.8.4] - 2026-04-20

### Fixed

* fix(release): stage curated release assets in `release.yml` so the publish step uploads only renamed binaries (`terraform-registry-<os>-<arch>`), `checksums.txt`, `checksums.txt.sig`, the deployment-configs tarball, and `multiple.intoto.jsonl` — avoiding HTTP 400 Bad Content-Length on GoReleaser's empty `digests.txt` and skipping internal files (`artifacts.json`, `metadata.json`, `config.yaml`, per-target build subdirs) (#210)

### Changed

* chore: bump Helm chart `appVersion`, cloud values files (`values-aks`, `values-eks`, `values-gke`), and Kustomize overlay tags (`eks`, `gke`) to `v0.8.4`

## [0.8.3] - 2026-04-19

### Fixed

* fix(release): create GitHub Release atomically with all assets (binaries, checksums, sigs, SBOMs, deployment configs, and SLSA L3 binary provenance) in a single `gh release create` call to satisfy GitHub's Immutable Releases security feature (#208)

### Changed

* chore: bump Helm chart `appVersion` to `0.8.3`

> Note: v0.8.3 had a partial release — the container image `ghcr.io/sethbacon/terraform-registry-backend:0.8.3` was published with cosign signature and SLSA attestation, but the GitHub Release was never created due to a workflow bug (HTTP 400 on empty `digests.txt`). The fix shipped in v0.8.4.

## [0.8.2] - 2026-04-19

### Fixed

* fix(scm): re-run HCL analyzer on Sync now when module docs are missing so previously-imported modules without extracted variables/outputs are backfilled
* fix(release): defer GitHub Release publication until after SLSA L3 binary-provenance upload so `multiple.intoto.jsonl` can be attached before the release becomes immutable

### Changed

* chore: bump Helm chart `appVersion`, cloud values files (`values-aks`, `values-eks`, `values-gke`), and Kustomize overlay tags (`eks`, `gke`) to `v0.8.2`

## [0.8.1] - 2026-04-19

### Fixed

* fix: bump deployment configs from v0.7.1 to v0.8.0 in Helm values, Kustomize overlays, and deployment docs (#203)
* fix: wire `TFR_SCANNING_*` env vars into Helm configmap so `scanning.enabled` actually takes effect (#203)
* fix: add `TFR_SCANNING_*` and `TFR_REDIS_*` stubs to Kustomize base configmap (#203)
* fix: store `collect-changelog.sh` as executable so `prepare-release.yml` rebase step no longer fails on an unstaged mode change (#204)

## [0.8.0] - 2026-04-18

### Added

* feat: Phase 0 quick wins — SECURITY.md, CODE_OF_CONDUCT.md, pinned Docker base-image digests, SBOM generation, cosign keyless signing, Prometheus metrics, gosec baseline drift gate (#197)
* feat: Phase 1 security hardening — Rekor transparency log, Swagger UI vendored locally, FIPS-140-3 build variant, bcrypt cost rotation, dependency review + OSV scan, Trivy fs scan in CI (#198)
* feat: upgrade to SLSA Level 3 build provenance via `slsa-framework/slsa-github-generator` (#201)

### Fixed

* fix: correct trivy-action SHA in CI workflow (#199)

### Changed

* docs: update ROADMAP with Phase 0 and Phase 1 completion checkmarks (#200)

## [0.7.1] - 2026-04-17

## [0.7.0] - 2026-04-17

### Added

* test: add `coverfilter` tool honoring `// coverage:skip:*` doc-comment markers and raise CI coverage threshold from 75% to 80%
* test: add httptest + fake-client unit tests for pull-through metadata fetch (100% of `services/pull_through.go`)
* test: add delegation tests for `auth/azuread` provider (`ExtractUserInfo`, `VerifyIDToken`)
* test: add unit test for `jobs.verifyGPGSignature` wrapper

### Changed

* refactor: introduce `mirror.UpstreamRegistryClient` interface and inject via factory in `PullThroughService` + `MirrorSyncJob` to enable unit testing without live HTTP

## [0.6.2] - 2026-04-16

## [0.6.1] - 2026-04-16

## [0.6.0] - 2026-04-15

## [0.4.3] - 2026-04-14

### Added

* feat: add scanning:read RBAC scope granting devops and auditor roles access to scan results and stats

## [0.4.2] - 2026-04-14

### Added

* feat: add security scanning config and stats API endpoints
* feat: add Security Scanning swagger tag with full annotations
* feat: sort swagger UI tags alphabetically
* feat: extend dashboard stats with scanning health data

## [0.4.1] - 2026-04-14

### Fixed

* fix: initialise `ModuleDoc` `Inputs`/`Outputs`/`Providers` to empty slices — prevents null JSON arrays in module analysis API response for modules with no inputs, outputs, or provider requirements

## [0.4.0-rc.2] - 2026-04-13

## [0.4.0-rc.1] - 2026-04-13

---

## [0.3.5] - 2026-04-13

### Fixed

* fix: add `/auth/exchange-token` endpoint so the frontend can securely receive the SSO JWT from the HttpOnly cookie instead of URL query params
* fix: change SSO callback cookie SameSite from Strict to Lax for cross-site redirect compatibility with identity providers

### Added

* feat: include `version` and `build_date` in `/health` response for deployment verification

### Chore

* chore: update deployment configs to v0.3.4/v0.4.2 and document release update steps in CLAUDE.md

---

## [0.3.4] - 2026-04-13

### Fixed

* fix: respect `security.rate_limiting.enabled` config — all rate limiters (auth, general, upload) were unconditionally applied, ignoring the config flag

---

## [0.3.3] - 2026-04-11

### Fixed

* fix: move module scan route from `/admin/modules/` to `/modules/` prefix to resolve gin wildcard panic on startup

### Documentation

* docs: add module security scanning setup guide covering Trivy, Checkov, Terrascan, Snyk, and custom scanner backends
* docs: add module documentation extraction guide covering terraform-docs auto-extraction API and web UI
* docs: add `scanning:` section to `config.example.yaml` and `TFR_SCANNING_*` variables to configuration reference

---

## [0.3.1] - 2026-04-09

### Security

* fix: reject path traversal sequences in `/v1/files/*filepath` handler and add `safeJoin` containment check to local storage backend — prevents arbitrary host file reads via `GET /v1/files/../../etc/passwd` when using local storage with `ServeDirectly: true` (public endpoint, no auth required)
* fix: reject symlinks and hard links in module archive validation — prevents the registry from storing archives that would create path-escaping symlinks on Terraform client machines during `terraform init`
* fix: require HTTPS for OIDC issuer URL — rejects `http://` issuers that would allow MITM substitution of JWKS signing keys to forge valid ID tokens

---

## [0.3.0] - 2026-04-10

### Added

* feat: pull-through provider caching on mirror cache miss — serves provider metadata immediately from upstream on cache miss while triggering background binary download, eliminating 404s during `terraform init` for unsynced providers
* feat: pluggable module security scanning (Trivy, Terrascan, Snyk, Checkov, custom SARIF) — async scan of every uploaded module archive; stores vulnerability counts and raw results surfaced via admin API
* feat: terraform-docs auto-generation from .tf files at module upload time — extracts and indexes module variables, outputs, and provider requirements using `hashicorp/terraform-config-inspect` (no binary dependency)

### Changed

* test: raise CI coverage floor from 74% to 76.2% via interface-based S3/GCS storage mocks and systematic branch coverage across validation, analyzer, auth/oidc, mirror, and admin packages

---

## [0.2.32] - 2026-04-07

### Security

* fix: deliver JWT auth tokens via HttpOnly secure cookies instead of URL query parameters — prevents token leakage in browser history, server logs, and referrer headers
* fix: add JWT revocation via JTI blocklist with database-backed `revoked_tokens` table — logout now invalidates tokens server-side instead of relying solely on client-side cookie deletion
* fix: prevent CORS `Access-Control-Allow-Credentials: true` from being sent with wildcard origins — only specific origin matches now receive credentials support
* fix: make HSTS header conditional on TLS — `Strict-Transport-Security` is no longer sent over plain HTTP connections, per RFC 6797
* fix: prevent decompression bombs in archive extraction by counting actual bytes written instead of trusting tar header sizes
* fix: protect session store with `sync.Mutex` to prevent concurrent map read/write panics
* fix: `generateRandomSecret()` now returns an error instead of silently falling back to a time-based secret
* fix: remove `GIN_MODE` from `isDevMode()` check — development-only code paths are no longer accidentally enabled by Gin's debug mode
* fix: add `ReadHeaderTimeout` (10s) and `IdleTimeout` (120s) to HTTP server to mitigate slowloris attacks

### Added

* feat: JWT revocation infrastructure — new migration `000013_jwt_revocation` creates `revoked_tokens` table; new `TokenRepository` with `RevokeToken`, `IsTokenRevoked`, and `CleanupExpiredRevocations` methods; daily cleanup goroutine in server startup
* feat: pagination support with `limit`/`offset` query params and `{items, total, limit, offset}` envelope for module versions, provider versions, provider docs, mirrored providers, and mirror config versions
* feat: background job registry with `Job` interface and `Registry` providing `Register`, `StartAll`, `StopAll` lifecycle management
* feat: migration `000014_terraform_mirror_gpg_config` adds `custom_gpg_key` and `skip_gpg_verify` columns to `terraform_mirror_configs`
* feat: checksum sidecar `.sha256` files for local storage — avoids re-reading entire files to compute checksums in `GetMetadata()`
* feat: migration file count parity test ensuring every `.up.sql` has a matching `.down.sql`

### Changed

* refactor: replace all `fmt.Printf`/`fmt.Println` logging with structured `log/slog` calls in audit shipper, SCM linking, and SCM publisher
* refactor: replace `getResourceType()` string-scanning helpers with `c.FullPath()` switch statement in audit middleware
* refactor: remove custom `itoa()` and `min()` functions in favour of stdlib `strconv.Itoa()` and Go builtin `min()`
* refactor: remove `contains()` and `indexOf()` helper functions from audit middleware
* chore: add HA limitation comments to `RateLimiter` (in-memory token bucket) and `docContentCache` (in-memory TTL cache)
* chore: add Swagger annotations to `ServeModuleFile`, `UploadModule`, and `UploadProviderVersion` handlers
* chore: bump Go version from 1.26.0 to 1.26.1
* chore: bump Docker runtime image from `alpine:3.19` to `alpine:3.21`; add `TARGETARCH` build arg for multi-platform builds
* chore: raise CI coverage threshold from 65% to 75%; add per-package coverage gate (80% for auth and middleware)
* chore: add `golangci-lint` step to CI pipeline with `.golangci.yml` configuration

---

## [0.2.31] - 2026-04-07

### Security

* fix: deliver JWT auth tokens via HttpOnly secure cookies instead of URL query parameters — prevents token leakage in browser history, server logs, and referrer headers
* fix: add JWT revocation via JTI blocklist with database-backed `revoked_tokens` table — logout now invalidates tokens server-side instead of relying solely on client-side cookie deletion
* fix: prevent CORS `Access-Control-Allow-Credentials: true` from being sent with wildcard origins — only specific origin matches now receive credentials support
* fix: make HSTS header conditional on TLS — `Strict-Transport-Security` is no longer sent over plain HTTP connections, per RFC 6797
* fix: prevent decompression bombs in archive extraction by counting actual bytes written instead of trusting tar header sizes
* fix: protect session store with `sync.Mutex` to prevent concurrent map read/write panics
* fix: `generateRandomSecret()` now returns an error instead of silently falling back to a time-based secret
* fix: remove `GIN_MODE` from `isDevMode()` check — development-only code paths are no longer accidentally enabled by Gin's debug mode
* fix: add `ReadHeaderTimeout` (10s) and `IdleTimeout` (120s) to HTTP server to mitigate slowloris attacks

### Added

* feat: JWT revocation infrastructure — new migration `000013_jwt_revocation` creates `revoked_tokens` table; new `TokenRepository` with `RevokeToken`, `IsTokenRevoked`, and `CleanupExpiredRevocations` methods; daily cleanup goroutine in server startup
* feat: pagination support with `limit`/`offset` query params and `{items, total, limit, offset}` envelope for module versions, provider versions, provider docs, mirrored providers, and mirror config versions
* feat: background job registry with `Job` interface and `Registry` providing `Register`, `StartAll`, `StopAll` lifecycle management
* feat: migration `000014_terraform_mirror_gpg_config` adds `custom_gpg_key` and `skip_gpg_verify` columns to `terraform_mirror_configs`
* feat: checksum sidecar `.sha256` files for local storage — avoids re-reading entire files to compute checksums in `GetMetadata()`
* feat: migration file count parity test ensuring every `.up.sql` has a matching `.down.sql`

### Changed

* refactor: replace all `fmt.Printf`/`fmt.Println` logging with structured `log/slog` calls in audit shipper, SCM linking, and SCM publisher
* refactor: replace `getResourceType()` string-scanning helpers with `c.FullPath()` switch statement in audit middleware
* refactor: remove custom `itoa()` and `min()` functions in favour of stdlib `strconv.Itoa()` and Go builtin `min()`
* refactor: remove `contains()` and `indexOf()` helper functions from audit middleware
* chore: add HA limitation comments to `RateLimiter` (in-memory token bucket) and `docContentCache` (in-memory TTL cache)
* chore: add Swagger annotations to `ServeModuleFile`, `UploadModule`, and `UploadProviderVersion` handlers
* chore: bump Go version from 1.26.0 to 1.26.1
* chore: bump Docker runtime image from `alpine:3.19` to `alpine:3.21`; add `TARGETARCH` build arg for multi-platform builds
* chore: raise CI coverage threshold from 65% to 75%; add per-package coverage gate (80% for auth and middleware)
* chore: add `golangci-lint` step to CI pipeline with `.golangci.yml` configuration

---

## [0.2.30] - 2026-03-25

### Fixed

* fix: switch doc-index and provider-version pagination from next-page sentinel to length-based detection — the registry v2 API never populates `meta.pagination.next-page`; `GetProviderDocIndexByVersion` now fetches all pages (1,500+ entries for large providers like azurerm) and `resolveProviderVersionID` pages through all provider-version pages to handle providers with more than 100 releases

---

## [0.2.29] - 2026-03-25

### Fixed

* fix: backfill doc index for existing provider versions with no docs — the mirror sync job now checks the doc count when skipping already-complete versions; if zero docs exist (due to a prior failed doc fetch), it fetches and stores the doc index without re-downloading binaries

---

## [0.2.28] - 2026-03-25

### Fixed

* fix: resolve numeric v2 provider-version ID before fetching doc index — `resolveProviderVersionID` now calls `GET /v2/providers/{namespace}/{name}` to obtain the provider's numeric ID then `GET /v2/providers/{id}/provider-versions` to find the matching semver entry

---

## [0.2.25] - 2026-03-24

### Added

* feat: expose real version and build date from `GET /version` — new endpoint returns `{"version":"x.y.z","build_date":"..."}` populated at build time via ldflags injected by GoReleaser and Docker `--build-arg`

### Fixed

* fix: resolve GoReleaser dirty-state failure — deployment-configs tarball now written to `/tmp/` to avoid untracked file detection
* fix: upload deployment-configs tarball via `gh release upload` — GoReleaser's `extra_files` glob rejects absolute paths; tarball attachment moved to a post-GoReleaser step

### Maintenance

* chore: migrate release workflow to GoReleaser — replaces 5-platform matrix build job and hand-rolled `sha256sum` + release upload steps; binary names and checksums file unchanged
* chore: upgrade GitHub Actions to Node 24 compatible versions

---

## [0.2.27] - 2026-03-24

### Fixed

* fix: fetch provider doc index from v2 API with version-specific filtering — replaces the v1 non-versioned endpoint with the upstream registry's v2 `provider-docs` API (`filter[provider-version]`), fixing empty doc listings for mirrored providers where the stored language or version didn't match

---

## [0.2.26] - 2026-03-24

### Fixed

* fix: add `/version` proxy location to Helm nginx ConfigMap — the ConfigMap was missing the location block, causing the SPA fallback to intercept backend API requests in Kubernetes deployments
* fix: remove `go mod tidy` and swag doc generation from Dockerfile — both steps fail in environments with corporate TLS interception; `swagger.json` is committed to the repo by CI and `go.sum` already pins all dependencies

### Maintenance

* chore: add PR template, CI changelog enforcement, and collection script — `.github/PULL_REQUEST_TEMPLATE.md` pre-fills the changelog section; `pr-checks.yml` fails PRs without a valid entry; `collect-changelog.sh` automates release-time changelog collection

---

## [0.2.25] - 2026-03-24

### Added

* feat: expose real version and build date from `GET /version` — new endpoint returns `{"version":"x.y.z","build_date":"..."}` populated at build time via ldflags injected by GoReleaser and Docker `--build-arg`

### Fixed

* fix: resolve GoReleaser dirty-state failure — deployment-configs tarball now written to `/tmp/` to avoid untracked file detection
* fix: upload deployment-configs tarball via `gh release upload` — GoReleaser's `extra_files` glob rejects absolute paths; tarball attachment moved to a post-GoReleaser step

### Maintenance

* chore: migrate release workflow to GoReleaser — replaces 5-platform matrix build job and hand-rolled `sha256sum` + release upload steps; binary names and checksums file unchanged
* chore: upgrade GitHub Actions to Node 24 compatible versions

---

## [0.2.28] - 2026-03-25

### Fixed

* fix: resolve numeric v2 provider-version ID before fetching doc index — `GetProviderDocIndexByVersion` was passing the semver string as `filter[provider-version]` to the upstream registry's v2 `provider-docs` API, which requires the numeric JSON:API provider-version ID; this caused HTTP 400 errors during mirror sync, leaving doc index entries empty and the provider documentation tab blank in the UI

---

## [0.2.27] - 2026-03-24

### Fixed

* fix: fetch provider doc index from v2 API with version-specific filtering — replaces the v1 non-versioned endpoint with the upstream registry's v2 `provider-docs` API (`filter[provider-version]`), fixing empty doc listings for mirrored providers where the stored language or version didn't match

---

## [0.2.26] - 2026-03-24

### Fixed

* fix: add `/version` proxy location to Helm nginx ConfigMap — the ConfigMap was missing the location block, causing the SPA fallback to intercept backend API requests in Kubernetes deployments
* fix: remove `go mod tidy` and swag doc generation from Dockerfile — both steps fail in environments with corporate TLS interception; `swagger.json` is committed to the repo by CI and `go.sum` already pins all dependencies

### Maintenance

* chore: add PR template, CI changelog enforcement, and collection script — `.github/PULL_REQUEST_TEMPLATE.md` pre-fills the changelog section; `pr-checks.yml` fails PRs without a valid entry; `collect-changelog.sh` automates release-time changelog collection

---

## [0.2.25] - 2026-03-24

### Added

* feat: expose real version and build date from `GET /version` — new endpoint returns `{"version":"x.y.z","build_date":"..."}` populated at build time via ldflags injected by GoReleaser and Docker `--build-arg`

### Fixed

* fix: resolve GoReleaser dirty-state failure — deployment-configs tarball now written to `/tmp/` to avoid untracked file detection
* fix: upload deployment-configs tarball via `gh release upload` — GoReleaser's `extra_files` glob rejects absolute paths; tarball attachment moved to a post-GoReleaser step

### Maintenance

* chore: migrate release workflow to GoReleaser — replaces 5-platform matrix build job and hand-rolled `sha256sum` + release upload steps; binary names and checksums file unchanged
* chore: upgrade GitHub Actions to Node 24 compatible versions

---

## [0.2.23] - 2026-03-22

### Added

* feat: provider documentation browsing — new `provider_version_docs` table stores doc metadata fetched from the HashiCorp registry v1 API during mirror sync; two new endpoints (`GET /api/v1/providers/:namespace/:type/versions/:version/docs` and `GET /api/v1/providers/:namespace/:type/versions/:version/docs/:category/:slug`) serve the doc index and proxy markdown content from the registry v2 API with a 15-minute in-memory TTL cache

---

## [0.2.22] - 2026-03-21

### Fixed

* fix: ADO `FetchTags` now adds `peelTags=true` and uses `peeledObjectId` as the commit SHA for annotated tags — migration script creates annotated tags whose `objectId` is the tag-object SHA, not the commit SHA, causing `DownloadSourceArchive` to 404 with `versionType=commit`
* fix: `LinkModuleToSCM` auto-detects the repository's true default branch via `FetchRepository` when `default_branch` is omitted, instead of always defaulting to `"main"` — repos migrated from ADO with `master` as default branch now store correct metadata
* fix: `UpdateSCMLink` no longer overwrites optional string fields with empty strings on partial update — fields absent from the request body now preserve their existing values
* fix: `GetModule` response now includes `created_by_name` (user display name) and per-version `published_by` / `published_by_name` — these were already populated by the DB join but excluded from the `gin.H` response map

### Changed

* test: `api-test` integration tool now covers `PUT /api/v1/admin/modules/{id}` (UpdateModuleRecord), `POST /api/v1/admin/providers` (CreateProviderRecord), and `GET /api/v1/admin/providers/{id}` (GetProviderByID)

---

## [0.2.21] - 2026-03-21

### Fixed

* fix: add snake_case JSON tags to `models.APIKey` — `organization_id` was decoding as empty on the client side because Go serialized fields as PascalCase without explicit tags (#88)
* fix: add `organization_id` to `CreateProviderRecordRequest` and correct `created_by` type assertion (`uuid.UUID` → `string`) in provider create handler (#89)

### Added

* feat: `GET /api/v1/admin/modules/{id}` endpoint — required for Terraform provider `ImportState` on module resources (#90)
* feat: `PUT /api/v1/admin/providers/{id}` endpoint for updating provider record description and source (#91)

---

## [0.2.20] - 2026-03-21

### Fixed

* fix: add snake_case JSON tags to `models.Provider` — without them `CreateProviderRecord` and `GetProviderByID` responses decoded to empty structs on the client, leaving `organization_id` blank on every Read (#84, #86)
* fix: add `organization_id`, `source`, and `created_by` to `GetModule` response — their absence caused a provider inconsistency error on every module update step since `UpdateModuleRecord` returns the full struct but `GetModule` did not (#85, #86)

---

## [0.2.19] - 2026-03-20

### Fixed

* fix: org creator membership fails silently due to wrong type assertion — `c.Get("user_id")` returns a `string`, not `uuid.UUID`; the incorrect assertion always silently failed, leaving org creators without membership and causing 403 on all member-gated endpoints (#80, #82)
* fix: add postgres healthcheck and required env vars (`TFR_DATABASE_SSL_MODE`, `ENCRYPTION_KEY`, `TFR_JWT_SECRET`) to `docker-compose.test.yml` so the acceptance-test stack starts correctly (#82)

### Added

* feat: `PUT /api/v1/admin/modules/{id}` endpoint for updating module records — the repository layer already had `UpdateModule`; only the HTTP handler and route registration were missing (#81, #82)

---

## [0.2.18] - 2026-03-20

### Fixed

* fix: mirror config detail **Latest Version** field now shows the highest semver version rather than the first version returned by the upstream registry (#74)
* fix: storage config creation no longer unconditionally activates the new config — `activate=true` must be explicitly passed to make it active (#75)
* fix: org creation now auto-adds the requesting user as an admin member so subsequent API calls succeed without a separate membership step (#76)

### Added

* feat: `POST /api/v1/admin/providers` and `GET /api/v1/admin/providers/:id` CRUD endpoints for provider records, enabling the Terraform provider `registry_provider_record` resource to create and read provider entries by UUID (#77)

---

## [0.2.17] - 2026-03-17

### Fixed

* fix: semver sort no longer crashes on pre-release or build-metadata version strings (e.g. `5.0.0-beta`, `4.0.0-rc1`, `1.2.3+build`) — `NULLIF` only guarded against empty strings; the new `REGEXP_REPLACE(..., '[-+].*$', '')` strips suffixes before `SPLIT_PART` and `CAST` in all four semver `ORDER BY` expressions. Resolves the provider search 500 and the mirror detail "No providers synced" empty-state (#69)

---

## [0.2.16] - 2026-03-17

### Fixed

* fix: module card, terraform binary mirror list, and mirror config detail modal now sort versions by semver instead of upload/sync time — `SearchModulesWithStats`, `TerraformMirrorRepository.ListVersions`, and `ListMirroredProviderVersions` all used `created_at`/`synced_at` ordering
* fix: harden semver sort in `SearchProvidersWithStats` (v0.2.15) to guard against empty split parts with `COALESCE(CAST(NULLIF(...) AS INTEGER), 0)`

---

## [0.2.15] - 2026-03-17

### Fixed

* fix: provider card shows latest semver version instead of latest uploaded version — `SearchProvidersWithStats` was ordering the `latest_version` subquery by upload time; now sorts by semver major/minor/patch so the correct highest version is always shown (#62)

---

## [0.2.14] - 2026-03-17

### Fixed

* fix: broaden OIDC email fallback to cover all Azure AD UPN claim variants (`preferred_username`, `upn`, `unique_name`) and log the specific extraction error for diagnosis

---

## [0.2.13] - 2026-03-17

### Fixed

* fix: OIDC login fails for Azure Entra ID when `email` claim is absent — fall back to `preferred_username` (UPN) so login works without requiring the optional `email` claim to be added to the App Registration

---

## [0.2.12] - 2026-03-17

### Fixed

* fix: stream provider and Terraform binary downloads to a temp file instead of buffering entire zip in memory — eliminates OOM kills for large providers (e.g. AWS ~500 MB) on memory-constrained deployments (#54)

---

## [0.2.11] - 2026-03-17

### Fixed

* fix: AuditMiddleware logs failed write operations even when `LogFailedRequests=false` — removed erroneous `&& isReadOp` guard from the failed-request skip condition (#29)

---

## [0.2.10] - 2026-03-17

### Fixed

* fix: resolve FK violation in `SetStorageConfigured` where `uuid.Nil` violated the `storage_configured_by → users(id)` FK, silently leaving `storage_configured = false` after a successful setup wizard save (#51)
* fix: log encryption error when storage credential encryption fails in setup wizard (#51)

---

## [0.2.9] - 2026-03-17

### Fixed

* fix: run frontend nginx on port 8080 so non-root container can bind without NET_BIND_SERVICE capability (#49)

---

## [0.2.8] - 2026-03-17

### Fixed

* fix: make frontend pod security context configurable via Helm values to support rootless nginx on AKS (#47)

---

## [0.2.7] - 2026-03-17

### Fixed

* fix: correct helm liveness and startup probe path from /healthz to /health (#44)

---

## [0.2.6] - 2026-03-16

### Fixed

* fix: reset stale `in_progress` mirror sync status on startup so mirrors are automatically re-scheduled after a backend restart or ECS task replacement (#42)

### Changed

* chore: add `.gitattributes` to enforce LF line endings repo-wide (#42)

---

## [0.2.5] - 2026-03-08

### Fixed

* fix: make mirror provider lookup deterministic by preferring organization-scoped providers over NULL-org fallback, preventing network mirror index/version mismatch errors during `terraform init` (#39)

---

## [0.2.4] - 2026-03-06

### Fixed

* fix: restore provider download count tracking for network mirror protocol — download counts were silently dropped for S3, Azure, GCS, and local storage without ServeDirectly after v0.2.3 moved tracking to ServeFileHandler, which is only reachable for local+ServeDirectly (#36, #37)

---

## [0.2.3] - 2026-03-05

### Fixed

* fix: move mirror download tracking to file serve handler — User-Agent parsing fails with Terraform 1.14.6 which omits platform info; now tracks via URL path at `/v1/files/` which always contains os/arch (#20)

---

## [0.2.2] - 2026-03-05

### Fixed

* fix: track provider downloads via network mirror protocol by parsing client User-Agent for platform detection (#18)

---

## [0.2.1] - 2026-03-05

### Fixed

* fix: compute and serve correct `h1:` dirhash for provider mirror packages, resolving `terraform init` checksum mismatch (#11)

### Added

* test: expand test coverage across API handlers (admin, mirror, modules, providers, setup), database repositories (modules, providers, terraform mirror), and CLI utilities (api-test, check-db, fix-migration, hash) (#15)

### Changed

* docs: update and expand documentation across all sections (CLAUDE.md, README.md, deployment, configuration, troubleshooting, observability, architecture, development, OIDC, terraform-cli, api-reference) (#14)

### Removed

* chore: remove legacy unused utility files (`backend/clean-db.sql`, `backend/fix-migration.sql`, `backend/cmd/test-api`) (#15)

---

## [0.2.0] - 2026-03-04

### Fixed

* Fix `TriggerManualSync` not releasing `activeSyncsMutex` after marking a sync active, causing all subsequent sync requests to block indefinitely (#3)
* Fix terraform mirror status response returning equal `version_count` and `platform_count` because `COUNT(*)` was used instead of `COUNT(DISTINCT v.id)` for versions (#4)
* Fix swagger auto-commit being rejected by GitHub when two CI runs regenerated the file concurrently; add rebase before push (#6)
* Fix Dockerfile health check using `https://` against an HTTP-only server (#8)
* Fix NetworkPolicy (`allow-backend-ingress`) silently dropping direct Gateway/load-balancer traffic to the backend on AKS/EKS/GKE overlays (#8)
* Fix HPA oscillation in production overlay caused by `spec.replicas` being re-applied on every `kubectl apply` (#8)
* Fix liveness probe using `/health` (dependency-checking endpoint) — now uses `/healthz`; readiness probe correctly uses `/health` (#8)
* Fix stale Azure-specific `<ACR_NAME>.azurecr.io` placeholder in the generic production overlay image references (#8)
* Fix production overlay base URL patch being a no-op `registry.example.com` value (#8)
* Fix deployment documentation environment variable names to use `TFR_` prefix throughout (#8)

### Added

* Add `startupProbe` on `/healthz` to backend Kustomize and Helm deployments (#8)
* Add `readOnlyRootFilesystem: true` with `/tmp` emptyDir volume to backend container (#8)
* Add pod and container `securityContext` to Helm frontend Deployment to match Kustomize base (#8)
* Add `serviceAccountName` to Helm frontend Deployment (#8)
* Add `topologySpreadConstraints` patch to generic production overlay (#8)
* Add GKE Cloud SQL Auth Proxy sidecar patch to `overlays/gke/patches/backend-cloudsql-proxy.yaml` (#8)
* Add nginx `Permissions-Policy` security header to frontend nginx ConfigMap (#8)
* Add cloud-specific Helm values files: `values-aks.yaml`, `values-eks.yaml`, `values-gke.yaml` (#8)
* Add Helm templates for Gateway API, ClusterIssuer, NetworkPolicy, SecretProviderClass (#8)
* Add `docs/deployment/` directory with cloud-specific guides (AKS, EKS, GKE: prerequisites, deployment, operations) (#8)
* Add database backup procedures and PVC Backup & Restore section to deployment documentation (#8)

### Changed

* Default Helm `cors.allowedOrigins` from `["*"]` to `[]` — requires explicit configuration (#8)
* Default Helm `networkPolicy.enabled` from `false` to `true` (#8)
* Default Helm `securityContext.readOnlyRootFilesystem` from `false` to `true` (#8)
* Return `202 Accepted` instead of `409 Conflict` when a concurrent mirror sync is already in progress (#3)

---

## [0.1.0] - 2026-03-04

* Initial commit
