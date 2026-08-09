package storage

import "testing"

// Issue #752 — the key namespace this validator must not break.
//
// Every entry in mustAccept is traced to the producer that emits it. That
// matters more than the reject list: rejecting a legitimate key is a production
// outage, while the issue itself is explicit that it could not construct an
// exploit for the traversal case. The reject list is the cheap half.
//
// Two design decisions are pinned by this table:
//
//   - NO character-set allowlist. Keys legitimately contain uppercase, '+', '~'
//     and '.', because namespaces are not lowercased on the storage path and
//     hashicorp/go-version is looser than strict semver (it accepts build
//     metadata like 1.0.0+build.5, two- and four-segment versions, and
//     1.0.0alpha). A charset rule derived from what "should" be there rejects
//     artifacts that already exist in deployed buckets.
//   - NO prefix allowlist. .readiness-probe and .connectivity-test are
//     root-level sentinels with no prefix, so requiring modules/ | providers/ |
//     terraform-binaries/ would break the readiness endpoint and both storage
//     connectivity tests.
var mustAccept = []struct{ key, producer string }{
	// Sentinels — no prefix at all.
	{".readiness-probe", "router.go readiness probe"},
	{".connectivity-test", "admin/storage.go + setup/handlers.go connectivity tests"},

	// Modules. Two leaf shapes: upload writes <version>.tar.gz, the SCM
	// publisher writes <name>-<version>.tar.gz.
	{"modules/hashicorp/consul/aws/1.0.0.tar.gz", "modules/upload.go"},
	{"modules/acme/vpc/aws/vpc-1.0.0.tar.gz", "services/scm_publisher.go"},
	// go-version accepts far more than strict semver.
	{"modules/acme_corp/my-module/google/1.0.0+build.tar.gz", "upload, build metadata"},
	{"modules/acme/mod/aws/1.0.0-rc.1+exp.sha.5114f85.tar.gz", "upload, prerelease+build"},
	{"modules/acme/mod/aws/1.2.tar.gz", "upload, two-segment version"},
	{"modules/acme/mod/aws/1.2.3.4.tar.gz", "upload, four-segment version"},
	{"modules/acme/mod/aws/1.0.0alpha.tar.gz", "upload, no separator"},
	{"modules/acme/mod/aws/1.0.0-foo~bar.tar.gz", "upload, tilde"},
	{"modules/acme/mod/aws/v1.0.0.tar.gz", "upload, v-prefixed"},
	// Namespaces are not lowercased on the storage path.
	{"modules/Acme/VPC/AWS/1.0.0.tar.gz", "upload, mixed case"},
	// The local backend writes a .sha256 sidecar next to every key; the sidecar
	// path is itself a key it operates on.
	{"modules/hashicorp/consul/aws/1.0.0.tar.gz.sha256", "local backend checksum sidecar"},

	// Providers. Three shapes under one prefix: 4-segment upload, the SUMS
	// pair, and the 6-segment mirror-sync layout.
	{"providers/hashicorp/aws/5.31.0/linux_amd64.zip", "providers/upload.go"},
	{"providers/hashicorp/aws/5.31.0/SHA256SUMS", "providers/upload.go"},
	{"providers/hashicorp/aws/5.31.0/SHA256SUMS.sig", "providers/upload.go"},
	{"providers/acme/prov/1.0.0+build/SHA256SUMS", "upload, build metadata in version"},
	{"providers/hashicorp/aws/5.31.0/linux/amd64/terraform-provider-aws_5.31.0_linux_amd64.zip", "jobs/mirror_sync.go"},
	{"providers/hashicorp/vault/4.2.0/linux/ppc64le/terraform-provider-vault_4.2.0_linux_ppc64le.zip", "mirror_sync, uncommon arch"},

	// Terraform binaries mirror.
	{"terraform-binaries/1.9.5/SHA256SUMS", "jobs/terraform_mirror_sync.go"},
	{"terraform-binaries/1.9.5/SHA256SUMS.terraform.sig", "terraform_mirror_sync, per-tool sig"},
	{"terraform-binaries/0.18.0/SHA256SUMS.terraform-docs.sig", "terraform_mirror_sync, hyphenated tool"},
	{"terraform-binaries/1.9.5/linux/amd64/terraform_1.9.5_linux_amd64.zip", "terraform_mirror_sync"},
	{"terraform-binaries/0.60.0/windows/amd64/opa_windows_amd64.exe", "terraform_mirror_sync, .exe"},
	{"terraform-binaries/1.9.0-alpha20240404/linux/amd64/terraform_1.9.0-alpha20240404_linux_amd64.zip", "terraform_mirror_sync, prerelease"},
	{"terraform-binaries/0.18.0/linux/amd64/terraform-docs-v0.18.0-linux-amd64.tar.gz", "terraform_mirror_sync, tar.gz asset"},
}

var mustReject = []struct{ key, why string }{
	{"", "empty"},
	{".", "names no object"},
	{"/", "absolute"},
	{"/etc/passwd", "absolute"},
	{"../../etc/passwd", "traversal"},
	{"modules/../../../etc/shadow", "traversal"},
	{"modules/acme/mod/aws/../../../../etc/shadow", "traversal"},
	{"terraform-binaries/1.9.5/linux/amd64/../../../../SHA256SUMS", "traversal"},
	{"providers/a/../../b/aws/1.0.0/linux/amd64/x.zip", "traversal"},
	{"modules//acme/mod/aws/1.0.0.tar.gz", "empty segment"},
	{"providers/hashicorp/aws/1.0.0/linux/amd64/", "trailing separator"},
	{"./modules/acme/mod/aws/1.0.0.tar.gz", "non-canonical leading ./"},
	{"providers/./hashicorp/aws/1.0.0/linux/amd64/x.zip", "non-canonical interior /./"},
	{`modules\acme\mod\aws\1.0.0.tar.gz`, "backslash separators"},
	{`C:\Windows\System32\config\SAM`, "windows absolute"},
	{"modules/acme/mod/aws/1.0.0.tar.gz\x00.png", "NUL byte"},
	{"providers/hashi\ncorp/aws/1.0.0/linux/amd64/x.zip", "control character"},
	{"s3://bucket/modules/acme/mod/aws/1.0.0.tar.gz", "scheme (contains //)"},
	{"https://evil.example.com/x", "scheme (contains //)"},
}

func TestValidateKey_AcceptsEveryRealKey(t *testing.T) {
	for _, tc := range mustAccept {
		t.Run(tc.key, func(t *testing.T) {
			if err := ValidateKey(tc.key); err != nil {
				t.Errorf("ValidateKey(%q) = %v, want nil — this key is produced by %s, "+
					"so rejecting it breaks that path", tc.key, err, tc.producer)
			}
		})
	}
}

func TestValidateKey_RejectsMalformedKeys(t *testing.T) {
	for _, tc := range mustReject {
		t.Run(tc.why+"/"+tc.key, func(t *testing.T) {
			if err := ValidateKey(tc.key); err == nil {
				t.Errorf("ValidateKey(%q) = nil, want an error (%s)", tc.key, tc.why)
			}
		})
	}
}

func TestValidateKey_LengthCap(t *testing.T) {
	long := "modules/"
	for len(long) <= maxKeyBytes {
		long += "a"
	}
	if err := ValidateKey(long); err == nil {
		t.Errorf("a %d-byte key was accepted; S3 rejects keys over %d bytes anyway",
			len(long), maxKeyBytes)
	}

	// Exactly at the cap is fine — the boundary must not be off by one.
	exact := "modules/" + repeat("a", maxKeyBytes-len("modules/"))
	if len(exact) != maxKeyBytes {
		t.Fatalf("test built a %d-byte key, wanted %d", len(exact), maxKeyBytes)
	}
	if err := ValidateKey(exact); err != nil {
		t.Errorf("a key of exactly %d bytes was rejected: %v", maxKeyBytes, err)
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, s[0])
	}
	return string(out)
}

// TestValidateKey_TableIsNotEmpty — the two tables drive everything above, so
// an accidental truncation would report green while asserting nothing.
func TestValidateKey_TableIsNotEmpty(t *testing.T) {
	if len(mustAccept) < 20 {
		t.Errorf("mustAccept has %d entries; it enumerates the real key namespace and "+
			"should not shrink", len(mustAccept))
	}
	if len(mustReject) < 15 {
		t.Errorf("mustReject has %d entries", len(mustReject))
	}
}
