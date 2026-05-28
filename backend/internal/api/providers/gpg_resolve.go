package providers

import "github.com/terraform-registry/terraform-registry/internal/mirror"

func resolveProviderGPGKey(armored string) string {
	return mirror.ResolveExpiredGPGKey(armored)
}
