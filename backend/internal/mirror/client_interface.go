// client_interface.go exports the UpstreamRegistryClient interface, which
// abstracts the subset of UpstreamRegistry methods used by consumers in the
// services and jobs packages.  It exists to enable dependency injection so
// consumers can be unit-tested against fake clients without performing real
// HTTP calls.  *UpstreamRegistry satisfies this interface by construction.
package mirror

import "context"

// UpstreamRegistryClient is the interface consumed by services and jobs that
// orchestrate upstream metadata fetches, shasums downloads, and mirror sync.
// Defining it in the mirror package lets consumers depend on a single
// contract while keeping the concrete UpstreamRegistry as the production
// implementation.  Tests may substitute a fake that records calls and
// returns canned responses.
type UpstreamRegistryClient interface {
	DiscoverServices(ctx context.Context) (*ServiceDiscoveryResponse, error)
	ListProviderVersions(ctx context.Context, namespace, providerName string) ([]ProviderVersion, error)
	GetProviderPackage(ctx context.Context, namespace, providerName, version, os, arch string) (*ProviderPackageResponse, error)
	DownloadFile(ctx context.Context, fileURL string) ([]byte, error)
	DownloadFileStream(ctx context.Context, fileURL string) (*DownloadStream, error)
	GetProviderDocIndexByVersion(ctx context.Context, namespace, providerName, version string) ([]ProviderDocEntry, error)
	GetProviderDocContent(ctx context.Context, upstreamDocID string) (string, error)
}

// Compile-time assertion that *UpstreamRegistry satisfies UpstreamRegistryClient.
var _ UpstreamRegistryClient = (*UpstreamRegistry)(nil)
