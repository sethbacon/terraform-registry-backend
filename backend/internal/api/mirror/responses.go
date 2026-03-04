package mirror

// MirrorArchiveEntry describes the URL and hash information for a single provider binary archive.
type MirrorArchiveEntry struct {
	URL    string            `json:"url"`
	Hashes map[string]string `json:"hashes"`
}

// MirrorVersionIndexResponse is returned by the network mirror version index endpoint.
// The top-level object is keyed by version string (e.g. "1.0.0").
// Each value is an empty object per the Network Mirror Protocol (version presence is the signal).
// swaggo does not support map[string]struct{} natively; use a generic map annotation.
type MirrorVersionIndexResponse struct {
	Versions map[string]interface{} `json:"versions"`
}

// MirrorPlatformIndexResponse is returned by the network mirror platform index endpoint.
// The top-level object is keyed by platform string (e.g. "linux_amd64").
type MirrorPlatformIndexResponse struct {
	Archives map[string]MirrorArchiveEntry `json:"archives"`
}
