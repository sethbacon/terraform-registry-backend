// Package archivelimits defines the size and entry-count caps that every tar.gz
// archive guard in this codebase must enforce: validation.ValidateArchive
// (upload-time validation) and archiver.ExtractTarGz (scan/analyze-time
// extraction). Both guards independently walk the same tar.gz structure and
// must apply identical caps; centralizing the numbers here means a future
// change to one guard's limit is automatically a change to both, rather than
// two constants that can silently drift apart.
package archivelimits

const (
	// MaxBytes is the maximum cumulative decompressed size of a module/provider
	// archive (100 MB).
	MaxBytes = 100 << 20

	// MaxEntries bounds the number of tar entries in an archive. Without this,
	// an archive of millions of zero-byte file entries never trips MaxBytes
	// (which only tracks decompressed body bytes) while still exhausting
	// inodes/metadata when later extracted. A ~1MB gzip can encode ~2M such
	// entries, so this must be checked independently of the byte cap.
	MaxEntries = 100000
)
