package analyzer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

// FuzzAnalyzeArchive ensures the archive parser does not panic or leak memory
// when fed arbitrary bytes. The function must handle any input gracefully
// (return an error, not panic).
func FuzzAnalyzeArchive(f *testing.F) {
	// Seed with a minimal valid tar.gz archive containing a single .tf file.
	f.Add(minimalTarGz())

	// Seed with an empty input.
	f.Add([]byte{})

	// Seed with random-looking garbage.
	f.Add([]byte("\x1f\x8b\x08\x00garbage"))

	// Seed with a valid gzip header but invalid tar content.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("not a tar archive"))
	_ = gz.Close()
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		// AnalyzeArchive must never panic — only return (nil, err) or (*ModuleDoc, nil).
		r := bytes.NewReader(data)
		doc, err := AnalyzeArchive(r)
		if err != nil {
			// Errors are expected for malformed input; that is fine.
			return
		}
		if doc == nil {
			return
		}
		// If a doc was returned, it must be marshallable without panicking.
		if doc.Inputs != nil {
			_, _ = MarshalInputs(doc.Inputs)
		}
		if doc.Outputs != nil {
			_, _ = MarshalOutputs(doc.Outputs)
		}
		if doc.Providers != nil {
			_, _ = MarshalProviders(doc.Providers)
		}
	})
}

// minimalTarGz builds a minimal tar.gz archive containing a trivial main.tf.
// It is used as a seed so the fuzzer starts from a plausible input.
func minimalTarGz() []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	content := []byte(`variable "region" { default = "us-east-1" }`)
	hdr := &tar.Header{
		Name: "main.tf",
		Mode: 0600,
		Size: int64(len(content)),
	}
	_ = tw.WriteHeader(hdr)
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gz.Close()

	return buf.Bytes()
}
