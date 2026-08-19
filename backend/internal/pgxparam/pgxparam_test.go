package pgxparam

import (
	"database/sql/driver"
	"testing"
	"time"
)

func TestConverterPassesSlicesThrough(t *testing.T) {
	// The reason this package exists: database/sql's default converter rejects
	// these outright, and they are what an org-scope predicate binds.
	cases := []struct {
		name string
		in   any
	}{
		{"string slice", []string{"org-1", "org-2"}},
		{"empty string slice", []string{}},
		{"int slice", []int64{1, 2, 3}},
		{"nil string slice", []string(nil)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Converter{}.ConvertValue(c.in)
			if err != nil {
				t.Fatalf("ConvertValue(%#v) errored: %v", c.in, err)
			}
			if _, def := driver.DefaultParameterConverter.ConvertValue(c.in); def == nil {
				t.Fatalf("%#v no longer needs this converter; database/sql now accepts it", c.in)
			}
			if gotSlice, ok := got.([]string); ok {
				want, _ := c.in.([]string)
				if len(gotSlice) != len(want) {
					t.Errorf("ConvertValue returned %#v, want %#v", got, c.in)
				}
			}
		})
	}
}

func TestConverterDefersEverythingElse(t *testing.T) {
	// []byte is already a driver.Value and must keep its own semantics rather
	// than be caught by the slice branch.
	cases := []any{[]byte("raw"), "org-1", 7, true, nil, time.Now()}
	for _, in := range cases {
		got, err := Converter{}.ConvertValue(in)
		if err != nil {
			t.Fatalf("ConvertValue(%#v) errored: %v", in, err)
		}
		want, err := driver.DefaultParameterConverter.ConvertValue(in)
		if err != nil {
			t.Fatalf("the default converter rejected %#v: %v", in, err)
		}
		if gotBytes, ok := got.([]byte); ok {
			if wantBytes, _ := want.([]byte); string(gotBytes) != string(wantBytes) {
				t.Errorf("ConvertValue(%#v) = %v, want %v", in, got, want)
			}
			continue
		}
		if got != want {
			t.Errorf("ConvertValue(%#v) = %v (%T), want %v (%T)", in, got, got, want, want)
		}
	}
}

func TestConverterRejectsWhatTheDefaultRejects(t *testing.T) {
	// A non-slice the default converter cannot handle must still be an error,
	// so this stays a narrow widening rather than a blanket pass-through.
	if _, err := (Converter{}).ConvertValue(struct{ A int }{1}); err == nil {
		t.Error("a struct was accepted; the converter is wider than intended")
	}
}
