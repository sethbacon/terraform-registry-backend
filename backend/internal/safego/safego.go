// Package safego provides a panic-recovering goroutine launcher for background work.
package safego

import "log/slog"

// Go launches fn in a new goroutine. If fn panics, the panic is recovered and
// logged rather than crashing the process. This should be used for all
// fire-and-forget goroutines (background jobs, async webhook processing, etc.)
// where an unrecovered panic would silently kill the goroutine forever.
func Go(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("recovered panic in background goroutine", "panic", r)
			}
		}()
		fn()
	}()
}
