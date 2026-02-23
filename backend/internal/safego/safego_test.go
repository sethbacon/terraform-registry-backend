package safego

import (
	"sync"
	"testing"
	"time"
)

func TestGo_RunsFunction(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)

	Go(func() {
		defer wg.Done()
	})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// function ran successfully
	case <-time.After(2 * time.Second):
		t.Error("goroutine did not complete within timeout")
	}
}

func TestGo_RecoversPanic(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)

	// This should not crash the test process; the panic must be recovered.
	Go(func() {
		defer wg.Done()
		panic("intentional panic in test")
	})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// panic was recovered; test passes
	case <-time.After(2 * time.Second):
		t.Error("goroutine did not complete within timeout after panic")
	}
}
