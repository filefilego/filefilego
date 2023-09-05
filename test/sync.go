package test

import (
	"sync"
	"testing"
	"time"
)

// WaitWithTimeout is a testing helper function that will block until the wait
// group counter is zero. If the timeout ticks before that, it will mark the
// test as failed and stop the testing process.
func WaitWithTimeout(t *testing.T, wg *sync.WaitGroup, timeout <-chan time.Time) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()

	select {
	case <-done:
		// success
	case <-timeout:
		t.Fatal("timeout")
	}
}
