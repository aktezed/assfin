package scan

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewSubfinderReturnsOnCanceledContext(t *testing.T) {
	enum, err := NewSubfinder(5, 1, "")
	if err != nil {
		t.Fatalf("NewSubfinder failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		_, err := enum(ctx, "example.test")
		done <- err
	}()

	select {
	case gotErr := <-done:
		if !errors.Is(gotErr, context.Canceled) {
			t.Fatalf("got err = %v, want context.Canceled", gotErr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("enum blocked on canceled context")
	}
}
