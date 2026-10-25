package scan

import (
	"context"
	"testing"

	"github.com/aktezed/assfin/pkg/types"
)

func TestProbeEmpty(t *testing.T) {
	called := false
	err := Probe(context.Background(), []string{}, ProbeOpts{
		OnProgress: func(c, tot int) {
			called = true
		},
	}, func(host string, p types.Probe) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Errorf("expected OnProgress not to be called for empty hosts")
	}
}
