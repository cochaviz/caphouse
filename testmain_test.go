//go:build integration || compression

package caphouse

import (
	"context"
	"fmt"
	"os"
	"testing"
)

type testSetup struct {
	setup    func(context.Context) error
	teardown func()
}

// testSetups is populated via init() in each tagged test file.
var testSetups []testSetup

func TestMain(m *testing.M) {
	ctx := context.Background()

	for _, s := range testSetups {
		if err := s.setup(ctx); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	code := m.Run()

	for _, s := range testSetups {
		if s.teardown != nil {
			s.teardown()
		}
	}

	os.Exit(code)
}
