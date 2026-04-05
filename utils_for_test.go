//go:build e2e || compression || throughput

package caphouse

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	tccontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

var e2eClient *Client

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

func init() {
	var ctr *clickhouse.ClickHouseContainer
	testSetups = append(testSetups, testSetup{
		setup: func(ctx context.Context) error {
			var err error
			ctr, err = clickhouse.Run(ctx, "clickhouse/clickhouse-server:25.3",
				tccontainers.WithEnv(map[string]string{
					"CLICKHOUSE_USER":     "default",
					"CLICKHOUSE_PASSWORD": "default",
					"CLICKHOUSE_DB":       "caphouse_e2e",
				}),
			)
			if err != nil {
				return fmt.Errorf("start clickhouse container: %w", err)
			}
			dsn, err := ctr.ConnectionString(ctx)
			if err != nil {
				return fmt.Errorf("get connection string: %w", err)
			}
			e2eClient, err = New(ctx, Config{
				DSN:       dsn,
				Database:  "caphouse_e2e",
				BatchSize: 50000,
			})
			if err != nil {
				return fmt.Errorf("create client: %w", err)
			}
			if err := e2eClient.InitSchema(ctx); err != nil {
				return fmt.Errorf("init schema: %w", err)
			}
			return nil
		},
		teardown: func() {
			_ = e2eClient.Close()
			_ = ctr.Terminate(context.Background())
		},
	})
}

// baselineCommit returns the merge-base of HEAD and main, which is the commit
// where the current branch diverged from main. When already on main this
// equals HEAD.
func baselineCommit(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "merge-base", "HEAD", "main").Output()
	if err != nil {
		t.Logf("warning: could not determine merge-base, falling back to HEAD: %v", err)
		return "HEAD"
	}
	return strings.TrimSpace(string(out))
}
