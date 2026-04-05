//go:build e2e

package caphouse

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
	"testing"
)

func newMigrateTestClient(t *testing.T, ctx context.Context, dbName string) *Client {
	t.Helper()
	if err := e2eClient.conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", quoteIdent(dbName))); err != nil {
		t.Fatalf("create database %s: %v", dbName, err)
	}
	client, err := New(ctx, Config{
		DSN:      e2eClient.cfg.DSN,
		Database: dbName,
		Logger:   slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = e2eClient.conn.Exec(context.Background(),
			fmt.Sprintf("DROP DATABASE IF EXISTS %s", quoteIdent(dbName)))
	})
	return client
}

// TestMigrationsIdempotent verifies that calling InitSchema twice on the same
// database does not fail.
func TestMigrationsIdempotent(t *testing.T) {
	ctx := context.Background()
	client := newMigrateTestClient(t, ctx, "migrate_test_idempotent")

	if err := client.InitSchema(ctx); err != nil {
		t.Fatalf("first InitSchema: %v", err)
	}
	if err := client.InitSchema(ctx); err != nil {
		t.Fatalf("second InitSchema: %v", err)
	}
}

// TestMigrationsVersionTracking verifies that after InitSchema the database
// version matches the latest embedded migration ID.
func TestMigrationsVersionTracking(t *testing.T) {
	ctx := context.Background()
	client := newMigrateTestClient(t, ctx, "migrate_test_version")

	if err := client.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var sqlNames []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") && e.Name() != ".keep.sql" {
			sqlNames = append(sqlNames, e.Name())
		}
	}
	if len(sqlNames) == 0 {
		t.Skip("no migrations embedded; skipping version tracking test")
	}
	sort.Strings(sqlNames)
	expectedVersion := migrationID(sqlNames[len(sqlNames)-1])

	var dbVersion string
	if err := client.conn.QueryRow(ctx, fmt.Sprintf(
		"SELECT id FROM %s ORDER BY id DESC LIMIT 1",
		client.tableRef("caphouse_schema_migrations"),
	)).Scan(&dbVersion); err != nil {
		t.Fatalf("query db version: %v", err)
	}

	if dbVersion != expectedVersion {
		t.Errorf("db version = %q, want %q", dbVersion, expectedVersion)
	}
}

// TestMigrationsStaleClientError verifies that a client whose compiled-in
// migrations are behind the database version returns an error.
func TestMigrationsStaleClientError(t *testing.T) {
	ctx := context.Background()
	client := newMigrateTestClient(t, ctx, "migrate_test_stale")

	if err := client.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// Manually insert a future version into the migrations table.
	futureID := "99991231235959_fffffff_future"
	if err := client.conn.Exec(ctx, fmt.Sprintf(
		"INSERT INTO %s (id) VALUES (?)",
		client.tableRef("caphouse_schema_migrations"),
	), futureID); err != nil {
		t.Fatalf("insert future version: %v", err)
	}

	err := client.runMigrations(ctx)
	if err == nil {
		t.Fatal("expected error for stale client, got nil")
	}
	t.Logf("got expected error: %v", err)
}

// testWriter adapts testing.T to io.Writer for slog output.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
