package caphouse

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// runMigrations applies any pending SQL migrations to the caphouse database.
// Migrations are SQL files embedded from the migrations/ directory, named
// YYYYMMDDHHMMSS_COMMIT_description.sql and applied in lexicographic order.
//
// A single row in caphouse_schema_migrations records the latest applied
// migration ID. If the database is ahead of the binary (db version >
// compiled-in latest), an error is returned so a stale client doesn't
// silently operate against an incompatible schema.
func (c *Client) runMigrations(ctx context.Context) error {
	migrationsTable := c.tableRef("caphouse_schema_migrations")

	if err := c.conn.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s
		(
			id         String,
			applied_at DateTime DEFAULT now()
		)
		ENGINE = ReplacingMergeTree
		ORDER BY id`,
		migrationsTable,
	)); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	// Read all migration files sorted lexicographically.
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	if len(entries) == 0 {
		return nil
	}

	// Derive the expected (latest) version from the last embedded file.
	expectedVersion := migrationID(entries[len(entries)-1].Name())

	// Query the current database version.
	var dbVersion string
	_ = c.conn.QueryRow(ctx, fmt.Sprintf(
		"SELECT id FROM %s ORDER BY id DESC LIMIT 1",
		migrationsTable,
	)).Scan(&dbVersion)

	if dbVersion > expectedVersion {
		return fmt.Errorf("database schema version %q is ahead of this client (expected %q); upgrade the client", dbVersion, expectedVersion)
	}
	if dbVersion == expectedVersion {
		return nil
	}

	// Apply pending migrations in order.
	for _, entry := range entries {
		id := migrationID(entry.Name())
		if id <= dbVersion {
			continue
		}

		sql, err := fs.ReadFile(migrationsFS, "migrations/"+entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		// Substitute {{ database }} with the actual database name.
		resolved := strings.ReplaceAll(string(sql), "{{ database }}", c.cfg.Database)

		// ClickHouse does not support multi-statement execution in a single
		// Exec call, so split on semicolons and execute each statement.
		for _, stmt := range splitStatements(resolved) {
			if err := c.conn.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("migration %s: %w", entry.Name(), err)
			}
		}

		if err := c.conn.Exec(ctx, fmt.Sprintf(
			"INSERT INTO %s (id) VALUES (?)", migrationsTable,
		), id); err != nil {
			return fmt.Errorf("record migration %s: %w", entry.Name(), err)
		}

		c.log.Info("applied migration", "id", id)
	}

	return nil
}

// migrationID returns the filename stem without the .sql extension.
func migrationID(filename string) string {
	return strings.TrimSuffix(filename, ".sql")
}

// splitStatements splits a SQL string on semicolons, returning non-empty
// trimmed statements. This is intentionally simple: migration files must not
// contain semicolons inside string literals or comments.
func splitStatements(sql string) []string {
	parts := strings.Split(sql, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" && !isComment(p) {
			out = append(out, p)
		}
	}
	return out
}

// isComment returns true if s consists entirely of SQL line comments (-- ...).
func isComment(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "--") {
			return false
		}
	}
	return true
}
