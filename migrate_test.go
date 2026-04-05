package caphouse

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

var migrationNameRe = regexp.MustCompile(`^\d{14}_[0-9a-f]{7}_[a-z0-9_]+\.sql$`)

// TestMigrationFileNaming verifies that every migration file follows the
// required YYYYMMDDHHMMSS_XXXXXXX_description.sql convention and contains
// at least one non-comment SQL statement.
func TestMigrationFileNaming(t *testing.T) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			t.Errorf("unexpected non-.sql file in migrations/: %s", name)
			continue
		}
		if name == ".keep.sql" {
			continue // placeholder, not a real migration
		}
		if !migrationNameRe.MatchString(name) {
			t.Errorf("migration %s does not match YYYYMMDDHHMMSS_XXXXXXX_description.sql", name)
		}

		sql, err := fs.ReadFile(migrationsFS, "migrations/"+name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if len(splitStatements(string(sql))) == 0 {
			t.Errorf("migration %s contains no executable SQL statements", name)
		}
	}
}

// TestMigrationOrdering verifies that migration IDs sort strictly, with no
// duplicates — a requirement for correct incremental application.
func TestMigrationOrdering(t *testing.T) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	var ids []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") || name == ".keep.sql" {
			continue
		}
		ids = append(ids, migrationID(name))
	}

	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Errorf("migration ordering broken: %q is not strictly after %q", ids[i], ids[i-1])
		}
	}
}

func TestSplitStatements(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single statement",
			input: "SELECT 1",
			want:  []string{"SELECT 1"},
		},
		{
			name:  "trailing semicolon",
			input: "SELECT 1;",
			want:  []string{"SELECT 1"},
		},
		{
			name:  "two statements",
			input: "SELECT 1;\nSELECT 2",
			want:  []string{"SELECT 1", "SELECT 2"},
		},
		{
			name:  "comment only",
			input: "-- just a comment\n-- another",
			want:  nil,
		},
		{
			name:  "comment between statements",
			input: "SELECT 1;\n-- comment\n;SELECT 2",
			want:  []string{"SELECT 1", "SELECT 2"},
		},
		{
			name:  "whitespace only segments",
			input: "SELECT 1;   ;SELECT 2",
			want:  []string{"SELECT 1", "SELECT 2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitStatements(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d statements, want %d: %v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("stmt[%d]: got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestMigrationID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"20260404123000_abc1234_init.sql", "20260404123000_abc1234_init"},
		{"20260404123000_abc1234_init", "20260404123000_abc1234_init"},
		{".keep.sql", ".keep"},
	}
	for _, tc := range cases {
		if got := migrationID(tc.in); got != tc.want {
			t.Errorf("migrationID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
