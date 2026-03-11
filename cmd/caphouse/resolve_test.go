package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveInputFiles_ExplicitStdin(t *testing.T) {
	// Explicit "-" → stdin passthrough.
	got, err := resolveInputFiles([]string{"-"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "-" {
		t.Fatalf("want [\"-\"], got %v", got)
	}
}

func TestResolveInputFiles_StdinWithOthers(t *testing.T) {
	_, err := resolveInputFiles([]string{"-", "a.pcap"})
	if err == nil {
		t.Fatal("expected error when mixing stdin with file paths")
	}
}

func TestResolveInputFiles_NoMatch(t *testing.T) {
	_, err := resolveInputFiles([]string{"/nonexistent/path/no*.pcap"})
	if err == nil {
		t.Fatal("expected error for pattern matching no files")
	}
}

func TestResolveInputFiles_LiteralPaths(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.pcap")
	b := filepath.Join(dir, "b.pcap")
	if err := os.WriteFile(a, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveInputFiles([]string{a, b})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("want [%s %s], got %v", a, b, got)
	}
}

func TestResolveInputFiles_GlobExpansion(t *testing.T) {
	dir := t.TempDir()
	names := []string{"ring0.pcap", "ring1.pcap", "ring2.pcap", "other.txt"}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := resolveInputFiles([]string{filepath.Join(dir, "ring*.pcap")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 files, got %d: %v", len(got), got)
	}
	// filepath.Glob returns sorted results.
	for i, want := range []string{"ring0.pcap", "ring1.pcap", "ring2.pcap"} {
		if filepath.Base(got[i]) != want {
			t.Errorf("got[%d] = %s, want %s", i, filepath.Base(got[i]), want)
		}
	}
}

func TestResolveInputFiles_MultipleGlobs(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a.pcap", "b.pcap", "c.pcapng"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := resolveInputFiles([]string{
		filepath.Join(dir, "*.pcap"),
		filepath.Join(dir, "*.pcapng"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 files, got %d: %v", len(got), got)
	}
}

func TestResolveInputFiles_Deduplication(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.pcap")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Same file listed twice via literal + glob.
	got, err := resolveInputFiles([]string{f, filepath.Join(dir, "*.pcap")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 (deduplicated), got %d: %v", len(got), got)
	}
}
