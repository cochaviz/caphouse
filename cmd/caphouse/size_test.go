package main

import "testing"

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		input string
		want  uint64
	}{
		{input: "42", want: 42},
		{input: "42B", want: 42},
		{input: "336b", want: 42},
		{input: "10GIB", want: 10 << 30},
		{input: "10Gib", want: (10 << 30) / 8},
		{input: "500MB", want: 500_000_000},
		{input: "500Mb", want: 62_500_000},
		{input: "1TiB", want: 1 << 40},
		{input: "1.5kiB", want: 1536},
		{input: "1.5Kib", want: 192},
	}

	for _, tc := range tests {
		got, err := parseByteSize(tc.input)
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("%q: got %d want %d", tc.input, got, tc.want)
		}
	}
}

func TestParseByteSizeInvalid(t *testing.T) {
	for _, input := range []string{"", "abc", "10XB", "12.3.4MB", "1b", "0.5B"} {
		if _, err := parseByteSize(input); err == nil {
			t.Fatalf("%q: expected error", input)
		}
	}
}
