// caphouse-sanitize reads a PCAP (or all PCAPs in a folder) and writes a
// sanitized copy in which every public IPv4, IPv6, and MAC address has been
// replaced with a deterministic pseudonym.
//
// Determinism means:
//   - The same input address always maps to the same output address within one
//     run (so packet relationships are preserved, even across files).
//   - Different seeds produce entirely different mappings (default: random).
//
// Usage:
//
//	caphouse-sanitize [--seed HEX] [--in FILE|DIR] [--out FILE|DIR]
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var seedHex string
	var inPath string
	var outPath string

	cmd := &cobra.Command{
		Use:   "caphouse-sanitize",
		Short: "Deterministically anonymize public IP and MAC addresses in a PCAP",
		Long: `Reads a PCAP file (or all *.pcap / *.pcapng files in a folder) and rewrites
every public IPv4, IPv6, and MAC address with a deterministic pseudonym derived
from an HMAC-SHA256 keyed with --seed. Private, loopback, link-local, and
multicast addresses are left unchanged.

The same seed always produces the same mapping, so packet relationships
(e.g. flows between two hosts) are preserved across all files in a batch.
The default seed is random, printed to stderr so you can reproduce the run.

Folder mode: --in and --out must both be directories (and must differ).
File names are preserved; the output directory is created if needed.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			seed, err := parseSeed(seedHex)
			if err != nil {
				return fmt.Errorf("--seed: %w", err)
			}
			m := newMapper(seed)
			return run(inPath, outPath, m)
		},
	}

	cmd.Flags().StringVar(&seedHex, "seed", "", "hex-encoded 32-byte HMAC seed (default: random)")
	cmd.Flags().StringVarP(&inPath, "in", "i", "", "input PCAP file or folder (default: stdin)")
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "output PCAP file or folder (default: stdout)")
	return cmd
}

// run dispatches to folder or single-file mode based on whether inPath is a
// directory. A shared mapper is passed to all calls so the same address maps
// to the same pseudonym across all files in a batch.
func run(inPath, outPath string, m *mapper) error {
	if inPath == "" {
		// stdin → stdout
		return sanitize(os.Stdin, os.Stdout, m)
	}

	info, err := os.Stat(inPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", inPath, err)
	}

	if !info.IsDir() {
		return runFile(inPath, outPath, m)
	}

	// Folder mode.
	if outPath == "" {
		return fmt.Errorf("--out is required when --in is a directory")
	}
	absIn, err := filepath.Abs(inPath)
	if err != nil {
		return fmt.Errorf("resolve input path: %w", err)
	}
	absOut, err := filepath.Abs(outPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	if absIn == absOut {
		return fmt.Errorf("input and output directories must differ: %s", absIn)
	}

	return runDir(absIn, absOut, m)
}

// runDir sanitizes all *.pcap and *.pcapng files in inDir, writing each to
// outDir under the same filename.
func runDir(inDir, outDir string, m *mapper) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	var pcaps []string
	for _, pattern := range []string{"*.pcap", "*.pcapng"} {
		matches, err := filepath.Glob(filepath.Join(inDir, pattern))
		if err != nil {
			return err
		}
		pcaps = append(pcaps, matches...)
	}
	if len(pcaps) == 0 {
		return fmt.Errorf("no *.pcap or *.pcapng files found in %s", inDir)
	}

	for _, src := range pcaps {
		dst := filepath.Join(outDir, filepath.Base(src))
		fmt.Fprintf(os.Stderr, "%s -> %s\n", src, dst)
		if err := runFile(src, dst, m); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(src), err)
		}
	}
	return nil
}

// runFile sanitizes a single PCAP file. If outPath is empty, writes to stdout.
func runFile(inPath, outPath string, m *mapper) error {
	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	var out io.WriteCloser
	if outPath == "" {
		out = os.Stdout
	} else {
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		out = f
	}
	defer out.Close()

	return sanitize(in, out, m)
}

// parseSeed decodes a hex seed or generates a random 32-byte key.
func parseSeed(hexStr string) ([]byte, error) {
	if hexStr == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate random seed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "seed: %s\n", hex.EncodeToString(key))
		return key, nil
	}
	key, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("seed must be exactly 32 bytes (64 hex chars), got %d bytes", len(key))
	}
	return key, nil
}
