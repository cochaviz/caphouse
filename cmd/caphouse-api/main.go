package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"caphouse"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var dsn string
	var addr string
	var debug bool

	cmd := &cobra.Command{
		Use:          "caphouse-api",
		Short:        "CapHouse REST API server",
		Long:         "HTTP REST API for querying and exporting network captures stored in ClickHouse.\n\nOpenAPI documentation is served at /docs and the raw schema at /openapi.json.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dsn == "" {
				dsn = os.Getenv("CAPHOUSE_DSN")
			}
			if dsn == "" {
				return fmt.Errorf("dsn is required (--dsn or CAPHOUSE_DSN)")
			}

			level := slog.LevelInfo
			if debug {
				level = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

			ctx := context.Background()
			client, err := caphouse.New(ctx, caphouse.Config{
				DSN:    dsn,
				Logger: logger,
				Debug:  debug,
			})
			if err != nil {
				return fmt.Errorf("connect to ClickHouse: %w", err)
			}
			defer client.Close()

			r := chi.NewRouter()
			r.Use(middleware.RealIP)
			r.Use(middleware.Logger)
			r.Use(middleware.Recoverer)
			r.Use(middleware.Timeout(5 * time.Minute))

			config := huma.DefaultConfig("CapHouse API", "1.0.0")
			config.Info.Description = "REST API for querying and exporting network packet captures stored in ClickHouse. " +
				"Use the search endpoint to filter packets by tcpdump-style expressions and retrieve JSON-formatted results, " +
				"or the export endpoints to reconstruct a classic PCAP file."

			api := humachi.New(r, config)

			registerHandlers(api, client)

			logger.Info("starting server", "addr", addr)
			logger.Info("OpenAPI docs available", "url", "http://"+addr+"/docs")
			return http.ListenAndServe(addr, r)
		},
	}

	cmd.Flags().StringVarP(&dsn, "dsn", "d", "", "ClickHouse DSN, e.g. clickhouse://user:pass@host:9000/db (or CAPHOUSE_DSN)")
	cmd.Flags().StringVarP(&addr, "addr", "a", ":8080", "TCP address to listen on")
	cmd.Flags().BoolVar(&debug, "debug", false, "enable verbose ClickHouse driver logging")

	return cmd
}
