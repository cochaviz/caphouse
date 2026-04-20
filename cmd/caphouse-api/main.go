package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/cochaviz/caphouse"
	"github.com/cochaviz/caphouse/geoip"

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
	var geoipSource string
	var geoipSourceV6 string
	var asnSource string
	var asnSourceV6 string
	var anthropicKey string
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
			if geoipSource == "" {
				geoipSource = os.Getenv("CAPHOUSE_GEOIP_SOURCE")
			}
			if geoipSourceV6 == "" {
				geoipSourceV6 = os.Getenv("CAPHOUSE_GEOIP_SOURCE_V6")
			}
			if asnSource == "" {
				asnSource = os.Getenv("CAPHOUSE_ASN_SOURCE")
			}
			if asnSourceV6 == "" {
				asnSourceV6 = os.Getenv("CAPHOUSE_ASN_SOURCE_V6")
			}
			if anthropicKey == "" {
				anthropicKey = os.Getenv("ANTHROPIC_API_KEY")
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

			geoCfg := geoip.InitConfig{
				CityV4: geoipSource,
				CityV6: geoipSourceV6,
				ASNV4:  asnSource,
				ASNV6:  asnSourceV6,
			}
			if geoCfg.CityV4 != "" || geoCfg.CityV6 != "" || geoCfg.ASNV4 != "" || geoCfg.ASNV6 != "" {
				if geoip.DictionariesReady(ctx, client.Conn(), geoCfg) {
					logger.Info("geoip dictionaries already loaded, skipping init")
				} else {
					logger.Info("starting geoip init in background",
						"city_v4", geoCfg.CityV4, "city_v6", geoCfg.CityV6,
						"asn_v4", geoCfg.ASNV4, "asn_v6", geoCfg.ASNV6)
					go func() {
						if err := client.InitGeoIP(context.Background(), geoCfg); err != nil {
							logger.Warn("geoip init failed", "err", err)
							return
						}
						logger.Info("geoip dictionaries ready")
					}()
				}
			}

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

			registerAllHandlers(api, client, anthropicKey)

			logger.Info("starting server", "addr", addr)
			logger.Info("OpenAPI docs available", "url", "http://"+addr+"/docs")
			return http.ListenAndServe(addr, r)
		},
	}

	cmd.Flags().StringVarP(&dsn, "dsn", "d", "", "ClickHouse DSN, e.g. clickhouse://user:pass@host:9000/db (or CAPHOUSE_DSN)")
	cmd.Flags().StringVarP(&addr, "addr", "a", ":8080", "TCP address to listen on")
	cmd.Flags().StringVar(&geoipSource, "geoip-source", "", "URL of a DB-IP city IPv4 CSV (or CAPHOUSE_GEOIP_SOURCE)")
	cmd.Flags().StringVar(&geoipSourceV6, "geoip-source-v6", "", "URL of a DB-IP city IPv6 CSV (or CAPHOUSE_GEOIP_SOURCE_V6)")
	cmd.Flags().StringVar(&asnSource, "asn-source", "", "URL of a DB-IP ASN IPv4 CSV (or CAPHOUSE_ASN_SOURCE)")
	cmd.Flags().StringVar(&asnSourceV6, "asn-source-v6", "", "URL of a DB-IP ASN IPv6 CSV (or CAPHOUSE_ASN_SOURCE_V6)")
	cmd.Flags().StringVar(&anthropicKey, "anthropic-key", "", "Anthropic API key for AI SQL generation (or ANTHROPIC_API_KEY)")
	cmd.Flags().BoolVar(&debug, "debug", false, "enable verbose ClickHouse driver logging")

	return cmd
}
