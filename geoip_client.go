package caphouse

import (
	"context"

	"github.com/cochaviz/caphouse/geoip"
)

// InitGeoIP creates/refreshes the city and ASN dictionaries in ClickHouse.
// Any source URL left empty skips that dictionary.
func (c *Client) InitGeoIP(ctx context.Context, cfg geoip.InitConfig) error {
	return geoip.Init(ctx, c.conn, cfg)
}

// GeoIPLookupBatch resolves country, city, ASN and org for a list of IPs.
// Missing dictionaries return empty fields rather than an error.
func (c *Client) GeoIPLookupBatch(ctx context.Context, ips []string) (map[string]geoip.GeoInfo, error) {
	return geoip.LookupBatch(ctx, c.conn, ips)
}
