package caphouse

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"caphouse/components"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

// CreateCapture inserts a capture row if it does not exist.
func (c *Client) CreateCapture(ctx context.Context, meta CaptureMeta) (uuid.UUID, error) {
	if meta.CaptureID == uuid.Nil {
		meta.CaptureID = uuid.New()
	}
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now()
	}
	if meta.Endianness == "" {
		meta.Endianness = "le"
	}
	if meta.TimeResolution == "" {
		meta.TimeResolution = "us"
	}
	if meta.Snaplen == 0 {
		meta.Snaplen = 65535
	}
	if meta.CodecVersion == 0 {
		meta.CodecVersion = components.CodecVersionV1
	}
	if meta.CodecProfile == "" {
		meta.CodecProfile = components.CodecProfileV1
	}

	query := fmt.Sprintf("SELECT capture_id FROM %s WHERE capture_id = ? LIMIT 1", c.capturesTable())
	var existing uuid.UUID
	if err := c.conn.QueryRow(ctx, query, meta.CaptureID).Scan(&existing); err == nil {
		return existing, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("check capture: %w", err)
	}

	rawHeader := meta.GlobalHeaderRaw
	if rawHeader == nil {
		rawHeader = []byte{}
	}

	insert := fmt.Sprintf(`INSERT INTO %s
(capture_id, sensor_id, created_at, endianness, snaplen, linktype, time_res, global_header_raw, codec_version, codec_profile)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, c.capturesTable())

	if err := c.conn.Exec(ctx, insert,
		meta.CaptureID,
		meta.SensorID,
		meta.CreatedAt,
		meta.Endianness,
		meta.Snaplen,
		meta.LinkType,
		meta.TimeResolution,
		rawHeader,
		meta.CodecVersion,
		meta.CodecProfile,
	); err != nil {
		return uuid.Nil, fmt.Errorf("insert capture: %w", err)
	}

	return meta.CaptureID, nil
}

// IngestPacket queues one packet for batch insert.
func (c *Client) IngestPacket(ctx context.Context, linkType uint32, p Packet) error {
	normalizePacket(&p)
	encoded := EncodePacket(linkType, p)

	c.mu.Lock()
	c.batch = append(c.batch, encoded)
	shouldFlush := c.cfg.BatchSize > 0 && len(c.batch) >= c.cfg.BatchSize
	if !shouldFlush && c.cfg.FlushInterval > 0 && time.Since(c.lastFlush) >= c.cfg.FlushInterval {
		shouldFlush = true
	}
	if !shouldFlush {
		c.mu.Unlock()
		return nil
	}

	batch := c.batch
	c.batch = nil
	c.lastFlush = time.Now()
	c.mu.Unlock()
	return c.insertBatch(ctx, batch)
}

// Flush sends any buffered packets to ClickHouse.
func (c *Client) Flush(ctx context.Context) error {
	c.mu.Lock()
	if len(c.batch) == 0 {
		c.mu.Unlock()
		return nil
	}
	batch := c.batch
	c.batch = nil
	c.lastFlush = time.Now()
	c.mu.Unlock()
	return c.insertBatch(ctx, batch)
}

func (c *Client) insertBatch(ctx context.Context, batch []CodecPacket) error {
	if len(batch) == 0 {
		return nil
	}

	nucleusInsert := fmt.Sprintf(`INSERT INTO %s
(capture_id, packet_id, ts, incl_len, orig_len, components, tail_offset, frame_raw, frame_hash)
VALUES`, c.packetsTable())

	nucleusBatch, err := c.conn.PrepareBatch(ctx, nucleusInsert)
	if err != nil {
		return fmt.Errorf("prepare nucleus batch: %w", err)
	}

	var ethernetBatch chdriver.Batch
	var dot1qBatch chdriver.Batch
	var linuxSLLBatch chdriver.Batch
	var ipv4Batch chdriver.Batch
	var ipv4OptionsBatch chdriver.Batch
	var ipv6Batch chdriver.Batch
	var ipv6ExtBatch chdriver.Batch
	var tailBatch chdriver.Batch

	for _, p := range batch {
		if err := nucleusBatch.Append(
			p.Nucleus.CaptureID,
			p.Nucleus.PacketID,
			p.Nucleus.Timestamp,
			p.Nucleus.InclLen,
			p.Nucleus.OrigLen,
			p.Nucleus.Components,
			p.Nucleus.TailOffset,
			p.Nucleus.FrameRaw,
			p.Nucleus.FrameHash,
		); err != nil {
			return fmt.Errorf("append nucleus: %w", err)
		}

		for _, component := range p.Components {
			switch component := component.(type) {
			case *components.EthernetComponent:
				if ethernetBatch == nil {
					stmt := fmt.Sprintf(`INSERT INTO %s
(capture_id, packet_id, codec_version, src_mac, dst_mac, eth_type, eth_len)
VALUES`, c.ethernetTable())
					ethernetBatch, err = c.conn.PrepareBatch(ctx, stmt)
					if err != nil {
						return fmt.Errorf("prepare ethernet batch: %w", err)
					}
				}
				if err := ethernetBatch.Append(
					component.CaptureID,
					component.PacketID,
					component.CodecVersion,
					component.SrcMAC,
					component.DstMAC,
					component.EtherType,
					component.Length,
				); err != nil {
					return fmt.Errorf("append ethernet: %w", err)
				}
			case *components.Dot1QComponent:
				if dot1qBatch == nil {
					stmt := fmt.Sprintf(`INSERT INTO %s
(capture_id, packet_id, codec_version, tag_index, priority, drop_eligible, vlan_id, eth_type)
VALUES`, c.dot1qTable())
					dot1qBatch, err = c.conn.PrepareBatch(ctx, stmt)
					if err != nil {
						return fmt.Errorf("prepare dot1q batch: %w", err)
					}
				}
				if err := dot1qBatch.Append(
					component.CaptureID,
					component.PacketID,
					component.CodecVersion,
					component.TagIndex,
					component.Priority,
					component.DropEligible,
					component.VLANID,
					component.EtherType,
				); err != nil {
					return fmt.Errorf("append dot1q: %w", err)
				}
			case *components.LinuxSLLComponent:
				if linuxSLLBatch == nil {
					stmt := fmt.Sprintf(`INSERT INTO %s
(capture_id, packet_id, codec_version, l2_len, l2_hdr_raw)
VALUES`, c.linuxSLLTable())
					linuxSLLBatch, err = c.conn.PrepareBatch(ctx, stmt)
					if err != nil {
						return fmt.Errorf("prepare linux sll batch: %w", err)
					}
				}
				if err := linuxSLLBatch.Append(
					component.CaptureID,
					component.PacketID,
					component.CodecVersion,
					component.L2Len,
					component.L2HdrRaw,
				); err != nil {
					return fmt.Errorf("append linux sll: %w", err)
				}
			case *components.IPv4Component:
				if ipv4Batch == nil {
					stmt := fmt.Sprintf(`INSERT INTO %s
(capture_id, packet_id, ts, codec_version, parsed_ok, parse_err, protocol,
 src_ip_v4, dst_ip_v4, ipv4_ihl, ipv4_tos, ipv4_total_len, ipv4_id, ipv4_flags,
 ipv4_frag_offset, ipv4_ttl, ipv4_hdr_checksum)
VALUES`, c.ipv4Table())
					ipv4Batch, err = c.conn.PrepareBatch(ctx, stmt)
					if err != nil {
						return fmt.Errorf("prepare ipv4 batch: %w", err)
					}
				}
				if err := ipv4Batch.Append(
					component.CaptureID,
					component.PacketID,
					component.Timestamp,
					component.CodecVersion,
					component.ParsedOK,
					shortErr(component.ParseErr),
					component.Protocol,
					ipv4String(component.SrcIP4),
					ipv4String(component.DstIP4),
					component.IPv4IHL,
					component.IPv4TOS,
					component.IPv4TotalLen,
					component.IPv4ID,
					component.IPv4Flags,
					component.IPv4FragOffset,
					component.IPv4TTL,
					component.IPv4HdrChecksum,
				); err != nil {
					return fmt.Errorf("append ipv4: %w", err)
				}
			case *components.IPv4OptionsComponent:
				if ipv4OptionsBatch == nil {
					stmt := fmt.Sprintf(`INSERT INTO %s
(capture_id, packet_id, codec_version, options_raw)
VALUES`, c.ipv4OptionsTable())
					ipv4OptionsBatch, err = c.conn.PrepareBatch(ctx, stmt)
					if err != nil {
						return fmt.Errorf("prepare ipv4 options batch: %w", err)
					}
				}
				if err := ipv4OptionsBatch.Append(
					component.CaptureID,
					component.PacketID,
					component.CodecVersion,
					component.OptionsRaw,
				); err != nil {
					return fmt.Errorf("append ipv4 options: %w", err)
				}
			case *components.IPv6Component:
				if ipv6Batch == nil {
					stmt := fmt.Sprintf(`INSERT INTO %s
(capture_id, packet_id, ts, codec_version, parsed_ok, parse_err, protocol,
 src_ip_v6, dst_ip_v6, ipv6_payload_len, ipv6_hop_limit, ipv6_flow_label, ipv6_traffic_class)
VALUES`, c.ipv6Table())
					ipv6Batch, err = c.conn.PrepareBatch(ctx, stmt)
					if err != nil {
						return fmt.Errorf("prepare ipv6 batch: %w", err)
					}
				}
				if err := ipv6Batch.Append(
					component.CaptureID,
					component.PacketID,
					component.Timestamp,
					component.CodecVersion,
					component.ParsedOK,
					shortErr(component.ParseErr),
					component.Protocol,
					ipv6String(component.SrcIP6),
					ipv6String(component.DstIP6),
					component.IPv6PayloadLen,
					component.IPv6HopLimit,
					component.IPv6FlowLabel,
					component.IPv6TrafficClass,
				); err != nil {
					return fmt.Errorf("append ipv6: %w", err)
				}
			case *components.IPv6ExtComponent:
				if ipv6ExtBatch == nil {
					stmt := fmt.Sprintf(`INSERT INTO %s
(capture_id, packet_id, codec_version, ext_index, ext_type, ext_raw)
VALUES`, c.ipv6ExtTable())
					ipv6ExtBatch, err = c.conn.PrepareBatch(ctx, stmt)
					if err != nil {
						return fmt.Errorf("prepare ipv6 ext batch: %w", err)
					}
				}
				if err := ipv6ExtBatch.Append(
					component.CaptureID,
					component.PacketID,
					component.CodecVersion,
					component.ExtIndex,
					component.ExtType,
					component.ExtRaw,
				); err != nil {
					return fmt.Errorf("append ipv6 ext: %w", err)
				}
			case *components.RawTailComponent:
				if tailBatch == nil {
					stmt := fmt.Sprintf(`INSERT INTO %s
(capture_id, packet_id, tail_offset, bytes)
VALUES`, c.rawTailTable())
					tailBatch, err = c.conn.PrepareBatch(ctx, stmt)
					if err != nil {
						return fmt.Errorf("prepare raw tail batch: %w", err)
					}
				}
				if err := tailBatch.Append(
					component.CaptureID,
					component.PacketID,
					component.TailOffset,
					component.Bytes,
				); err != nil {
					return fmt.Errorf("append raw tail: %w", err)
				}
			}
		}
	}

	if err := nucleusBatch.Send(); err != nil {
		return fmt.Errorf("send nucleus batch: %w", err)
	}
	if ethernetBatch != nil {
		if err := ethernetBatch.Send(); err != nil {
			return fmt.Errorf("send ethernet batch: %w", err)
		}
	}
	if dot1qBatch != nil {
		if err := dot1qBatch.Send(); err != nil {
			return fmt.Errorf("send dot1q batch: %w", err)
		}
	}
	if linuxSLLBatch != nil {
		if err := linuxSLLBatch.Send(); err != nil {
			return fmt.Errorf("send linux sll batch: %w", err)
		}
	}
	if ipv4Batch != nil {
		if err := ipv4Batch.Send(); err != nil {
			return fmt.Errorf("send ipv4 batch: %w", err)
		}
	}
	if ipv4OptionsBatch != nil {
		if err := ipv4OptionsBatch.Send(); err != nil {
			return fmt.Errorf("send ipv4 options batch: %w", err)
		}
	}
	if ipv6Batch != nil {
		if err := ipv6Batch.Send(); err != nil {
			return fmt.Errorf("send ipv6 batch: %w", err)
		}
	}
	if ipv6ExtBatch != nil {
		if err := ipv6ExtBatch.Send(); err != nil {
			return fmt.Errorf("send ipv6 ext batch: %w", err)
		}
	}
	if tailBatch != nil {
		if err := tailBatch.Send(); err != nil {
			return fmt.Errorf("send raw tail batch: %w", err)
		}
	}
	return nil
}

func normalizePacket(p *Packet) {
	if p.InclLen == 0 {
		p.InclLen = uint32(len(p.Frame))
	}
	if p.InclLen != uint32(len(p.Frame)) {
		p.InclLen = uint32(len(p.Frame))
	}
	if p.OrigLen == 0 || p.OrigLen < p.InclLen {
		p.OrigLen = p.InclLen
	}
}

func shortErr(msg string) string {
	if len(msg) <= 200 {
		return msg
	}
	return msg[:200]
}

func ipv4String(addr netip.Addr) string {
	if addr.IsValid() && addr.Is4() {
		return addr.String()
	}
	return "0.0.0.0"
}

func ipv6String(addr netip.Addr) string {
	if addr.IsValid() && addr.Is6() {
		return addr.String()
	}
	return "::"
}
