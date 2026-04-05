package caphouse

import (
	"context"
	"fmt"
	"strings"

	"caphouse/components"
)

func (c *Client) managedTableNames() []string {
	tables := []string{"pcap_captures", "pcap_packets"}
	seen := map[string]struct{}{
		"pcap_captures": {},
		"pcap_packets":  {},
	}
	for _, kind := range components.KnownComponentKinds {
		name := components.ComponentTable(components.ComponentFactories[kind]())
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		tables = append(tables, name)
	}
	for _, name := range []string{"stream_captures", "stream_http"} {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		tables = append(tables, name)
	}
	return tables
}

// nonPacketTableNames returns all managed table names except pcap_packets,
// used when cleaning up metadata for sessions whose packets have been dropped.
func (c *Client) nonPacketTableNames() []string {
	all := c.managedTableNames()
	out := make([]string, 0, len(all)-1)
	for _, name := range all {
		if name != "pcap_packets" {
			out = append(out, name)
		}
	}
	return out
}

func (c *Client) storageUsageBytes(ctx context.Context) (uint64, error) {
	tables := c.managedTableNames()
	quoted := make([]string, 0, len(tables))
	for _, table := range tables {
		quoted = append(quoted, fmt.Sprintf("'%s'", table))
	}

	query := fmt.Sprintf(`
		SELECT toUInt64(ifNull(sum(data_compressed_bytes), 0))
		FROM system.parts
		WHERE database = ?
		  AND active = 1
		  AND table IN (%s)`,
		strings.Join(quoted, ", "),
	)

	var total uint64
	if err := c.conn.QueryRow(ctx, query, c.cfg.Database).Scan(&total); err != nil {
		return 0, fmt.Errorf("query system.parts: %w", err)
	}
	return total, nil
}

// partitionCandidates returns pcap_packets partition names (date strings,
// e.g. "2024-01-01") ordered oldest-first.
func (c *Client) partitionCandidates(ctx context.Context) ([]string, error) {
	rows, err := c.conn.Query(ctx,
		"SELECT DISTINCT partition FROM system.parts WHERE database = ? AND table = 'pcap_packets' AND active = 1 ORDER BY partition ASC",
		c.cfg.Database,
	)
	if err != nil {
		return nil, fmt.Errorf("query partitions: %w", err)
	}
	defer rows.Close()

	var partitions []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("scan partition: %w", err)
		}
		partitions = append(partitions, p)
	}
	return partitions, rows.Err()
}

// sessionIDsInPartition returns the session IDs that have packets in the
// given partition. Called before dropping the partition so we know which
// sessions to clean up from other tables afterward.
func (c *Client) sessionIDsInPartition(ctx context.Context, partition string) ([]uint64, error) {
	rows, err := c.conn.Query(ctx, fmt.Sprintf(
		"SELECT DISTINCT session_id FROM %s WHERE toDate(intDiv(ts, 1000000000)) = ?",
		c.packetsTable(),
	), partition)
	if err != nil {
		return nil, fmt.Errorf("query sessions in partition %s: %w", partition, err)
	}
	defer rows.Close()

	var ids []uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan session id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// dropPacketsPartition drops a partition from pcap_packets. The partition
// argument is a date string (e.g. "2024-01-01") from system.parts.
// Partition drops are reflected immediately in system.parts.
func (c *Client) dropPacketsPartition(ctx context.Context, partition string) error {
	query := fmt.Sprintf("ALTER TABLE %s DROP PARTITION '%s'", c.packetsTable(), partition)
	if err := c.conn.Exec(ctx, query); err != nil {
		return fmt.Errorf("drop partition %s: %w", partition, err)
	}
	return nil
}

// deleteOrphanedSessions removes rows from all managed tables except
// pcap_packets for sessions that no longer have any packets. Sessions that
// span multiple partitions are left intact until their last partition is
// dropped.
func (c *Client) deleteOrphanedSessions(ctx context.Context, candidateIDs []uint64) error {
	if len(candidateIDs) == 0 {
		return nil
	}

	// Build an IN list to check which of the candidate sessions still have packets.
	inList := make([]string, len(candidateIDs))
	for i, id := range candidateIDs {
		inList[i] = fmt.Sprintf("%d", id)
	}
	inSQL := strings.Join(inList, ", ")

	rows, err := c.conn.Query(ctx, fmt.Sprintf(
		"SELECT DISTINCT session_id FROM %s WHERE session_id IN (%s)",
		c.packetsTable(), inSQL,
	))
	if err != nil {
		return fmt.Errorf("check remaining sessions: %w", err)
	}
	defer rows.Close()

	remaining := make(map[uint64]struct{})
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan remaining session: %w", err)
		}
		remaining[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	var orphaned []string
	for _, id := range candidateIDs {
		if _, ok := remaining[id]; !ok {
			orphaned = append(orphaned, fmt.Sprintf("%d", id))
		}
	}
	if len(orphaned) == 0 {
		return nil
	}

	orphanSQL := strings.Join(orphaned, ", ")
	for _, table := range c.nonPacketTableNames() {
		query := fmt.Sprintf("DELETE FROM %s WHERE session_id IN (%s)", c.tableRef(table), orphanSQL)
		if err := c.conn.Exec(ctx, query); err != nil {
			return fmt.Errorf("delete orphaned sessions from %s: %w", table, err)
		}
	}
	return nil
}

// enforceStorageCap prunes oldest packet partitions until managed storage drops
// under MaxStorageBytes.
//
// protectedSessionIDs are sessions currently being appended to. This matters
// for append paths like IngestPacket: even when pruning runs before the new
// packet is written, the target session may already exist in pcap_packets and
// therefore be a pruning candidate. Protecting that session preserves the
// "keep the newest/active capture" behavior while still dropping older data.
func (c *Client) enforceStorageCap(ctx context.Context, protectedSessionIDs ...uint64) error {
	if c.cfg.MaxStorageBytes == 0 {
		return nil
	}

	protected := make(map[uint64]bool, len(protectedSessionIDs))
	for _, id := range protectedSessionIDs {
		if id != 0 {
			protected[id] = true
		}
	}

	before, err := c.storageUsageBytes(ctx)
	if err != nil {
		return fmt.Errorf("measure storage usage: %w", err)
	}
	if before <= c.cfg.MaxStorageBytes {
		return nil
	}

	candidates, err := c.partitionCandidates(ctx)
	if err != nil {
		return err
	}

	used := before
	droppedPartitions := make([]string, 0, len(candidates))
	for _, partition := range candidates {
		if used <= c.cfg.MaxStorageBytes {
			break
		}

		// I hope sessionIDs doesn't grow too large?
		sessionIDs, err := c.sessionIDsInPartition(ctx, partition)
		if err != nil {
			return err
		}

		skipProtected := false
		for _, id := range sessionIDs {
			if protected[id] {
				skipProtected = true
				break
			}
		}
		if skipProtected {
			c.log.Debug("skipping protected partition during storage-cap pruning",
				"partition", partition,
			)
			continue
		}

		if err := c.dropPacketsPartition(ctx, partition); err != nil {
			return err
		}

		// Partition drops are immediately reflected in system.parts, so
		// re-measuring here tells us whether we need to continue.
		used, err = c.storageUsageBytes(ctx)
		if err != nil {
			return fmt.Errorf("measure storage usage after partition drop: %w", err)
		}
		droppedPartitions = append(droppedPartitions, partition)
		c.log.Info("dropped partition to enforce storage cap",
			"partition", partition,
			"cap_bytes", c.cfg.MaxStorageBytes,
			"used_bytes_after", used,
		)

		if err := c.deleteOrphanedSessions(ctx, sessionIDs); err != nil {
			return err
		}
	}

	if used > c.cfg.MaxStorageBytes {
		c.log.Warn("storage cap remains exceeded after pruning",
			"cap_bytes", c.cfg.MaxStorageBytes,
			"used_bytes", used,
		)
		return nil
	}

	c.log.Info("storage cap enforced",
		"cap_bytes", c.cfg.MaxStorageBytes,
		"used_bytes_before", before,
		"used_bytes_after", used,
		"dropped_partitions", droppedPartitions,
	)
	return nil
}
