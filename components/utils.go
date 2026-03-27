package components

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

func copyBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func boolToUint8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

// clickhouseWriter is the minimal interface needed to INSERT a row into ClickHouse.
// It is satisfied by all registered Component types and by PacketNucleus.
type clickhouseWriter interface {
	Name() string
	ClickhouseColumns() ([]string, error)
	ClickhouseValues() ([]any, error)
}

// CreateBatch creates a batch for an array of components _of single type_ into a ClickHouse table.
// Unknown behavior for components of different types. (probably very bad)
func CreateBatch(
	ctx context.Context,
	conn clickhouse.Conn,
	components []clickhouseWriter,
) (chdriver.Batch, error) {
	if len(components) == 0 {
		return nil, fmt.Errorf("no components provided")
	}

	columns, err := components[0].ClickhouseColumns()
	if err != nil {
		return nil, err
	}

	table := "pcap_" + components[0].Name()
	for i := 1; i < len(components); i++ {
		if name := components[i].Name(); "pcap_"+name != table {
			return nil, fmt.Errorf("component table mismatch: %s != %s", name, components[0].Name())
		}
	}

	serializedColumns := "(" + strings.Join(columns, ", ") + ")"
	emptyColumns := []string{}

	// creates an array '?, ? ..., ?' of len(columns)
	for i := 0; i < len(columns); i++ {
		emptyColumns = append(emptyColumns, "?")
	}

	serializedEmptyColumns := "(" + strings.Join(emptyColumns, ", ") + ")"

	batch, err := conn.PrepareBatch(
		ctx,
		fmt.Sprintf("INSERT INTO %s %s VALUES %s", table, serializedColumns, serializedEmptyColumns),
	)
	if err != nil {
		return nil, err
	}
	for _, component := range components {
		vals, err := component.ClickhouseValues()
		if err != nil {
			return nil, err
		}
		err = batch.Append(vals...)
		if err != nil {
			return nil, err
		}
	}
	return batch, nil
}
