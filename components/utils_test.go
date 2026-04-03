package components

import (
	"context"
	"reflect"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type fakeBatch struct {
	appended [][]any
}

func (b *fakeBatch) Abort() error { return nil }
func (b *fakeBatch) Flush() error { return nil }
func (b *fakeBatch) Send() error  { return nil }
func (b *fakeBatch) IsSent() bool { return false }
func (b *fakeBatch) Rows() int    { return len(b.appended) }
func (b *fakeBatch) Append(v ...any) error {
	row := make([]any, len(v))
	copy(row, v)
	b.appended = append(b.appended, row)
	return nil
}
func (b *fakeBatch) AppendStruct(v any) error    { return nil }
func (b *fakeBatch) Columns() []column.Interface { return nil }
func (b *fakeBatch) Column(int) driver.BatchColumn {
	return fakeBatchColumn{}
}

type fakeBatchColumn struct{}

func (fakeBatchColumn) Append(any) error    { return nil }
func (fakeBatchColumn) AppendRow(any) error { return nil }

type fakeConn struct {
	query string
	batch *fakeBatch
}

func (c *fakeConn) Contributors() []string { return nil }
func (c *fakeConn) ServerVersion() (*driver.ServerVersion, error) {
	return nil, nil
}
func (c *fakeConn) Select(ctx context.Context, dest any, query string, args ...any) error {
	return nil
}
func (c *fakeConn) Query(ctx context.Context, query string, args ...any) (driver.Rows, error) {
	return nil, nil
}
func (c *fakeConn) QueryRow(ctx context.Context, query string, args ...any) driver.Row {
	return nil
}
func (c *fakeConn) PrepareBatch(ctx context.Context, query string, opts ...driver.PrepareBatchOption) (driver.Batch, error) {
	c.query = query
	if c.batch == nil {
		c.batch = &fakeBatch{}
	}
	return c.batch, nil
}
func (c *fakeConn) Exec(ctx context.Context, query string, args ...any) error { return nil }
func (c *fakeConn) AsyncInsert(ctx context.Context, query string, wait bool, args ...any) error {
	return nil
}
func (c *fakeConn) Ping(context.Context) error { return nil }
func (c *fakeConn) Stats() driver.Stats        { return driver.Stats{} }
func (c *fakeConn) Close() error               { return nil }

type testComponent struct {
	CaptureID string  `ch:"capture_id"`
	PacketID  uint64  `ch:"packet_id"`
	Optional  *string `ch:"optional"`
	Skip      string  `ch:"-"`
	hidden    string
}

func (testComponent) Kind() uint    { return 0 }
func (testComponent) Order() uint   { return 0 }
func (testComponent) Index() uint16 { return 0 }
func (testComponent) Name() string  { return "test_table" }
func (c testComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}
func (c testComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}
func (testComponent) SetIndex(uint16)                  {}
func (testComponent) LayerSize() int                   { return 0 }
func (testComponent) ApplyNucleus(PacketNucleus)       {}
func (testComponent) Reconstruct(*DecodeContext) error { return nil }

type otherComponent struct {
	ID string `ch:"id"`
}

func (otherComponent) Kind() uint    { return 0 }
func (otherComponent) Order() uint   { return 0 }
func (otherComponent) Index() uint16 { return 0 }
func (otherComponent) Name() string  { return "other_table" }
func (c otherComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}
func (c otherComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}
func (otherComponent) SetIndex(uint16)                  {}
func (otherComponent) LayerSize() int                   { return 0 }
func (otherComponent) ApplyNucleus(PacketNucleus)       {}
func (otherComponent) Reconstruct(*DecodeContext) error { return nil }

func TestCreateBatchBuildsQueryAndAppends(t *testing.T) {
	ctx := context.Background()
	conn := &fakeConn{}

	opt := "value"
	comp1 := testComponent{
		CaptureID: "cap-1",
		PacketID:  42,
		Optional:  &opt,
		Skip:      "skip",
		hidden:    "hidden",
	}
	comp2 := testComponent{
		CaptureID: "cap-2",
		PacketID:  43,
		Optional:  nil,
	}

	batch, err := CreateBatch(ctx, conn, []clickhouseWriter{comp1, comp2})
	if err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}
	if batch == nil {
		t.Fatalf("CreateBatch returned nil batch")
	}

	wantQuery := "INSERT INTO pcap_test_table (capture_id, packet_id, optional) VALUES (?, ?, ?)"
	if conn.query != wantQuery {
		t.Fatalf("query mismatch: got %q want %q", conn.query, wantQuery)
	}

	wantRows := [][]any{
		{"cap-1", uint64(42), &opt},
		{"cap-2", uint64(43), (*string)(nil)},
	}
	if conn.batch.Rows() != len(wantRows) {
		t.Fatalf("rows mismatch: got %d want %d", conn.batch.Rows(), len(wantRows))
	}
	if !reflect.DeepEqual(conn.batch.appended, wantRows) {
		t.Fatalf("appended rows mismatch: got %#v want %#v", conn.batch.appended, wantRows)
	}
}

func TestCreateBatchRejectsEmptySlice(t *testing.T) {
	_, err := CreateBatch(context.Background(), &fakeConn{}, nil)
	if err == nil {
		t.Fatalf("expected error for empty components")
	}
}

func TestCreateBatchRejectsTableMismatch(t *testing.T) {
	_, err := CreateBatch(context.Background(), &fakeConn{}, []clickhouseWriter{
		testComponent{CaptureID: "cap"},
		otherComponent{ID: "id"},
	})
	if err == nil {
		t.Fatalf("expected error for mismatched tables")
	}
}

func TestSplatClickhouseColumnsPointer(t *testing.T) {
	opt := "value"
	comp := &testComponent{
		CaptureID: "cap",
		PacketID:  9,
		Optional:  &opt,
		Skip:      "skip",
		hidden:    "hidden",
	}

	values, err := GetClickhouseValuesFrom(comp)
	if err != nil {
		t.Fatalf("SplatClickhouseColumns: %v", err)
	}
	want := []any{"cap", uint64(9), &opt}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("values mismatch: got %#v want %#v", values, want)
	}
}
