package caphouse

import (
	"reflect"
	"testing"

	"caphouse/components"
)

func TestNestedComponentFields(t *testing.T) {
	comp := &components.GREComponent{
		Protocol:   0x86dd,
		Flags:      1,
		Version:    0,
		Checksum:   7,
		Key:        9,
		Seq:        11,
		LayerIndex: 2,
	}

	name, fields, err := nestedComponentFields(comp)
	if err != nil {
		t.Fatalf("nestedComponentFields: %v", err)
	}
	if name != "gre" {
		t.Fatalf("name = %q, want gre", name)
	}

	want := map[string]any{
		"gre_protocol":    uint16(0x86dd),
		"gre_flags":       uint8(1),
		"gre_version":     uint8(0),
		"gre_checksum":    uint16(7),
		"gre_key":         uint32(9),
		"gre_seq":         uint32(11),
		"gre_layer_index": uint16(2),
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("fields mismatch:\n got: %#v\nwant: %#v", fields, want)
	}
}

func TestAppendNestedComponent(t *testing.T) {
	got := map[string]any{}
	appendNestedComponent(got, "dot1q", map[string]any{"dot1q_vlan_id": uint16(100)})
	appendNestedComponent(got, "dot1q", map[string]any{"dot1q_vlan_id": uint16(200)})

	items, ok := got["dot1q"].([]map[string]any)
	if !ok {
		t.Fatalf("dot1q type = %T, want []map[string]any", got["dot1q"])
	}
	if len(items) != 2 {
		t.Fatalf("len(dot1q) = %d, want 2", len(items))
	}
}
