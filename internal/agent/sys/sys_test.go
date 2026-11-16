package sys

import "testing"

func TestParseProcAddr(t *testing.T) {
	a, p, err := parseProcAddr("0100007F:0016")
	if err != nil || a.String() != "127.0.0.1" || p != 22 {
		t.Fatalf("%v %v %v", a, p, err)
	}
	a, _, _ = parseProcAddr("0000000000000000FFFF00000501A8C0:0050")
	if a.Unmap().String() != "192.168.1.5" {
		t.Fatalf("v6-mapped: %v", a)
	}
}
