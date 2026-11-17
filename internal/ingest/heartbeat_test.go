package ingest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/NazifSelimi/httpowl-api/internal/wire"
)

// The nginx helper's error is stored with the agent info so the Blocked page can show it.
func TestHeartbeatKeepsSiteBlockError(t *testing.T) {
	hb := wire.Heartbeat{SiteBlocks: "nginx", SiteBlocksError: "nginx rejected the website block list: " + strings.Repeat("x", 900)}
	cleanHeartbeat(&hb)
	if len(hb.SiteBlocksError) != 500 || !strings.HasPrefix(hb.SiteBlocksError, "nginx rejected") {
		t.Fatalf("not capped: %d", len(hb.SiteBlocksError))
	}
	b, _ := json.Marshal(hb)
	var back map[string]any
	_ = json.Unmarshal(b, &back)
	if back["site_blocks_error"] != hb.SiteBlocksError || back["site_blocks"] != "nginx" {
		t.Fatalf("not stored: %s", b)
	}
}
