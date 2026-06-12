package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/mcp"
)

// TestMCPToolSurface pins the frozen MCP tool surface: names, input and
// output schemas, and annotations, exactly as a client sees them from
// tools/list. Shape changes are deliberate acts: update the golden file in
// the same commit and say why.
func TestMCPToolSurface(t *testing.T) {
	server := &mcp.Server{Name: "notenv", Version: "test", Tools: mcpTools()}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	var out bytes.Buffer
	if err := server.Serve(context.Background(), in, &out); err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, resp.Result, "", "  "); err != nil {
		t.Fatal(err)
	}
	got := pretty.String() + "\n"

	golden, err := os.ReadFile("testdata/mcp_tools.golden.json")
	if os.IsNotExist(err) && os.Getenv("NOTENV_UPDATE_GOLDEN") == "1" {
		if werr := os.WriteFile("testdata/mcp_tools.golden.json", []byte(got), 0o644); werr != nil {
			t.Fatal(werr)
		}
		t.Skip("golden written; re-run without NOTENV_UPDATE_GOLDEN")
	}
	if err != nil {
		t.Fatal(err)
	}
	if got != string(golden) {
		t.Fatalf("MCP tool surface drifted from testdata/mcp_tools.golden.json:\n%s", got)
	}
}
