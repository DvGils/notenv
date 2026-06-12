package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testServer() *Server {
	return &Server{
		Name:    "notenv",
		Version: "test",
		Tools: []Tool{{
			Name:        "echo",
			Description: "echoes its input",
			InputSchema: map[string]any{"type": "object"},
			Handler: func(_ context.Context, args json.RawMessage) (string, error) {
				var p struct {
					Text string `json:"text"`
					Fail bool   `json:"fail"`
				}
				if err := json.Unmarshal(args, &p); err != nil {
					return "", err
				}
				if p.Fail {
					return "", errors.New("the tool failed")
				}
				return p.Text, nil
			},
		}},
	}
}

// session feeds newline-delimited requests through a server and returns the
// responses in order.
func session(t *testing.T, lines ...string) []map[string]any {
	t.Helper()
	var out strings.Builder
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	if err := testServer().Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var resps []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("response %q: %v", line, err)
		}
		resps = append(resps, m)
	}
	return resps
}

// TestSession drives the handshake and a tool call the way a client would:
// initialize, the initialized notification (no response), tools/list, call.
func TestSession(t *testing.T) {
	resps := session(t,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"t"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"ping"}`,
	)
	if len(resps) != 4 {
		t.Fatalf("got %d responses, want 4 (the notification is silent): %v", len(resps), resps)
	}
	init := resps[0]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-03-26" {
		t.Fatalf("initialize must echo the client's protocol revision, got %v", init["protocolVersion"])
	}
	tools := resps[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "echo" {
		t.Fatalf("tools/list = %v", tools)
	}
	call := resps[2]["result"].(map[string]any)
	if call["isError"] != false {
		t.Fatalf("call result = %v", call)
	}
	content := call["content"].([]any)[0].(map[string]any)
	if content["type"] != "text" || content["text"] != "hi" {
		t.Fatalf("content = %v", content)
	}
}

// TestErrors: a handler failure is a tool-level error result the agent can
// read; an unknown tool or method is a protocol error; an unknown
// notification is silently ignored.
func TestErrors(t *testing.T) {
	resps := session(t,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"fail":true}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nope","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled"}`,
	)
	if len(resps) != 3 {
		t.Fatalf("got %d responses, want 3: %v", len(resps), resps)
	}
	failed := resps[0]["result"].(map[string]any)
	if failed["isError"] != true {
		t.Fatalf("handler failure must be a tool-level error: %v", failed)
	}
	text := failed["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "the tool failed") {
		t.Fatalf("error text = %q", text)
	}
	if resps[1]["error"] == nil {
		t.Fatalf("unknown tool must be a protocol error: %v", resps[1])
	}
	if resps[2]["error"] == nil {
		t.Fatalf("unknown method must be a protocol error: %v", resps[2])
	}
}

// TestParseError: a garbage line gets a parse error and the session goes on.
func TestParseError(t *testing.T) {
	resps := session(t,
		`this is not json`,
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
	)
	if len(resps) != 2 {
		t.Fatalf("got %d responses, want 2: %v", len(resps), resps)
	}
	if errObj := resps[0]["error"]; errObj == nil || errObj.(map[string]any)["code"].(float64) != codeParse {
		t.Fatalf("first response must be a parse error: %v", resps[0])
	}
	if resps[1]["result"] == nil {
		t.Fatalf("the session must survive a garbage line: %v", resps[1])
	}
}

// TestInitializeDefaultsVersion: a client that names no revision gets ours.
func TestInitializeDefaultsVersion(t *testing.T) {
	resps := session(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	got := resps[0]["result"].(map[string]any)["protocolVersion"]
	if got != protocolVersion {
		t.Fatalf("protocolVersion = %v, want %v", got, protocolVersion)
	}
}
