// Package mcp is a minimal Model Context Protocol server over stdio: enough
// of the protocol (initialize, ping, tools/list, tools/call as
// newline-delimited JSON-RPC 2.0) for an agent to call notenv's tools, and
// nothing more. Hand-rolled deliberately — like internal/ui, it adds zero new
// supply-chain surface, which matters more than protocol breadth while the
// server is a prototype.
//
// Requests are handled sequentially in arrival order; there is no
// cancellation and no server-initiated traffic. Handlers' results travel as
// text content. The transport's stdin/stdout belong to the protocol; prompts
// and logging elsewhere in notenv already go to /dev/tty and stderr, so a
// handler can run the full app stack without corrupting the stream.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// protocolVersion is the MCP revision this server answers with when the
// client's requested version is unusable. The subset spoken here (tools over
// stdio) is stable across revisions, so the server otherwise echoes the
// client's choice.
const protocolVersion = "2025-06-18"

// Tool is one callable tool: a name, the description an agent picks it by,
// a JSON-Schema input declaration, and the handler. A handler error becomes a
// tool-level error result (isError), not a protocol error: the agent gets to
// read it and adapt.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Handler     func(ctx context.Context, args json.RawMessage) (string, error)
}

// Server serves a fixed tool set over one stdio session.
type Server struct {
	Name    string
	Version string
	Tools   []Tool
}

// request is an incoming JSON-RPC message; a nil ID marks a notification.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	codeParse         = -32700
	codeMethodMissing = -32601
	codeBadParams     = -32602
)

// Serve runs the session until in closes (the client hanging up) or ctx is
// canceled between messages. Malformed lines get a parse error where an ID is
// recoverable and are dropped otherwise; unknown notifications are ignored,
// per JSON-RPC.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			if err := reply(out, response{JSONRPC: "2.0", Error: &rpcError{Code: codeParse, Message: err.Error()}}); err != nil {
				return err
			}
			continue
		}
		resp, respond := s.handle(ctx, &req)
		if !respond {
			continue
		}
		if err := reply(out, resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func reply(out io.Writer, resp response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s\n", data)
	return err
}

// handle dispatches one message; respond=false for notifications.
func (s *Server) handle(ctx context.Context, req *request) (response, bool) {
	if req.ID == nil {
		return response{}, false // notification (e.g. notifications/initialized): nothing to say
	}
	resp := response{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = s.initializeResult(req.Params)
	case "ping":
		resp.Result = struct{}{}
	case "tools/list":
		resp.Result = s.toolsResult()
	case "tools/call":
		resp = s.callTool(ctx, resp, req.Params)
	default:
		resp.Error = &rpcError{Code: codeMethodMissing, Message: fmt.Sprintf("method %q is not supported", req.Method)}
	}
	return resp, true
}

func (s *Server) initializeResult(params json.RawMessage) any {
	// Echo the client's protocol revision (the tools subset is stable across
	// them); answer with our own only when the client sent none.
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	version := p.ProtocolVersion
	if version == "" {
		version = protocolVersion
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": struct{}{}},
		"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
	}
}

func (s *Server) toolsResult() any {
	tools := make([]map[string]any, 0, len(s.Tools))
	for _, t := range s.Tools {
		tools = append(tools, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		})
	}
	return map[string]any{"tools": tools}
}

func (s *Server) callTool(ctx context.Context, resp response, params json.RawMessage) response {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		resp.Error = &rpcError{Code: codeBadParams, Message: err.Error()}
		return resp
	}
	for _, t := range s.Tools {
		if t.Name != p.Name {
			continue
		}
		text, err := t.Handler(ctx, p.Arguments)
		isError := err != nil
		if isError {
			text = err.Error()
		}
		resp.Result = map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"isError": isError,
		}
		return resp
	}
	resp.Error = &rpcError{Code: codeBadParams, Message: fmt.Sprintf("unknown tool %q", p.Name)}
	return resp
}
