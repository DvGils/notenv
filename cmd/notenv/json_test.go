package main

import (
	"encoding/json"
	"errors"
	"os/exec"
	"syscall"
	"testing"

	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/runner"
	"github.com/DvGils/notenv/internal/secrets"
)

// mustJSON marshals exactly as printJSON does, minus the trailing newline.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestListJSONShape pins the frozen `list --json` shape: sorted secrets,
// metadata omitted when absent, modified as RFC 3339 UTC, never values.
func TestListJSONShape(t *testing.T) {
	meta := map[string]secrets.Meta{
		"DB_URL": {Description: "primary DSN", TS: 1765900800}, // 2025-12-16T16:00:00Z
	}
	got := mustJSON(t, listOutput{Namespace: "ops", Secrets: listedSecrets([]string{"API_KEY", "DB_URL"}, meta)})
	want := `{
  "namespace": "ops",
  "secrets": [
    {
      "name": "API_KEY"
    },
    {
      "name": "DB_URL",
      "description": "primary DSN",
      "modified": "2025-12-16T16:00:00Z"
    }
  ]
}`
	if got != want {
		t.Fatalf("list --json shape drifted:\n%s\nwant:\n%s", got, want)
	}
}

// TestKeyListJSONShape pins the frozen `key list --json` shape: indexed
// slots, normalized type, public_key only on recipient slots.
func TestKeyListJSONShape(t *testing.T) {
	h := &crypto.Header{
		VaultID:  "vault-1",
		Revision: 7,
		Slots: []crypto.Slot{
			{Name: "demian@legion", Primary: true, Type: crypto.SlotPassphrase, PublicKey: "age1internal"},
			{Name: "bob", Type: crypto.SlotRecipient, PublicKey: "age1bob"},
		},
	}
	got := mustJSON(t, keyListOutput(h))
	want := `{
  "vault_id": "vault-1",
  "revision": 7,
  "slots": [
    {
      "index": 0,
      "name": "demian@legion",
      "type": "passphrase",
      "primary": true
    },
    {
      "index": 1,
      "name": "bob",
      "type": "recipient",
      "public_key": "age1bob"
    }
  ]
}`
	if got != want {
		t.Fatalf("key list --json shape drifted:\n%s\nwant:\n%s", got, want)
	}
}

// TestClassifyRunError: never-started children map to 127 (not found) and
// 126 (found but cannot run); everything else stays notenv's own failure.
func TestClassifyRunError(t *testing.T) {
	notFound := &runner.StartError{Err: &exec.Error{Name: "nope", Err: exec.ErrNotFound}}
	var ec *exitCodeError
	if err := classifyRunError(notFound); !errors.As(err, &ec) || ec.code != 127 {
		t.Fatalf("not-found = %v, want exit 127", err)
	}
	denied := &runner.StartError{Err: &exec.Error{Name: "./x", Err: syscall.EACCES}}
	if err := classifyRunError(denied); !errors.As(err, &ec) || ec.code != 126 {
		t.Fatalf("permission = %v, want exit 126", err)
	}
	own := errors.New("network down")
	if err := classifyRunError(own); !errors.Is(err, own) || errors.As(err, &ec) {
		t.Fatalf("own failure = %v, must pass through for the 125 wrap", err)
	}
}
