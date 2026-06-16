package main

import (
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/DvGils/notenv/internal/secrets"
)

// TestEditBufferTrapsCatchableTerminationSignals asserts the edit buffer is
// unlinked on every signal a process can actually catch, and that SIGKILL (which
// it cannot) is not falsely listed.
func TestEditBufferTrapsCatchableTerminationSignals(t *testing.T) {
	got := map[os.Signal]bool{}
	for _, s := range editBufferSignals {
		got[s] = true
	}
	for _, want := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		if !got[want] {
			t.Errorf("edit must trap %v to unlink its plaintext buffer", want)
		}
	}
	if got[syscall.SIGKILL] {
		t.Error("SIGKILL cannot be trapped and must not be listed (it would imply false coverage)")
	}
}

func editState(vals map[string]string, descs map[string]string) *secrets.State {
	meta := map[string]secrets.Meta{}
	for k, d := range descs {
		meta[k] = secrets.Meta{Description: d}
	}
	return &secrets.State{Secrets: vals, Meta: meta}
}

// TestUnrepresentableKeys guards the v0.19.1 fix: edit must refuse a namespace
// whose values it cannot round-trip (surrounding whitespace, embedded newline),
// rather than corrupt them; internal whitespace is fine.
func TestUnrepresentableKeys(t *testing.T) {
	state := editState(map[string]string{
		"OK":       "plain",
		"INTERNAL": "a b c",
		"TRAILING": "secret ",
		"LEADING":  " secret",
		"MULTI":    "line1\nline2",
	}, nil)
	got := unrepresentableKeys(state)
	want := []string{"LEADING", "MULTI", "TRAILING"} // sorted
	if len(got) != len(want) {
		t.Fatalf("unrepresentableKeys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unrepresentableKeys = %v, want %v", got, want)
		}
	}
	if len(unrepresentableKeys(editState(map[string]string{"A": "1"}, nil))) != 0 {
		t.Error("a clean namespace should have no unrepresentable keys")
	}
}

// TestWouldWipeNamespace guards the v0.19.1 fix: an emptied or truncated buffer
// diffs to an all-delete, and runEdit must recognize that as a full wipe (and
// confirm) rather than proceed silently.
func TestWouldWipeNamespace(t *testing.T) {
	before := editState(map[string]string{"A": "1", "B": "2", "C": "3"}, nil)

	entries, err := parseEditBuffer(strings.NewReader("\n\n# only a comment\n"))
	if err != nil {
		t.Fatalf("parseEditBuffer: %v", err)
	}
	writes, err := diffEdit(before, entries)
	if err != nil {
		t.Fatal(err)
	}
	if !wouldWipeNamespace(before, writes) {
		t.Fatal("an empty buffer should be detected as wiping the namespace")
	}

	if wouldWipeNamespace(before, []secrets.Write{{Key: "A", Deleted: true}, {Key: "B", Deleted: true}}) {
		t.Error("deleting some but not all keys is not a wipe")
	}
	if wouldWipeNamespace(before, []secrets.Write{{Key: "A", Deleted: true}, {Key: "B", Deleted: true}, {Key: "C", Value: "x"}}) {
		t.Error("a batch that still sets a key is not a wipe")
	}
	if wouldWipeNamespace(editState(nil, nil), nil) {
		t.Error("an empty namespace is never a wipe")
	}
}

// TestEditBufferRoundTrip: rendering a state and parsing it back unchanged
// yields keeps for every key, descriptions intact, and an empty diff.
func TestEditBufferRoundTrip(t *testing.T) {
	state := editState(
		map[string]string{"DB_URL": "postgres://x", "API_KEY": "k"},
		map[string]string{"DB_URL": "primary DSN"},
	)
	text := renderEditBuffer("myapp", state)
	if strings.Contains(text, "postgres://x") || strings.Contains(text, `"k"`) {
		t.Fatalf("the buffer must never contain a stored value:\n%s", text)
	}
	entries, err := parseEditBuffer(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || !entries["DB_URL"].keep || !entries["API_KEY"].keep {
		t.Fatalf("entries = %+v", entries)
	}
	if entries["DB_URL"].description != "primary DSN" || entries["API_KEY"].description != "" {
		t.Fatalf("descriptions lost: %+v", entries)
	}
	writes, err := diffEdit(state, entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(writes) != 0 {
		t.Fatalf("an unchanged buffer must diff to nothing, got %+v", writes)
	}
}

// TestEditDiff: one buffer expressing every operation produces exactly the
// right batch: set new, rewrite, re-describe (value carried), unset.
func TestEditDiff(t *testing.T) {
	state := editState(
		map[string]string{"REWRITE": "old", "REDESC": "stays", "GONE": "x", "SAME": "s"},
		map[string]string{"REDESC": "old words"},
	)
	buffer := `# Editing namespace "x" with 4 secret(s).

# new words
REDESC=<keep>

REWRITE=newvalue
SAME=<keep>
NEW=fresh
`
	entries, err := parseEditBuffer(strings.NewReader(buffer))
	if err != nil {
		t.Fatal(err)
	}
	writes, err := diffEdit(state, entries)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]secrets.Write{}
	for _, w := range writes {
		byKey[w.Key] = w
	}
	if len(writes) != 4 {
		t.Fatalf("want 4 writes, got %+v", writes)
	}
	if w := byKey["NEW"]; w.Value != "fresh" || w.Deleted {
		t.Fatalf("NEW = %+v", w)
	}
	if w := byKey["REWRITE"]; w.Value != "newvalue" {
		t.Fatalf("REWRITE = %+v", w)
	}
	if w := byKey["REDESC"]; w.Value != "stays" || w.Description != "new words" {
		t.Fatalf("REDESC must carry the value and change the description: %+v", w)
	}
	if w := byKey["GONE"]; !w.Deleted {
		t.Fatalf("GONE = %+v", w)
	}
}

// TestEditBlankLineKeepsDescription: a blank line slipped between a key's comment
// and the key (an editor reflow) detaches the comment, but a value change must
// then KEEP the stored description, never silently clear it.
func TestEditBlankLineKeepsDescription(t *testing.T) {
	state := editState(
		map[string]string{"TOKEN": "old"},
		map[string]string{"TOKEN": "the API token"},
	)
	// The description comment is no longer directly above the key.
	buffer := "# the API token\n\nTOKEN=newvalue\n"
	entries, err := parseEditBuffer(strings.NewReader(buffer))
	if err != nil {
		t.Fatal(err)
	}
	if entries["TOKEN"].description != "" {
		t.Fatalf("a blank line detaches the comment, so the parsed description is empty: %+v", entries["TOKEN"])
	}
	writes, err := diffEdit(state, entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(writes) != 1 {
		t.Fatalf("want one write for the value change, got %+v", writes)
	}
	w := writes[0]
	if w.Key != "TOKEN" || w.Value != "newvalue" {
		t.Fatalf("TOKEN value must change: %+v", w)
	}
	if !w.KeepDescription || w.Description != "" {
		t.Fatalf("the description must be kept (KeepDescription), not cleared: %+v", w)
	}
}

// TestEditParseErrors: the strict failures, each naming its line.
func TestEditParseErrors(t *testing.T) {
	for name, buffer := range map[string]string{
		"not an assignment": "garbage line\n",
		"invalid name":      "9BAD=x\n",
		"duplicate key":     "A=1\nA=2\n",
		"empty value":       "A=\n",
	} {
		if _, err := parseEditBuffer(strings.NewReader(buffer)); err == nil {
			t.Errorf("%s must fail to parse", name)
		}
	}
}

// TestEditSentinelOnNewKey: a literal sentinel value for a key that holds
// nothing is refused, naming the collision.
func TestEditSentinelOnNewKey(t *testing.T) {
	entries, err := parseEditBuffer(strings.NewReader("NEW=<keep>\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = diffEdit(editState(nil, nil), entries)
	if err == nil || !strings.Contains(err.Error(), keepSentinel) {
		t.Fatalf("err = %v, want the sentinel collision named", err)
	}
}

// TestRefuseConcurrentEdits: a touched key that changed remotely stops the
// save naming it; remote changes to untouched keys do not.
func TestRefuseConcurrentEdits(t *testing.T) {
	before := editState(map[string]string{"A": "1", "B": "2"}, nil)
	freshUntouched := editState(map[string]string{"A": "1", "B": "99"}, nil)
	writes := []secrets.Write{{Key: "A", Value: "new"}}
	if err := refuseConcurrentEdits(before, freshUntouched, writes); err != nil {
		t.Fatalf("a remote change to an untouched key must merge: %v", err)
	}
	freshTouched := editState(map[string]string{"A": "remote", "B": "2"}, nil)
	err := refuseConcurrentEdits(before, freshTouched, writes)
	if err == nil || !strings.Contains(err.Error(), "A") {
		t.Fatalf("err = %v, want the clashing key named", err)
	}
}

// TestEditDiffIsSorted: deterministic write order, keyed alphabetically.
func TestEditDiffIsSorted(t *testing.T) {
	entries, err := parseEditBuffer(strings.NewReader("B=2\nA=1\nC=3\n"))
	if err != nil {
		t.Fatal(err)
	}
	writes, err := diffEdit(editState(nil, nil), entries)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, w := range writes {
		keys = append(keys, w.Key)
	}
	if !slices.IsSorted(keys) {
		t.Fatalf("writes must be sorted, got %v", keys)
	}
}
