package dotenv_test

import (
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/dotenv"
)

func parse(t *testing.T, in string) []dotenv.Pair {
	t.Helper()
	pairs, err := dotenv.Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return pairs
}

func one(t *testing.T, in string) dotenv.Pair {
	t.Helper()
	pairs := parse(t, in)
	if len(pairs) != 1 {
		t.Fatalf("want 1 pair, got %v", pairs)
	}
	return pairs[0]
}

func TestParseValues(t *testing.T) {
	cases := map[string]struct{ in, key, value string }{
		"unquoted":              {"A=hello", "A", "hello"},
		"unquoted trimmed":      {"A=  hello  ", "A", "hello"},
		"unquoted with comment": {"A=hello # the api key", "A", "hello"},
		"hash inside value":     {"A=pa#ss", "A", "pa#ss"},
		"export prefix":         {"export A=hello", "A", "hello"},
		"empty":                 {"A=", "A", ""},
		"single quoted":         {`A='  $literal \n  '`, "A", `  $literal \n  `},
		"double quoted":         {`A="line1\nline2\t\"x\"\\"`, "A", "line1\nline2\t\"x\"\\"},
		"double keeps dollar":   {`A="$HOME stays"`, "A", "$HOME stays"},
		"quoted then comment":   {`A="v" # note`, "A", "v"},
		"key space around":      {"  A = hello", "A", "hello"},
		"value with equals":     {"A=k=v", "A", "k=v"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := one(t, c.in)
			if p.Key != c.key || p.Value != c.value {
				t.Fatalf("got %q=%q, want %q=%q", p.Key, p.Value, c.key, c.value)
			}
		})
	}
}

// TestParseStripsLeadingBOM: a UTF-8 BOM (Windows editors add one) is not part
// of the first key.
func TestParseStripsLeadingBOM(t *testing.T) {
	p := one(t, "\ufeffAPI_KEY=secret")
	if p.Key != "API_KEY" {
		t.Fatalf("first key = %q, want API_KEY (BOM not stripped?)", p.Key)
	}
}

func TestParseMultiline(t *testing.T) {
	in := "CERT=\"-----BEGIN-----\nabc\ndef\n-----END-----\"\nB=2\n"
	pairs := parse(t, in)
	if len(pairs) != 2 {
		t.Fatalf("want 2 pairs, got %v", pairs)
	}
	if pairs[0].Value != "-----BEGIN-----\nabc\ndef\n-----END-----" {
		t.Fatalf("multiline value wrong: %q", pairs[0].Value)
	}
	if pairs[1].Key != "B" || pairs[1].Line != 5 {
		t.Fatalf("line tracking wrong after multiline: %+v", pairs[1])
	}
}

func TestParseSkipsNoiseKeepsOrder(t *testing.T) {
	in := "# header comment\n\nA=1\n  # indented comment\nB=2\nA=3\n"
	pairs := parse(t, in)
	if len(pairs) != 3 {
		t.Fatalf("want 3 pairs (duplicates preserved for last-wins), got %v", pairs)
	}
	if pairs[2].Key != "A" || pairs[2].Value != "3" {
		t.Fatalf("duplicate order lost: %+v", pairs)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"no assignment":      "JUSTAWORD\n",
		"unterminated quote": `A="never closed`,
		"trailing junk":      `A="v" extra`,
		"bad escape":         `A="\x41"`,
		"dangling backslash": `A="end\`,
		"quoted key":         `"A"=v`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := dotenv.Parse(strings.NewReader(in)); err == nil {
				t.Fatalf("input %q must be rejected", in)
			}
		})
	}
}

// TestParseNeverExpands is the dialect's core promise: $-syntax passes
// through everywhere.
func TestParseNeverExpands(t *testing.T) {
	for _, in := range []string{`A=$HOME/x`, `A="${B}"`, `A='$C'`} {
		p := one(t, in)
		if !strings.Contains(p.Value, "$") {
			t.Fatalf("expansion happened for %q: %q", in, p.Value)
		}
	}
}
