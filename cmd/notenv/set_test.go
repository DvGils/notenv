package main

import "testing"

// TestTrimStdinTerminator: a value piped via --stdin loses exactly one trailing
// line terminator (the "\r\n" pair or a lone "\n") so a CRLF source cannot store
// a hidden trailing "\r"; interior and deliberate bare-"\r" bytes survive.
func TestTrimStdinTerminator(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"crlf pair stripped as a unit", "secret\r\n", "secret"},
		{"lone newline stripped", "secret\n", "secret"},
		{"no terminator untouched", "secret", "secret"},
		{"bare trailing cr kept", "secret\r", "secret\r"},
		{"only the last terminator goes", "line1\r\nline2\r\n", "line1\r\nline2"},
		{"interior crlf kept", "line1\r\nline2\n", "line1\r\nline2"},
		{"empty stays empty", "", ""},
		{"lone newline becomes empty", "\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := trimStdinTerminator(c.in); got != c.want {
				t.Fatalf("trimStdinTerminator(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
