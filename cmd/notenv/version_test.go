package main

import "testing"

func TestRenderVersion(t *testing.T) {
	tests := []struct {
		name    string
		v, c, d string
		want    string
	}{
		{"release", "v0.4.0", "72ae01824df6abc1234", "2026-06-11", "notenv v0.4.0 (commit 72ae01824df6, built 2026-06-11)"},
		{"version only (proxy install)", "v0.3.0", "", "", "notenv v0.3.0"},
		{"commit only", "v0.3.0+dirty", "72ae01824df6", "", "notenv v0.3.0+dirty (commit 72ae01824df6)"},
		{"date only", "v0.3.0", "", "2026-06-11", "notenv v0.3.0 (built 2026-06-11)"},
		{"empty version falls back to dev", "", "", "", "notenv dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := renderVersion(tt.v, tt.c, tt.d); got != tt.want {
				t.Fatalf("renderVersion(%q,%q,%q) = %q, want %q", tt.v, tt.c, tt.d, got, tt.want)
			}
		})
	}
}
