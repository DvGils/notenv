package crypto

import (
	"strings"
	"testing"
)

func TestObjectMACRoundTrip(t *testing.T) {
	mk, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	mac, err := mk.ObjectMAC([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := mk.CheckObjectMAC([]byte("payload"), mac); err != nil {
		t.Fatalf("CheckObjectMAC on matching plaintext: %v", err)
	}
	if err := mk.CheckObjectMAC([]byte("other payload"), mac); err == nil {
		t.Fatal("a different plaintext must not verify")
	}

	// The MAC is keyed from the master: another master neither produces nor
	// verifies it (no offline-guessing oracle next to the public header).
	other, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := other.CheckObjectMAC([]byte("payload"), mac); err == nil {
		t.Fatal("a different master must not verify the MAC")
	}
	otherMAC, err := other.ObjectMAC([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if otherMAC == mac {
		t.Fatal("two masters must derive different MAC keys")
	}
}

func TestApplyManifest(t *testing.T) {
	h := &Header{}
	h.ApplyManifest(ManifestDelta{Add: map[string]ManifestEntry{
		"ns/seg-a.age":  {MAC: "aa"},
		"ns/snap-b.age": {MAC: "bb"},
	}})
	h.ApplyManifest(ManifestDelta{Fold: []string{"ns/seg-a.age", "ns/absent.age"}})
	if !h.Manifest["ns/seg-a.age"].Folded || h.Manifest["ns/seg-a.age"].MAC != "aa" {
		t.Fatalf("fold must mark the entry and keep its MAC: %+v", h.Manifest)
	}
	if _, ok := h.Manifest["ns/absent.age"]; ok {
		t.Fatal("folding an absent entry must not create one")
	}
	h.ApplyManifest(ManifestDelta{Prune: []string{"ns/seg-a.age"}})
	if _, ok := h.Manifest["ns/seg-a.age"]; ok {
		t.Fatal("prune must remove the entry")
	}
	if h.Manifest["ns/snap-b.age"].MAC != "bb" {
		t.Fatal("untouched entries must survive")
	}
	if !(ManifestDelta{}).Empty() {
		t.Fatal("the zero delta is empty")
	}
	if (ManifestDelta{Fold: []string{"x"}}).Empty() {
		t.Fatal("a folding delta is not empty")
	}
}

// TestManifestSurvivesSeal: the manifest is part of the authenticated header —
// sealing and verifying cover it, and a tampered entry breaks the tag.
func TestManifestSurvivesSeal(t *testing.T) {
	h, mk, err := NewHeader("p", "owner")
	if err != nil {
		t.Fatal(err)
	}
	h.ApplyManifest(ManifestDelta{Add: map[string]ManifestEntry{"ns/seg-a.age": {MAC: "aa"}}})
	if err := h.Seal(mk); err != nil {
		t.Fatal(err)
	}
	raw, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(mk); err != nil {
		t.Fatalf("sealed manifest must verify: %v", err)
	}
	parsed.Manifest["ns/seg-a.age"] = ManifestEntry{MAC: "ee"}
	if err := parsed.Verify(mk); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("a tampered manifest entry must break the tag, got %v", err)
	}
}
