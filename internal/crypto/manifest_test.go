package crypto

import (
	"strings"
	"testing"
)

func TestBlobMACRoundTrip(t *testing.T) {
	mk, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	mac, err := mk.BlobMAC([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := mk.CheckBlobMAC([]byte("payload"), mac); err != nil {
		t.Fatalf("CheckBlobMAC on matching plaintext: %v", err)
	}
	if err := mk.CheckBlobMAC([]byte("other payload"), mac); err == nil {
		t.Fatal("a different plaintext must not verify")
	}

	// The MAC is keyed from the master: another master neither produces nor
	// verifies it (no offline-guessing oracle next to the public header).
	other, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := other.CheckBlobMAC([]byte("payload"), mac); err == nil {
		t.Fatal("a different master must not verify the MAC")
	}
	otherMAC, err := other.BlobMAC([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if otherMAC == mac {
		t.Fatal("two masters must derive different MAC keys")
	}
}

func TestNamespaceManifestOps(t *testing.T) {
	h := &Header{}
	h.SetNamespace("proj", ManifestEntry{Blob: "proj/data-a.age", MAC: "aa"})
	h.SetNamespace("other", ManifestEntry{Blob: "other/data-b.age", MAC: "bb"})

	e, ok := h.NamespaceEntry("proj")
	if !ok || e.Blob != "proj/data-a.age" || e.MAC != "aa" {
		t.Fatalf("NamespaceEntry(proj) = %+v,%v", e, ok)
	}
	// SetNamespace replaces in place (a write advances the blob pointer).
	h.SetNamespace("proj", ManifestEntry{Blob: "proj/data-c.age", MAC: "cc", Prev: "proj/data-a.age", PrevMAC: "aa"})
	if e, _ := h.NamespaceEntry("proj"); e.Blob != "proj/data-c.age" || e.Prev != "proj/data-a.age" {
		t.Fatalf("SetNamespace did not replace: %+v", e)
	}
	h.RemoveNamespace("proj")
	if _, ok := h.NamespaceEntry("proj"); ok {
		t.Fatal("RemoveNamespace must drop the entry")
	}
	if e, ok := h.NamespaceEntry("other"); !ok || e.MAC != "bb" {
		t.Fatalf("untouched namespace must survive: %+v,%v", e, ok)
	}
}

// TestManifestSurvivesSeal: the manifest is part of the authenticated header —
// sealing and verifying cover it, and a tampered entry breaks the tag.
func TestManifestSurvivesSeal(t *testing.T) {
	h, mk, err := NewHeader("p", "owner")
	if err != nil {
		t.Fatal(err)
	}
	h.SetNamespace("proj", ManifestEntry{Blob: "proj/data-a.age", MAC: "aa"})
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
	parsed.Manifest["proj"] = ManifestEntry{Blob: "proj/data-a.age", MAC: "ee"}
	if err := parsed.Verify(mk); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("a tampered manifest entry must break the tag, got %v", err)
	}
}
