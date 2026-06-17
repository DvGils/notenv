package backend

import (
	"testing"

	"github.com/DvGils/notenv/internal/contract"
)

func TestIsNamespaceBlob(t *testing.T) {
	good := []string{
		"api/data-0123456789abcdef.age",
		"my-service/data-ffffffffffffffff.age",
		"a/data-00000000000000ff.age",
		"ns_1/data-deadbeefdeadbeef.age",
		"a.b.c/data-0123456789abcdef.age",
	}
	for _, key := range good {
		if !IsNamespaceBlob(key) {
			t.Errorf("IsNamespaceBlob(%q) = false, want true", key)
		}
	}
	bad := []string{
		"",
		"notes.txt",
		"api/notes.txt",
		"api/data-0123456789abcdef.txt",     // wrong suffix
		"api/data-0123456789ABCDEF.age",     // hex must be lowercase
		"api/data-0123.age",                 // too few hex digits
		"api/data-0123456789abcdef0.age",    // too many hex digits
		"api/sub/data-0123456789abcdef.age", // namespaces are one segment
		"/api/data-0123456789abcdef.age",    // leading slash
		"data-0123456789abcdef.age",         // no namespace segment
		".header.json",                      // reserved, not a blob
		"../data-0123456789abcdef.age",      // traversal-ish first segment
	}
	for _, key := range bad {
		if IsNamespaceBlob(key) {
			t.Errorf("IsNamespaceBlob(%q) = true, want false", key)
		}
	}
}

func TestIsNotenvObject(t *testing.T) {
	ours := []string{
		HeaderName, HeaderBackupName, HeaderLockName, ProbeName,
		".tmp-abc123",
		"api/data-0123456789abcdef.age",
	}
	for _, key := range ours {
		if !IsNotenvObject(key) {
			t.Errorf("IsNotenvObject(%q) = false, want true (notenv writes it)", key)
		}
	}
	foreign := []string{
		"passwd",
		"home/user/.bashrc",
		"api/secrets.env",
		"Documents/photo.jpg",
	}
	for _, key := range foreign {
		if IsNotenvObject(key) {
			t.Errorf("IsNotenvObject(%q) = true, want false (notenv must never delete it)", key)
		}
	}
}

// TestNamespaceBlobKeyTracksContract guards the namespace charset embedded in
// namespaceBlobKey against drift from contract.NamespaceName, the real validator.
// If contract widens or narrows what a namespace may contain, a blob built from a
// now-legal namespace must still be recognized as notenv's own (and an illegal one
// must not), or the recognizer would stop matching real blobs (a reconcile would
// leak stale objects) or start matching foreign paths.
func TestNamespaceBlobKeyTracksContract(t *testing.T) {
	const blob = "/data-0123456789abcdef.age"
	cases := []struct {
		ns    string
		valid bool
	}{
		{"api", true},
		{"my-service", true},
		{"ns_1", true},
		{"a.b", true},
		{"-leading-dash", false},
		{".leading-dot", false},
		{"has/slash", false},
		{"has space", false},
		{"", false},
	}
	for _, c := range cases {
		gotContract := contract.NamespaceName.MatchString(c.ns)
		if gotContract != c.valid {
			t.Fatalf("test assumption wrong: contract.NamespaceName.MatchString(%q) = %v, want %v", c.ns, gotContract, c.valid)
		}
		gotBlob := IsNamespaceBlob(c.ns + blob)
		if gotBlob != c.valid {
			t.Errorf("IsNamespaceBlob(%q+blob) = %v, want %v (must match contract.NamespaceName)", c.ns, gotBlob, c.valid)
		}
	}
}
