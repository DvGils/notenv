package backend

import (
	"bytes"
	"errors"
	"testing"
)

func TestReadCapped(t *testing.T) {
	// Empty, under, and exactly at the cap all succeed and return every byte.
	for _, n := range []int{0, 5, 10} {
		got, err := ReadCapped(bytes.NewReader(bytes.Repeat([]byte("x"), n)), 10)
		if err != nil {
			t.Fatalf("%d bytes under cap 10: %v", n, err)
		}
		if len(got) != n {
			t.Fatalf("%d bytes: read back %d", n, len(got))
		}
	}
	// One byte past the cap fails closed (no truncated read returned).
	got, err := ReadCapped(bytes.NewReader(bytes.Repeat([]byte("x"), 11)), 10)
	if !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("11 bytes over cap 10 must be ErrObjectTooLarge, got %v", err)
	}
	if got != nil {
		t.Fatalf("an over-cap read must not return data, got %d bytes", len(got))
	}
}

func TestCappedWriter(t *testing.T) {
	canceled := false
	cw := &cappedWriter{max: 10, cancel: func() { canceled = true }}

	n, err := cw.Write([]byte("hello")) // 5 of 10
	if n != 5 || err != nil {
		t.Fatalf("under-cap write: n=%d err=%v", n, err)
	}
	if cw.exceeded || canceled {
		t.Fatal("must not be over the cap after 5/10")
	}

	// 6 more would make 11 > 10: marks exceeded, cancels the command, but still
	// reports success so os/exec's copier doesn't error (the child is killed via
	// cancel instead).
	n, err = cw.Write([]byte("world!"))
	if n != 6 || err != nil {
		t.Fatalf("over-cap write must report success to the copier: n=%d err=%v", n, err)
	}
	if !cw.exceeded {
		t.Fatal("must be marked exceeded once the cap is passed")
	}
	if !canceled {
		t.Fatal("must cancel the command once the cap is passed")
	}

	// Further writes are discarded, so memory stays bounded as the killed child drains.
	_, _ = cw.Write([]byte("more and more"))
	if cw.buf.String() != "hello" {
		t.Fatalf("buffer must hold only the pre-overflow bytes, got %q", cw.buf.String())
	}
}
