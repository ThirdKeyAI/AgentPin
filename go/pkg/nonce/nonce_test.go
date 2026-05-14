package nonce

import (
	"testing"
	"time"
)

func TestFreshNonceAccepted(t *testing.T) {
	s := NewInMemoryStore()
	ok, err := s.CheckAndRecord("n1", time.Minute)
	if err != nil || !ok {
		t.Fatalf("first call: ok=%v err=%v", ok, err)
	}
}

func TestDuplicateNonceRejected(t *testing.T) {
	s := NewInMemoryStore()
	_, _ = s.CheckAndRecord("dup", time.Minute)
	ok, _ := s.CheckAndRecord("dup", time.Minute)
	if ok {
		t.Fatal("duplicate should be rejected")
	}
}

func TestExpiredNonceReusable(t *testing.T) {
	s := NewInMemoryStore()
	_, _ = s.CheckAndRecord("exp", time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	ok, _ := s.CheckAndRecord("exp", time.Minute)
	if !ok {
		t.Fatal("expired nonce should be reusable")
	}
}
