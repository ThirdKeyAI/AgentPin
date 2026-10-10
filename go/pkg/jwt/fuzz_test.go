package jwt

import "testing"

func FuzzDecodeJWTUnverified(f *testing.F) {
	f.Add("eyJhbGciOiJFUzI1NiJ9.e30.AA")
	f.Add("a.b.c")
	f.Fuzz(func(t *testing.T, s string) {
		if _, p, _, err := DecodeJWTUnverified(s); err == nil {
			_ = ValidateClaims(p)
		}
	})
}
