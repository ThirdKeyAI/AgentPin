package dns

import "testing"

func FuzzParseTxtRecord(f *testing.F) {
	f.Add("v=agentpin1; kid=example-2026-01; fp=sha256:00")
	f.Add(";;=")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseTxtRecord(s)
	})
}
