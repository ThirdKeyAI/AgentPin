package sfv

import "testing"

// FuzzDictionary checks that any accepted Dictionary serializes, and that
// the serialization parses back to the same canonical form.
func FuzzDictionary(f *testing.F) {
	for _, s := range []string{
		`sig1=("@authority" "signature-agent";key="sig1");created=1;keyid="k";tag="web-bot-auth"`,
		`sig1=:AQID:`, `a, b;x=?0, c=1.5`, `a=@1, b=%"x%22"`, `a=(1 2);p=*t`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		d, err := ParseDictionary(in)
		if err != nil {
			return
		}
		s1, err := SerializeDictionary(d)
		if err != nil {
			t.Fatalf("%q parsed but does not serialize: %v", in, err)
		}
		d2, err := ParseDictionary(s1)
		if err != nil {
			t.Fatalf("serialization %q does not parse: %v", s1, err)
		}
		if s2, _ := SerializeDictionary(d2); s2 != s1 {
			t.Fatalf("not canonical: %q vs %q", s1, s2)
		}
	})
}
