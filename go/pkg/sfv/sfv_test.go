package sfv

import "testing"

func TestDictionaryRoundTrip(t *testing.T) {
	for in, want := range map[string]string{
		`a=1, b=2`:                        `a=1, b=2`,
		`a=1,b=2`:                         `a=1, b=2`,
		"a=1 ,\tb=2":                      `a=1, b=2`,
		`  a="x\"y\\z"  `:                 `a="x\"y\\z"`,
		`a, b;x=?0, c=?1`:                 `a, b;x=?0, c`,
		`a=(1 "two" three);p=:AQID:`:      `a=(1 "two" three);p=:AQID:`,
		`a=1.50, b=-0.025, c=0.0, d=12.0`: `a=1.5, b=-0.025, c=0.0, d=12.0`,
		`a=@1659578233, b=%"f%c3%bc%22"`:  `a=@1659578233, b=%"f%c3%bc%22"`,
		`a=1, b=2, a=3`:                   `a=3, b=2`,
		`a=x;k=1;k=2`:                     `a=x;k=2`,
		`a=:AQI=:, b=:AQI:`:               `a=:AQI=:, b=:AQI=:`,
		`sig1=("@authority" "x";key="a")`: `sig1=("@authority" "x";key="a")`,
		`a=*tok/en:x`:                     `a=*tok/en:x`,
		`a=()`:                            `a=()`,
		`a=( 1  2 )`:                      `a=(1 2)`,
		`a=-999999999999999`:              `a=-999999999999999`,
		`a=999999999999.999`:              `a=999999999999.999`,
		``:                                ``,
	} {
		d, err := ParseDictionary(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		got, err := SerializeDictionary(d)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestDictionaryRejects(t *testing.T) {
	for _, in := range []string{
		`a=1,`, `a=1,,b=2`, `A=1`, `a=1 b=2`, `a="unterminated`, `a="\x"`,
		"a=\"tab\there\"", `a=:AQ=I:`, `a=:AQI==:`, `a=:A Q:`, `a=1.`, `a=1.2345`,
		`a=1234567890123456`, `a=1234567890123.1`, `a=(1 2`, `a=(1,2)`, `a=?2`,
		`a=@1.5`, `a=%"F%C3"`, `a=%"%c3"`, `a=-`, `a=1;`, "\ta=1",
	} {
		if _, err := ParseDictionary(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestItemAndList(t *testing.T) {
	it, err := ParseItem(`"https://a.test";type=x`)
	if err != nil || it.Bare.Str != "https://a.test" || len(it.Params) != 1 {
		t.Fatalf("%+v %v", it, err)
	}
	l, err := ParseList(`a, (b c);d, "e"`)
	if err != nil || len(l) != 3 || l[1].Inner == nil {
		t.Fatalf("%+v %v", l, err)
	}
	s, _ := SerializeList(l)
	if s != `a, (b c);d, "e"` {
		t.Fatal(s)
	}
	if _, err := SerializeItem(Item{Bare: Str("é")}); err == nil {
		t.Fatal("non-ASCII string serialized")
	}
	if _, err := SerializeDictionary(Dictionary{{Key: "Bad", Value: Member{Item: &Item{Bare: Int(1)}}}}); err == nil {
		t.Fatal("invalid key serialized")
	}
}
