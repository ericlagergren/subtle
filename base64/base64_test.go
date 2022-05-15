package base64

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type encPair struct {
	name   string
	enc    *Encoding
	stdlib *base64.Encoding
}

var encs = []encPair{
	{"StdEncoding", StdEncoding, base64.StdEncoding},
	{"RawStdEncoding", RawStdEncoding, base64.RawStdEncoding},
	{"URLEncoding", URLEncoding, base64.URLEncoding},
	{"RawURLEncoding", RawURLEncoding, base64.RawURLEncoding},
}

// TestStdEncodeStdlib tests StdEncode against the stdlib.
func TestStdEncodeStdlib(t *testing.T) {
	for _, e := range encs {
		t.Run(e.name, func(t *testing.T) {
			testStdlibEncode(t, e)
		})
	}
}

func testStdlibEncode(t *testing.T, p encPair) {
	e := p.enc
	stdlib := p.stdlib

	src := make([]byte, 8192)
	want := make([]byte, e.EncodedLen(len(src)))
	got := make([]byte, stdlib.EncodedLen(len(src)))
	if len(want) != len(got) {
		t.Fatalf("expected %d, got %d", len(want), len(got))
	}
	if _, err := rand.Read(src); err != nil {
		t.Fatal(err)
	}
	for i := range src {
		stdlib.Encode(want, src[:i])
		want := want[:stdlib.EncodedLen(i)]

		e.Encode(got, src[:i])
		got := got[:e.EncodedLen(i)]
		if !bytes.Equal(want, got) {
			t.Fatalf("#%d: mismatch: %s", i, cmp.Diff(want, got))
		}
	}
}

const stdTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"abcdefghijklmnopqrstuvwxyz" +
	"0123456789" +
	"+/"

const urlTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"abcdefghijklmnopqrstuvwxyz" +
	"0123456789" +
	"-_"

func TestCmp(t *testing.T) {
	for i := 0; i < 256; i++ {
		for j := 0; j < 256; j++ {
			x := uint(i)
			y := uint(j)

			var want byte
			if x >= y {
				want = 0xff
			}

			// x >= y -> 0xff
			// x <  y -> 0x00
			got := byte((y - x - 1) >> 8)
			if got != want {
				t.Fatalf("expected %2x, got %2x", want, got)
			}

			// Now test the reverse.
			want = ^want

			// x >= y -> 0x00
			// x <  y -> 0xff
			got = byte((x - y) >> 8)
			if got != want {
				t.Fatalf("expected %2x, got %2x", want, got)
			}
		}
	}
}

// TestStdLookup tests stdLookup and stdRevLookup.
func TestStdLookup(t *testing.T) {
	for i := 0; i < len(stdTable); i++ {
		b64 := stdLookup(uint(i))
		if b64 != stdTable[i] {
			t.Fatalf("#%d: expected %q, got %q", i, stdTable[i], b64)
		}
		bin := stdRevLookup(uint(b64))
		if bin != byte(i) {
			t.Fatalf("#%d: expected %d got %d", i, i, bin)
		}
	}
}

// TestURLLookup tests urlLookup and urlRevLookup.
func TestURLLookup(t *testing.T) {
	for i := 0; i < len(urlTable); i++ {
		b64 := urlLookup(uint(i))
		if b64 != urlTable[i] {
			t.Fatalf("#%d: expected %q, got %q", i, urlTable[i], b64)
		}
		// bin := urlRevLookup(uint(b64))
		// if bin != byte(i) {
		// 	t.Fatalf("#%d: expected %d got %d", i, i, bin)
		// }
	}
}

func TestStdRevLookup(t *testing.T) {
	var m [256]byte
	for i := range m {
		m[i] = 0xff
	}
	for i := 0; i < len(stdTable); i++ {
		m[stdTable[i]] = byte(i)
	}
	for i := 0; i < 256; i++ {
		c := byte(m[i])
		ok := c != 0xff
		switch bin := stdRevLookup(uint(i)); {
		case ok && bin != c:
			t.Fatalf("#%d: expected %d got %d", i, c, bin)
		case !ok && bin != 0xff:
			t.Fatalf("#%d: got %#2x", i, bin)
		}
	}
}

func TestStdLookupSWAR3(t *testing.T) {
	const (
		maxUint24 = 1<<24 - 1
	)
	for u := uint(0); u < maxUint24; u++ {
		// Add 0xff to ensure that SWAR3 ignores [8:0].
		v := stdLookupSWAR3(uint32(u)<<8 | 0xff)

		got := byte(v) // [0]
		want := stdLookup(u >> 18 & 0x3f)
		if got != want {
			t.Fatalf("%d: expected %q, got %q", u>>8, want, got)
		}

		got = byte(v >> 8) // [1]
		want = stdLookup(u >> 12 & 0x3f)
		if got != want {
			t.Fatalf("%d: expected %q, got %q", u>>8, want, got)
		}

		got = byte(v >> 16) // [2]
		want = stdLookup(u >> 6 & 0x3f)
		if got != want {
			t.Fatalf("%d: expected %q, got %q", u>>8, want, got)
		}

		got = byte(v >> 24) // [3]
		want = stdLookup(u & 0x3f)
		if got != want {
			t.Fatalf("%d: expected %q, got %q", u>>8, want, got)
		}
	}
}

var sinkB byte

func BenchmarkStdLookup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkB = stdLookup(uint(i % len(stdTable)))
	}
}

func BenchmarkStdRevLookup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c := stdTable[i%len(stdTable)]
		sinkB = stdRevLookup(uint(c))
	}
}
