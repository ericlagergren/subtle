package base64

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

const (
	StdPadding = base64.StdPadding // standard padding '='
	NoPadding  = base64.NoPadding  // no padding
)

// ErrCorrupt is returned when the Base64-encoded input is
// incorrect.
var ErrCorrupt = errors.New("base64: input is corrupt")

// StdEncoding is the standard Base64 encoding.
//
// It uses the following table:
//
//    ABCDEFGHIJKLMNOPQRSTUVWXYZ
//    abcdefghijklmnopqrstuvwxyz
//    0123456789
//    +/
//
var StdEncoding = &Encoding{
	encode:  stdEncode,
	decode:  stdDecode,
	padChar: StdPadding,
}

// RawStdEncoding is the unpadded standard Base64 encoding.
//
// It uses the following table:
//
//    ABCDEFGHIJKLMNOPQRSTUVWXYZ
//    abcdefghijklmnopqrstuvwxyz
//    0123456789
//    +/
//
var RawStdEncoding = &Encoding{
	encode:  stdEncode,
	decode:  stdDecode,
	padChar: NoPadding,
}

// URLEncoding is the base64url Base64 encoding.
//
// It uses the following table:
//
//    ABCDEFGHIJKLMNOPQRSTUVWXYZ
//    abcdefghijklmnopqrstuvwxyz
//    0123456789
//    -_
//
var URLEncoding = &Encoding{
	encode:  urlEncode,
	decode:  urlDecode,
	padChar: StdPadding,
}

// RawStdEncoding is the unpadded base64url Base64 encoding.
//
// It uses the following table:
//
//    ABCDEFGHIJKLMNOPQRSTUVWXYZ
//    abcdefghijklmnopqrstuvwxyz
//    0123456789
//    -_
//
var RawURLEncoding = &Encoding{
	encode:  urlEncode,
	decode:  urlDecode,
	padChar: NoPadding,
}

// Encoding is a particular Base64 encoding.
//
// See the package docs for a comparison with encoding/base64.
type Encoding struct {
	encode  func(dst, src []byte, padChar rune)
	decode  func(dst, src []byte, padChar rune, strict bool) (int, error)
	padChar rune
	strict  bool
}

// Strict returns an identical Encoding that operates in "strict"
// mode where all padding bits MUST be zero (see section 3.5 of
// RFC 4648 and golang.org/issues/15656).
func (e Encoding) Strict() *Encoding {
	e.strict = true
	return &e
}

// WithPadding returns an identical Encoding that uses the
// specified padding character.
//
// The padding character must be less than 0xff and cannot be
// '\r', '\n', or a character in the encoding's alphabet.
func (e Encoding) WithPadding(r rune) *Encoding {
	switch {
	case r == '\r', r == '\n', r > 0xff:
		panic("base64: invalid padding")
	// TODO(eric): this isn't exactly correct
	case urlRevLookup(uint(r)) != 0xff,
		stdRevLookup(uint(r)) != 0xff:
		panic("base64: padding contained in alphabet")
	}
	e.padChar = r
	return &e
}

// EncodedLen returns the size in bytes of the Base64 encoding
// of n source bytes.
func (e *Encoding) EncodedLen(n int) int {
	if e.padChar == NoPadding {
		return (n*8 + 5) / 6
	}
	return (n + 2) / 3 * 4
}

// DecodedLen returns the maximum length in bytes of n bytes of
// Base64-encoded data.
func (e *Encoding) DecodedLen(n int) int {
	if e.padChar == NoPadding {
		return n * 6 / 8
	}
	return n / 4 * 3
}

// Encode encodes src, writing writing EncodedLen(len(src)) bytes
// to dst.
//
// Encode runs in constant time for the length of src.
func (e *Encoding) Encode(dst, src []byte) {
	e.encode(dst, src, e.padChar)
}

// EncodeToString encodes src.
//
// EncodeToString runs in constant time for the length of src.
func (e *Encoding) EncodeToString(src []byte) string {
	dst := make([]byte, e.EncodedLen(len(src)))
	e.Encode(dst, src)
	return string(dst)
}

// Decode decodes src, writing at most DecodedLen(len(src)) bytes
// to dst.
//
// It returns the total number of bytes written to dst, even when
// src contains invalid Base64. If src contains invalid Base64,
// Decode returns ErrCorrupt.
//
// Decode runs in constant time for the length of src.
//
// See the package docs for a comparison with encoding/base64.
func (e *Encoding) Decode(dst, src []byte) (int, error) {
	return e.decode(dst, src, e.padChar, e.strict)
}

// DecodeString decodes src.
//
// It returns all bytes written to dst, even when src contains
// invalid Base64. If src contains invalid Base64, DecodeString
// returns ErrCorrupt.
//
// DecodeString runs in constant time for the length of src.
//
// See the package docs for a comparison with encoding/base64.
func (e *Encoding) DecodeString(src string) ([]byte, error) {
	dst := make([]byte, e.DecodedLen(len(src)))
	n, err := e.Decode(dst, []byte(src))
	return dst[:n], err
}

func stdEncode(dst, src []byte, padChar rune) {
	if len(src) == 0 {
		return
	}

	// Convert 6 -> 8 with at least 8 src bytes.
	for len(src) >= 8 && len(dst) >= 8 {
		u := binary.BigEndian.Uint64(src)
		binary.LittleEndian.PutUint64(dst, stdLookupSWAR6(u))
		src = src[6:]
		dst = dst[8:]
	}

	// Convert 3 -> 4 with at least 3 src bytes.
	for len(src) >= 3 {
		v := uint32(src[0])<<16 | uint32(src[1])<<8 | uint32(src[2])
		binary.LittleEndian.PutUint32(dst, stdLookupSWAR3(v<<8))
		src = src[3:]
		dst = dst[4:]
	}

	switch len(src) {
	case 2:
		v := uint(src[0])<<16 | uint(src[1])<<8
		dst[2] = stdLookup(v >> 6 & 0x3f)
		dst[1] = stdLookup(v >> 12 & 0x3f)
		dst[0] = stdLookup(v >> 18 & 0x3f)
		if padChar != NoPadding {
			dst[3] = byte(padChar)
		}
	case 1:
		v := uint(src[0]) << 16
		dst[1] = stdLookup(v >> 12 & 0x3f)
		dst[0] = stdLookup(v >> 18 & 0x3f)
		if padChar != NoPadding {
			dst[3] = byte(padChar)
			dst[2] = byte(padChar)
		}
	}
}

// stdLookup converts the 6-bit value c to its corresponding
// base64 character.
//
// c must be in [0, 63].
//
// See http://0x80.pl/notesen/2016-01-12-sse-base64-encoding.html
func stdLookup(c uint) byte {
	s := uint('A')
	s += (26 - c - 1) >> 8 & 6
	s -= (52 - c - 1) >> 8 & 75
	s -= (62 - c - 1) >> 8 & 15
	s += (63 - c - 1) >> 8 & 3
	return byte(c + s)
}

// stdLookupSWAR6 converts the 6 source bytes in [64:16] into
// 8 Base64 bytes.
//
// See http://0x80.pl/articles/avx512-foundation-base64.html
func stdLookupSWAR6(u uint64) uint64 {
	// AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD EEEEEEEE FFFFFFFF ........ ........
	// <<
	// DDDDDDDD EEEEEEEE FFFFFFFF ........ ........ ........ ........ ........
	// 11111111 11111111 11111111 ........ ........ ........ ........ ........
	// =
	// DDDDDDDD EEEEEEEE FFFFFFFF ........ ........ ........ ........ ........
	u0 := ((u << 24) & 0xff_ff_ff_00_00_00_00_00)
	// AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD EEEEEEEE FFFFFFFF ........ ........
	// >>
	// ........ ........ ........ ........ AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD
	// ........ ........ ........ ........ 11111111 11111111 11111111 ........
	// =
	// ........ ........ ........ ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	u1 := ((u >> 32) & 0x00_00_00_00_ff_ff_ff_00)

	// DDDDDDDD EEEEEEEE FFFFFFFF ........ ........ ........ ........ ........
	// ........ ........ ........ ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	// =
	// DDDDDDDD EEEEEEEE FFFFFFFF ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	v := u0 | u1

	var c uint64
	// DDDDDDDD EEEEEEEE FFFFFFFF ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	// >>
	// ........ ........ ........ ..DDDDDD DDEEEEEE EEFFFFFF FF...... ..AAAAAA
	// ........ ........ ........ ..111111 ........ ........ ........ ..111111
	// =
	// ........ ........ ........ ..DDDDDD ........ ........ ........ ..AAAAAA
	c |= (v >> 26) & 0x00_00_00_3f_00_00_00_3f

	// DDDDDDDD EEEEEEEE FFFFFFFF ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	// >>
	// ........ ....DDDD DDDDEEEE EEEEFFFF FFFF.... ....AAAA AAAABBBB BBBBCCCC
	// ........ ........ ..111111 ........ ........ ........ ..111111 ........
	// =
	// ........ ........ ..DDEEEE ........ ........ ........ ..AABBBB ........
	c |= (v >> 12) & 0x00_00_3f_00_00_00_3f_00

	// DDDDDDDD EEEEEEEE FFFFFFFF ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	// <<
	// DDDDDDEE EEEEEEFF FFFFFF.. ......AA AAAAAABB BBBBBBCC CCCCCC.. ........
	// ........ ..111111 ........ ........ ........ ..111111 ........ ........
	// =
	// ........ ..EEEEFF ........ ........ ........ ..BBBBCC ........ ........
	c |= (v << 2) & 0x00_3f_00_00_00_3f_00_00

	// DDDDDDDD EEEEEEEE FFFFFFFF ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	// <<
	// FFFFFFFF ........ AAAAAAAA BBBBBBBB CCCCCCCC ........ ........ ........
	// ..111111 ........ ........ ........ ..111111 ........ ........ ........
	// =
	// ..FFFFFF ........ ........ ........ ..CCCCCC ........ ........ ........
	c |= (v << 16) & 0x3f_00_00_00_3f_00_00_00

	// ........ ........ ........ ..DDDDDD ........ ........ ........ ..AAAAAA
	// ........ ........ ..DDEEEE ........ ........ ........ ..AABBBB ........
	// ........ ..EEEEFF ........ ........ ........ ..BBBBCC ........ ........
	// ..FFFFFF ........ ........ ........ ..CCCCCC ........ ........ ........
	// =
	// ..FFFFFF ..EEEEFF ..DDEEEE ..DDDDDD ..CCCCCC ..BBBBCC ..AABBBB ..AAAAAA

	const (
		msb = 0x8080808080808080
	)

	// if c[i] >= 26 { s[i] = 6 }
	c0 := (c + 0x6666666666666666) & msb
	c0 -= c0 >> 7
	c0 &= 0x0606060606060606

	// if c[i] >= 52 { s[i] = 187&0x7f }
	c1 := (c + 0x4c4c4c4c4c4c4c4c) & msb
	c1msb := c1
	c1 -= c1 >> 7
	c1 &= 0x3b3b3b3b3b3b3b3b

	// if c[i] >= 62 { s[i] = 17 }
	c2 := (c + 0x4242424242424242) & msb
	c2 -= c2 >> 7
	c2 &= 0x1111111111111111

	// if c[i] >= 63 { s[i] = 29 }
	c3 := (c + 0x4141414141414141) & msb
	c3 -= c3 >> 7
	c3 &= 0x1d1d1d1d1d1d1d1d

	s := 0x4141414141414141 ^ c0 ^ c1 ^ c2 ^ c3

	return (c + s) ^ c1msb
}

// stdLookupSWAR3 converts the 3 source bytes in [32:8] into
// 4 Base64 bytes.
//
// See http://0x80.pl/articles/avx512-foundation-base64.html
func stdLookupSWAR3(u uint32) uint32 {
	var c uint32
	// AAAAAAAA BBBBBBBB CCCCCCCC ........
	// >>
	// ........ ........ ........ ..AAAAAA
	// ........ ........ ........ ..111111
	// =
	// ........ ........ ........ ..AAAAAA
	c |= (u >> 26) & 0x00_00_00_3f

	// AAAAAAAA BBBBBBBB CCCCCCCC ........
	// >>
	// ........ ....AAAA AAAABBBB BBBBCCCC
	// ........ ........ ..111111 ........
	// =
	// ........ ........ ..AABBBB ........
	c |= (u >> 12) & 0x00_00_3f_00

	// AAAAAAAA BBBBBBBB CCCCCCCC ........
	// <<
	// AAAAAABB BBBBBBCC CCCCCC.. ........
	// ........ ..111111 ........ ........
	// =
	// ........ ..BBBBCC ........ ........
	c |= (u << 2) & 0x00_3f_00_00

	// AAAAAAAA BBBBBBBB CCCCCCCC ........
	// <<
	// CCCCCCCC ........ ........ ........
	// ..111111 ........ ........ ........
	// =
	// ..CCCCCC ........ ........ ........
	c |= (u << 16) & 0x3f_00_00_00

	// ........ ........ ........ ..AAAAAA
	// ........ ........ ..AABBBB ........
	// ........ ..BBBBCC ........ ........
	// ..CCCCCC ........ ........ ........
	// =
	// ..CCCCCC ..BBBBCC ..AABBBB ..AAAAAA

	const (
		msb = 0x80808080
	)

	// if c[i] >= 26 { s[i] = 6 }
	c0 := (c + 0x66666666) & msb
	c0 -= c0 >> 7
	c0 &= 0x06060606

	// if c[i] >= 52 { s[i] = 187&0x7f }
	c1 := (c + 0x4c4c4c4c) & msb
	c1msb := c1
	c1 -= c1 >> 7
	c1 &= 0x3b3b3b3b

	// if c[i] >= 62 { s[i] = 17 }
	c2 := (c + 0x42424242) & msb
	c2 -= c2 >> 7
	c2 &= 0x11111111

	// if c[i] >= 63 { s[i] = 29 }
	c3 := (c + 0x41414141) & msb
	c3 -= c3 >> 7
	c3 &= 0x1d1d1d1d

	s := 0x41414141 ^ c0 ^ c1 ^ c2 ^ c3

	return (c + s) ^ c1msb
}

func stdDecode(dst, src []byte, padChar rune, strict bool) (n int, err error) {
	if len(src) == 0 {
		return 0, nil
	}
	switch len(src) % 4 {
	case 0:
		// OK
	case 2, 3:
		if padChar != NoPadding {
			// Padded base64 should be a multiple of 4.
			return 0, ErrCorrupt
		}
	default:
		// Even unpadded base64 only has a 2-3 character partial
		// block.
		return 0, ErrCorrupt
	}

	if padChar != NoPadding {
		var t int
		t += subtle.ConstantTimeByteEq(src[len(src)-1], byte(padChar))
		t += subtle.ConstantTimeByteEq(src[len(src)-2], byte(padChar))
		src = src[:len(src)-t]
	}

	var failed byte
	for len(src) >= 8 && len(dst)-n >= 8 {
		c0 := stdRevLookup(uint(src[0]))
		c1 := stdRevLookup(uint(src[1]))
		c2 := stdRevLookup(uint(src[2]))
		c3 := stdRevLookup(uint(src[3]))
		c4 := stdRevLookup(uint(src[4]))
		c5 := stdRevLookup(uint(src[5]))
		c6 := stdRevLookup(uint(src[6]))
		c7 := stdRevLookup(uint(src[7]))

		c := uint64(c0)<<58 |
			uint64(c1)<<52 |
			uint64(c2)<<46 |
			uint64(c3)<<40 |
			uint64(c4)<<34 |
			uint64(c5)<<28 |
			uint64(c6)<<22 |
			uint64(c7)<<16
		binary.BigEndian.PutUint64(dst[n:], c)

		failed |= c0 | c1 | c2 | c3 | c4 | c5 | c6 | c7

		src = src[8:]
		n += 6
	}

	for len(src) >= 4 && len(dst)-n >= 4 {
		c0 := stdRevLookup(uint(src[0]))
		c1 := stdRevLookup(uint(src[1]))
		c2 := stdRevLookup(uint(src[2]))
		c3 := stdRevLookup(uint(src[3]))

		c := uint32(c0)<<26 |
			uint32(c1)<<20 |
			uint32(c2)<<14 |
			uint32(c3)<<8
		binary.BigEndian.PutUint32(dst[n:], c)

		failed |= c0 | c1 | c2 | c3

		src = src[4:]
		n += 3
	}

	for len(src) >= 4 {
		c0 := stdRevLookup(uint(src[0]))
		c1 := stdRevLookup(uint(src[1]))
		c2 := stdRevLookup(uint(src[2]))
		c3 := stdRevLookup(uint(src[3]))

		dst[n+0] = byte(c0<<2 | c1>>4)
		dst[n+1] = byte(c1<<4 | c2>>2)
		dst[n+2] = byte(c2<<6 | c3)

		failed |= c0 | c1 | c2 | c3

		src = src[4:]
		n += 3
	}

	switch len(src) {
	case 3:
		c0 := stdRevLookup(uint(src[0]))
		c1 := stdRevLookup(uint(src[1]))
		c2 := stdRevLookup(uint(src[2]))

		dst[n+0] = byte(c0<<2 | c1>>4)
		dst[n+1] = byte(c1<<4 | c2>>2)

		failed |= c0 | c1 | c2
		if strict {
			// Fail if any bits in [3:0] are non-zero.
			failed |= byte((0 - uint(c2&0x3)) >> 8)
		}
		n += 2
	case 2:
		c0 := stdRevLookup(uint(src[0]))
		c1 := stdRevLookup(uint(src[1]))

		dst[n+0] = byte(c0<<2 | c1>>4)

		failed |= c0 | c1
		if strict {
			// Fail if any bits in [4:0] are non-zero.
			failed |= byte((0 - uint(c1&0xf)) >> 8)
		}
		n++
	case 0:
		// OK
	default:
		failed |= 0xff
	}

	if failed&0xff == 0xff {
		err = ErrCorrupt
	}
	return
}

// stdRevLookup converts the base64 character c to its 6-bit
// binary value.
//
// If the character is invalid stdRevLookup returns 0xff.
func stdRevLookup(c uint) (r byte) {
	// NB. This function is written like this so that the
	// compiler (as of 1.18.1) will inline it.

	// switch {
	// case >= 'A' && c <= 'Z':
	//     s = -65
	// case c >= 'a' && c <= 'z'
	//     s = -71
	// case c >= '0' && c <= '9'
	//     s = 4
	// case c == '+':
	//     s = 19
	// case c == '/':
	//     s = 16
	// }
	s := ((((64 - c) & (c - 91)) >> 8) & 191) ^
		((((96 - c) & (c - 123)) >> 8) & 185) ^
		((((47 - c) & (c - 58)) >> 8) & 4) ^
		((((42 - c) & (c - 44)) >> 8) & 19) ^
		((((46 - c) & (c - 48)) >> 8) & 16)
	// If s == 0 then the input is corrupt.
	//
	// Since s is one of {0, 191, 185, 4, 19, 6}, shift off bits
	// [8:0] (which are allowed to be non-zero) and check [16:8].
	return byte((s+c)&0x3f | ((((0 - s) >> 8) & 0xff) ^ 0xff))
}

func urlEncode(dst, src []byte, padChar rune) {
	if len(src) == 0 {
		return
	}

	// Convert 6 -> 8 with at least 8 src bytes.
	for len(src) >= 8 && len(dst) >= 8 {
		u := binary.BigEndian.Uint64(src)
		binary.LittleEndian.PutUint64(dst, urlLookupSWAR6(u))
		src = src[6:]
		dst = dst[8:]
	}

	// Convert 3 -> 4 with at least 3 src bytes.
	for len(src) >= 3 {
		v := uint32(src[0])<<16 | uint32(src[1])<<8 | uint32(src[2])
		binary.LittleEndian.PutUint32(dst, urlLookupSWAR3(v<<8))
		src = src[3:]
		dst = dst[4:]
	}

	switch len(src) {
	case 2:
		v := uint(src[0])<<16 | uint(src[1])<<8
		dst[2] = urlLookup(v >> 6 & 0x3f)
		dst[1] = urlLookup(v >> 12 & 0x3f)
		dst[0] = urlLookup(v >> 18 & 0x3f)
		if padChar != NoPadding {
			dst[3] = byte(padChar)
		}
	case 1:
		v := uint(src[0]) << 16
		dst[1] = urlLookup(v >> 12 & 0x3f)
		dst[0] = urlLookup(v >> 18 & 0x3f)
		if padChar != NoPadding {
			dst[3] = byte(padChar)
			dst[2] = byte(padChar)
		}
	}
}

// urlLookup converts the 6-bit value c to its corresponding
// base64 character.
//
// c must be in [0, 63].
//
// See http://0x80.pl/notesen/2016-01-12-sse-base64-encoding.html
func urlLookup(c uint) byte {
	// Start with an initial guess that c is in [0, 25], making
	// the shift 'A' (65).
	s := uint('A')

	// If c is greater than 25, guess that c is in [26, 51] and
	// adjust the shift by adding 6 since
	//    'a' - (26+'A') = 6
	//    'b' - (27+'A') = 6
	//    ...
	//    'z' - (51+'A') = 6
	// The shift is now 71.
	s += (26 - c - 1) >> 8 & 6

	// If c is greater than 51, guess that c is in [52, 61] and
	// adjust the shift by subtracting 75 since
	//    '0' - (52+71) = -75
	//    '0' - (53+71) = -75
	//    ...
	//    '0' - (61+71) = -75
	// The shift is now -4 mod 2^64.
	s -= (52 - c - 1) >> 8 & 75

	// If c is greater than 61, guess that c == 62 and adjust
	// the shift by adding 13 since
	//    '-' - (62-4) = 13
	// The shift is now -17 mode 2^64.
	s -= (62 - c - 1) >> 8 & 13

	// If c is greater than 62, guess that c == 63 and adjust the
	// shift by adding 49 since
	//    '_' - (63-17) = 49
	// The shift is now 32.
	s += (63 - c - 1) >> 8 & 49

	return byte(c + s)
}

// urlLookupSWAR6 converts the 6 source bytes in [64:16] into
// 8 Base64 bytes.
//
// See http://0x80.pl/articles/avx512-foundation-base64.html
func urlLookupSWAR6(u uint64) uint64 {
	// AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD EEEEEEEE FFFFFFFF ........ ........
	// <<
	// DDDDDDDD EEEEEEEE FFFFFFFF ........ ........ ........ ........ ........
	// 11111111 11111111 11111111 ........ ........ ........ ........ ........
	// =
	// DDDDDDDD EEEEEEEE FFFFFFFF ........ ........ ........ ........ ........
	u0 := ((u << 24) & 0xff_ff_ff_00_00_00_00_00)
	// AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD EEEEEEEE FFFFFFFF ........ ........
	// >>
	// ........ ........ ........ ........ AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD
	// ........ ........ ........ ........ 11111111 11111111 11111111 ........
	// =
	// ........ ........ ........ ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	u1 := ((u >> 32) & 0x00_00_00_00_ff_ff_ff_00)

	// DDDDDDDD EEEEEEEE FFFFFFFF ........ ........ ........ ........ ........
	// ........ ........ ........ ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	// =
	// DDDDDDDD EEEEEEEE FFFFFFFF ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	v := u0 | u1

	var c uint64
	// DDDDDDDD EEEEEEEE FFFFFFFF ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	// >>
	// ........ ........ ........ ..DDDDDD DDEEEEEE EEFFFFFF FF...... ..AAAAAA
	// ........ ........ ........ ..111111 ........ ........ ........ ..111111
	// =
	// ........ ........ ........ ..DDDDDD ........ ........ ........ ..AAAAAA
	c |= (v >> 26) & 0x00_00_00_3f_00_00_00_3f

	// DDDDDDDD EEEEEEEE FFFFFFFF ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	// >>
	// ........ ....DDDD DDDDEEEE EEEEFFFF FFFF.... ....AAAA AAAABBBB BBBBCCCC
	// ........ ........ ..111111 ........ ........ ........ ..111111 ........
	// =
	// ........ ........ ..DDEEEE ........ ........ ........ ..AABBBB ........
	c |= (v >> 12) & 0x00_00_3f_00_00_00_3f_00

	// DDDDDDDD EEEEEEEE FFFFFFFF ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	// <<
	// DDDDDDEE EEEEEEFF FFFFFF.. ......AA AAAAAABB BBBBBBCC CCCCCC.. ........
	// ........ ..111111 ........ ........ ........ ..111111 ........ ........
	// =
	// ........ ..EEEEFF ........ ........ ........ ..BBBBCC ........ ........
	c |= (v << 2) & 0x00_3f_00_00_00_3f_00_00

	// DDDDDDDD EEEEEEEE FFFFFFFF ........ AAAAAAAA BBBBBBBB CCCCCCCC ........
	// <<
	// FFFFFFFF ........ AAAAAAAA BBBBBBBB CCCCCCCC ........ ........ ........
	// ..111111 ........ ........ ........ ..111111 ........ ........ ........
	// =
	// ..FFFFFF ........ ........ ........ ..CCCCCC ........ ........ ........
	c |= (v << 16) & 0x3f_00_00_00_3f_00_00_00

	// ........ ........ ........ ..DDDDDD ........ ........ ........ ..AAAAAA
	// ........ ........ ..DDEEEE ........ ........ ........ ..AABBBB ........
	// ........ ..EEEEFF ........ ........ ........ ..BBBBCC ........ ........
	// ..FFFFFF ........ ........ ........ ..CCCCCC ........ ........ ........
	// =
	// ..FFFFFF ..EEEEFF ..DDEEEE ..DDDDDD ..CCCCCC ..BBBBCC ..AABBBB ..AAAAAA

	const (
		msb = 0x8080808080808080
	)

	// if c[i] >= 26 { s[i] = 6 }
	c0 := (c + 0x6666666666666666) & msb
	c0 -= c0 >> 7
	c0 &= 0x0606060606060606

	// if c[i] >= 52 { s[i] = 187&0x7f }
	c1 := (c + 0x4c4c4c4c4c4c4c4c) & msb
	c1msb := c1
	c1 -= c1 >> 7
	c1 &= 0x3b3b3b3b3b3b3b3b

	// if c[i] >= 62 { s[i] = 13 }
	c2 := (c + 0x4242424242424242) & msb
	c2 -= c2 >> 7
	c2 &= 0x0d0d0d0d0d0d0d0d

	// if c[i] >= 63 { s[i] = 49 }
	c3 := (c + 0x4141414141414141) & msb
	c3 -= c3 >> 7
	c3 &= 0x3131313131313131

	s := 0x4141414141414141 ^ c0 ^ c1 ^ c2 ^ c3

	return (c + s) ^ c1msb
}

// urlLookupSWAR3 converts the 3 source bytes in [32:8] into
// 4 Base64 bytes.
//
// See http://0x80.pl/articles/avx512-foundation-base64.html
func urlLookupSWAR3(u uint32) uint32 {
	var c uint32
	// AAAAAAAA BBBBBBBB CCCCCCCC ........
	// >>
	// ........ ........ ........ ..AAAAAA
	// ........ ........ ........ ..111111
	// =
	// ........ ........ ........ ..AAAAAA
	c |= (u >> 26) & 0x00_00_00_3f

	// AAAAAAAA BBBBBBBB CCCCCCCC ........
	// >>
	// ........ ....AAAA AAAABBBB BBBBCCCC
	// ........ ........ ..111111 ........
	// =
	// ........ ........ ..AABBBB ........
	c |= (u >> 12) & 0x00_00_3f_00

	// AAAAAAAA BBBBBBBB CCCCCCCC ........
	// <<
	// AAAAAABB BBBBBBCC CCCCCC.. ........
	// ........ ..111111 ........ ........
	// =
	// ........ ..BBBBCC ........ ........
	c |= (u << 2) & 0x00_3f_00_00

	// AAAAAAAA BBBBBBBB CCCCCCCC ........
	// <<
	// CCCCCCCC ........ ........ ........
	// ..111111 ........ ........ ........
	// =
	// ..CCCCCC ........ ........ ........
	c |= (u << 16) & 0x3f_00_00_00

	// ........ ........ ........ ..AAAAAA
	// ........ ........ ..AABBBB ........
	// ........ ..BBBBCC ........ ........
	// ..CCCCCC ........ ........ ........
	// =
	// ..CCCCCC ..BBBBCC ..AABBBB ..AAAAAA

	const (
		msb = 0x80808080
	)

	// if c[i] >= 26 { s[i] = 6 }
	c0 := (c + 0x66666666) & msb
	c0 -= c0 >> 7
	c0 &= 0x06060606

	// if c[i] >= 52 { s[i] = 187&0x7f }
	c1 := (c + 0x4c4c4c4c) & msb
	c1msb := c1
	c1 -= c1 >> 7
	c1 &= 0x3b3b3b3b

	// if c[i] >= 62 { s[i] = 17 }
	c2 := (c + 0x42424242) & msb
	c2 -= c2 >> 7
	c2 &= 0x11111111

	// if c[i] >= 63 { s[i] = 29 }
	c3 := (c + 0x41414141) & msb
	c3 -= c3 >> 7
	c3 &= 0x1d1d1d1d

	s := 0x41414141 ^ c0 ^ c1 ^ c2 ^ c3

	return (c + s) ^ c1msb
}

func urlDecode(dst, src []byte, padChar rune, strict bool) (n int, err error) {
	if len(src) == 0 {
		return 0, nil
	}
	switch len(src) % 4 {
	case 0:
		// OK
	case 2, 3:
		if padChar != NoPadding {
			// Padded base64 should be a multiple of 4.
			return 0, ErrCorrupt
		}
	default:
		// Even unpadded base64 only has a 2-3 character partial
		// block.
		return 0, ErrCorrupt
	}

	if padChar != NoPadding {
		var t int
		t += subtle.ConstantTimeByteEq(src[len(src)-1], byte(padChar))
		t += subtle.ConstantTimeByteEq(src[len(src)-2], byte(padChar))
		src = src[:len(src)-t]
	}

	var failed byte
	for len(src) >= 8 && len(dst)-n >= 8 {
		c0 := urlRevLookup(uint(src[0]))
		c1 := urlRevLookup(uint(src[1]))
		c2 := urlRevLookup(uint(src[2]))
		c3 := urlRevLookup(uint(src[3]))
		c4 := urlRevLookup(uint(src[4]))
		c5 := urlRevLookup(uint(src[5]))
		c6 := urlRevLookup(uint(src[6]))
		c7 := urlRevLookup(uint(src[7]))

		c := uint64(c0)<<58 |
			uint64(c1)<<52 |
			uint64(c2)<<46 |
			uint64(c3)<<40 |
			uint64(c4)<<34 |
			uint64(c5)<<28 |
			uint64(c6)<<22 |
			uint64(c7)<<16
		binary.BigEndian.PutUint64(dst[n:], c)

		failed |= c0 | c1 | c2 | c3 | c4 | c5 | c6 | c7

		src = src[8:]
		n += 6
	}

	for len(src) >= 4 && len(dst)-n >= 4 {
		c0 := urlRevLookup(uint(src[0]))
		c1 := urlRevLookup(uint(src[1]))
		c2 := urlRevLookup(uint(src[2]))
		c3 := urlRevLookup(uint(src[3]))

		c := uint32(c0)<<26 |
			uint32(c1)<<20 |
			uint32(c2)<<14 |
			uint32(c3)<<8
		binary.BigEndian.PutUint32(dst[n:], c)

		failed |= c0 | c1 | c2 | c3

		src = src[4:]
		n += 3
	}

	for len(src) >= 4 {
		c0 := urlRevLookup(uint(src[0]))
		c1 := urlRevLookup(uint(src[1]))
		c2 := urlRevLookup(uint(src[2]))
		c3 := urlRevLookup(uint(src[3]))

		dst[n+0] = byte(c0<<2 | c1>>4)
		dst[n+1] = byte(c1<<4 | c2>>2)
		dst[n+2] = byte(c2<<6 | c3)

		failed |= c0 | c1 | c2 | c3

		src = src[4:]
		n += 3
	}

	switch len(src) {
	case 3:
		c0 := urlRevLookup(uint(src[0]))
		c1 := urlRevLookup(uint(src[1]))
		c2 := urlRevLookup(uint(src[2]))

		dst[n+0] = byte(c0<<2 | c1>>4)
		dst[n+1] = byte(c1<<4 | c2>>2)

		failed |= c0 | c1 | c2
		if strict {
			// Fail if any bits in [3:0] are non-zero.
			failed |= byte((0 - uint(c2&0x3)) >> 8)
		}
		n += 2
	case 2:
		c0 := urlRevLookup(uint(src[0]))
		c1 := urlRevLookup(uint(src[1]))

		dst[n+0] = byte(c0<<2 | c1>>4)

		failed |= c0 | c1
		if strict {
			// Fail if any bits in [4:0] are non-zero.
			failed |= byte((0 - uint(c1&0xf)) >> 8)
		}
		n++
	case 0:
		// OK
	default:
		failed |= 0xff
	}

	if failed&0xff == 0xff {
		err = ErrCorrupt
	}
	return
}

// urlRevLookup converts the base64 character c to its 6-bit
// binary value.
//
// If the character is invalid urlRevLookup returns 0xff.
func urlRevLookup(c uint) (r byte) {
	// NB. This function is written like this so that the
	// compiler (as of 1.18.1) will inline it.

	// switch {
	// case >= 'A' && c <= 'Z':
	//     s = -65
	// case c >= 'a' && c <= 'z'
	//     s = -71
	// case c >= '0' && c <= '9'
	//     s = 4
	// case c == '+':
	//     s = 19
	// case c == '/':
	//     s = 16
	// }
	s := ((((64 - c) & (c - 91)) >> 8) & 191) ^
		((((96 - c) & (c - 123)) >> 8) & 185) ^
		((((47 - c) & (c - 58)) >> 8) & 4) ^
		((((42 - c) & (c - 44)) >> 8) & 19) ^
		((((46 - c) & (c - 48)) >> 8) & 16)
	// If s == 0 then the input is corrupt.
	//
	// Since s is one of {0, 191, 185, 4, 19, 6}, shift off bits
	// [8:0] (which are allowed to be non-zero) and check [16:8].
	return byte((s+c)&0x3f | ((((0 - s) >> 8) & 0xff) ^ 0xff))
}
