// Package base64 implements constant-time base64 encoding and
// decoding as specified by RFC 4648.
//
// Comparison to encoding/base64
//
// This package is almost, but not exactly a drop-in replacement
// for encoding/base64.
//
// Unlike encoding/base64, this package rejects the newline
// characters '\r' and '\n'.
//
// Unlike encoding/base64, this package does not return partial
// Base64-encoded data. For example:
//
//    src := []byte("aGVsb?8=")
//    StdEncoding.Decode(dst, src) // 3, CorruptInputError(5)
//    StdDecode(dst, src)          // 5, ErrCorrupt
//
// Given the input "aGVsb?8=" encoding/base64 will return (3,
// CorruptInputError(5)). However, this package will return (5,
// ErrCorrupt).
//
// These restrictions may be lifted in the future.
package base64
