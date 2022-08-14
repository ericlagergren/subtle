// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !amd64 && !arm64 && !ppc64 && !ppc64le

package subtle

import (
	"runtime"
	"unsafe"
)

const wordSize = int(unsafe.Sizeof(uintptr(0)))
const supportsUnaligned = runtime.GOARCH == "386" || runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le" || runtime.GOARCH == "s390x"

func xorBytes(dst, x, y *byte, n int) {
	if supportsUnaligned || aligned(dst, x, y, n) {
		xorWordsLoop(dst, x, y, n)
	} else {
		xorBytesLoop(dst, x, y, n)
	}
}

func aligned(dst, x, y *byte, n int) bool {
	return (uintptr(unsafe.Pointer(dst))|uintptr(unsafe.Pointer(x))|uintptr(unsafe.Pointer(y))|uintptr(n))&(wordSize-1) == 0
}

func xorWordsLoop(dst, x, y *byte, n int) {
	n /= wordSize
	dstw := unsafe.Slice((*uintptr)(unsafe.Pointer(dst)), n)
	xw := unsafe.Slice((*uintptr)(unsafe.Pointer(x)), n)
	yw := unsafe.Slice((*uintptr)(unsafe.Pointer(y)), n)
	for i := 0; i < n; i++ {
		dstw[i] = xw[i] ^ yw[i]
	}
}

func xorBytesLoop(dst, x, y *byte, n int) {
	// Hoist bounds checks.
	_ = dst[n-1]
	_ = x[n-1]
	_ = y[n-1]

	for i := 0; i < n; i++ {
		dst[i] = x[i] ^ y[i]
	}
}
