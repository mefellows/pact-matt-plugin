package ffi

/*
#cgo darwin,arm64 LDFLAGS: -L. -L./osx_aarch64  -lpact_ffi
#cgo darwin,amd64 LDFLAGS: -L. -L./osx_x86_64  -lpact_ffi
#cgo windows,amd64 LDFLAGS: -lpact_ffi
#cgo linux,amd64 LDFLAGS: -L. -L./linux_x86_64 -lpact_ffi
#cgo linux,arm64 LDFLAGS: -L. -L./linux_aarch64 -lpact_ffi
*/
import "C"
