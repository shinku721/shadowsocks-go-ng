// +build linux,386

package shadowsocks

import (
	"syscall"
	"unsafe"
)

const GETSOCKOPT = 15

func getsockopt(fd, level, option_name int, option_value, option_len uintptr) error {
	var data [6]uintptr
	data[0], data[1], data[2], data[3], data[4], data[5] = uintptr(fd), uintptr(level),
		uintptr(option_name), option_value, option_len, 0
	_, _, errno := syscall.Syscall6(syscall.SYS_SOCKETCALL, GETSOCKOPT, uintptr(unsafe.Pointer(&data)), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
