// +build linux,!386

package shadowsocks

import "syscall"

func getsockopt(fd, level, option_name int, option_value, option_len uintptr) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(level),
		uintptr(option_name), option_value, option_len, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
