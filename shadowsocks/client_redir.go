// +build linux

package shadowsocks

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

const SO_ORIGINAL_DST = 80

func ntohs(in uint16) (out uint16) {
	data := [2]byte{}
	binary.LittleEndian.PutUint16(data[:], in)
	if uint16(data[0]) == in&0xff { // LE
		return binary.BigEndian.Uint16(data[:])
	} else { // BE
		return in
	}
}

func getOrigAddr(conn *net.TCPConn) (*net.TCPAddr, error) {
	f, err := conn.File()
	if err != nil {
		return nil, err
	}
	fd := f.Fd()
	syscall.SetNonblock(int(fd), true)

	saddr := syscall.RawSockaddrInet4{}
	size := unsafe.Sizeof(saddr)
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_IP, SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&saddr)), uintptr(unsafe.Pointer(&size)), 0)
	if errno == 0 {
		res := &net.TCPAddr{
			IP:   net.IPv4(saddr.Addr[0], saddr.Addr[1], saddr.Addr[2], saddr.Addr[3]),
			Port: int(ntohs(saddr.Port)),
		}
		return res, nil
	}

	saddr6 := syscall.RawSockaddrInet6{}
	size6 := unsafe.Sizeof(saddr6)
	_, _, errno6 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_IPV6, SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&saddr6)), uintptr(unsafe.Pointer(&size6)), 0)
	if errno6 == 0 {
		res := &net.TCPAddr{
			IP:   net.IP(append([]byte(nil), saddr6.Addr[:]...)),
			Port: int(ntohs(saddr6.Port)),
		}
		return res, nil
	}
	return nil, nil
}

func DetectRedir(tconn SSConn) bool {
	c := tconn.(PlainConn).TCPConn
	addr := c.LocalAddr().(*net.TCPAddr)
	orig, err := getOrigAddr(c)
	if err != nil {
		return false
	}
	if orig.IP.Equal(addr.IP) && orig.Port == addr.Port {
		return false
	}
	return true
}

func (ctx *ClientContext) HandleRedir(tconn SSConn, buf *SSBuffer) error {
	return nil
}
