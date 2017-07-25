package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

// IsIP checks whether the name is an IP address,
// and returns IP version. Returns 0 on failure.
func IsIP(host string) int {
  ip := net.ParseIP(host)
	if ip == nil {
		return 0
	}
	if strings.Contains(host, ":") {
		return 6
	}
	return 4
}

func WrapAddr(host string, port uint16) string {
	if IsIP(host) == 6 {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(int(port))
}

// ParseAddress parses an address buffer into string.
// It returns resulting address, length of bytes required,
// and error if exists.
// You must check that len(buf) >= n, otherwise addr is not
// a valid address.
func ParseAddress(buf []byte) (addr string, n int, err error) {
	if len(buf) < 2 {
		n = 2
		return
	}
	typ := buf[0]
	if typ == 0x1 { // ipv4
		n = 7
		if len(buf) < n {
			return
		}
		host := net.IPv4(buf[1], buf[2], buf[3], buf[4]).String()
		var p16 uint16
		binary.Read(bytes.NewBuffer(buf[5:7]), binary.BigEndian, &p16)
		port := strconv.Itoa(int(p16))
		addr = "[" + host + "]:" + port
	} else if typ == 0x3 { // host
		alen := int(buf[1])
		n = 1 + 1 + alen + 2
		if len(buf) < n {
			return
		}
		host := string(buf[2 : 2+alen])
		if IsIP(host) == 6 {
			host = "[" + host + "]"
		}
		var p16 uint16
		binary.Read(bytes.NewBuffer(buf[2+alen:n]), binary.BigEndian, &p16)
		port := strconv.Itoa(int(p16))
		addr = host + ":" + port
	} else if typ == 0x4 { // ipv6
		n = 19
		if len(buf) < n {
			return
		}
		host := net.IP(buf[1:17]).String()
		var p16 uint16
		binary.Read(bytes.NewBuffer(buf[17:19]), binary.BigEndian, &p16)
		port := strconv.Itoa(int(p16))
		addr = "[" + host + "]:" + port
	} else { // error
		err = ERR_INVALID_ADDR_TYPE
	}
	return
}
