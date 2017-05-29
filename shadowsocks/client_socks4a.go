package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
)

var SOCKS4_INVALID_PROTOCOL = errors.New("Invalid socks4 protocol")
var SOCKS4_COMMAND_NOT_SUPPORTED = errors.New("Unsupported socks4 command")

/* DetectSocks4 detects whether the buffer contains a valid socks4(a) request.
   Protocol definition:
   https://www.openssh.com/txt/socks4.protocol
   https://www.openssh.com/txt/socks4a.protocol
*/
func DetectSocks4(buf *SSBuffer) bool {
	if len(buf.buf) < 9 {
		return false
	}
	if buf.buf[0] == 0x04 { // version
		return true
	} else {
		return false
	}
}

// HandleSocks4 handles a socks4(a) connection.
func (ctx *ClientContext) HandleSocks4(tconn SSConn, buf *SSBuffer) (err error) {
	cmd := buf.buf[1]
	if cmd != 0x01 {
		return SOCKS4_COMMAND_NOT_SUPPORTED
	}

	var port uint16
	binary.Read(bytes.NewBuffer(buf.buf[2:4]), binary.BigEndian, &port)
	if buf.buf[4] == 0 && buf.buf[5] == 0 && buf.buf[6] == 0 { // socks4a
		var firstNul, secondNul int
		for i := 8; ; i++ {
			if i >= len(buf.buf) {
				if err = tconn.SSRead(buf); err != nil {
					return
				}
			}
			if buf.buf[i] == 0 {
				if firstNul == 0 {
					firstNul = i
				} else {
					secondNul = i
					break
				}
			}
		}
		hostlen := secondNul - firstNul - 1
		if hostlen > 255 {
			return SOCKS4_INVALID_PROTOCOL
		}
		buf.buf = buf.buf[:2+hostlen+2]
		buf.buf[0] = 0x03 // Host
		buf.buf[1] = byte(hostlen)
		copy(buf.buf[2:2+hostlen], buf.buf[firstNul+1:secondNul])
		binary.Write(bytes.NewBuffer(buf.buf[:2+hostlen]), binary.BigEndian, &port)
	} else { // plain socks4
		// eat userid
		for i := 8; ; i++ {
			if i >= len(buf.buf) {
				if err = tconn.SSRead(buf); err != nil {
					return
				}
			}
			if buf.buf[i] == 0 {
				break
			}
		}
		buf.buf = buf.buf[:7]
		buf.buf[0] = 0x01 // IPv4
		copy(buf.buf[1:5], buf.buf[4:8])
		binary.Write(bytes.NewBuffer(buf.buf[:5]), binary.BigEndian, &port)
	}

	rbuf := NewBuffer()
	rbuf.buf = rbuf.buf[:8]
	copy(rbuf.buf, []byte{0x00, 0x5a})
	tconn.SSWrite(rbuf)

	err = tconn.(PlainConn).SSReadTimeout(buf, 5) // Wait 5 millis for data
	if err != nil {
		return
	}

	var rconn net.Conn
	rconn, err = net.Dial("tcp", ctx.serverAddr)
	if err != nil {
		return
	}
	defer rconn.Close()
	rconn.(*net.TCPConn).SetNoDelay(true)
	trconn := PlainConn{rconn.(*net.TCPConn)}
	wrconn := ctx.cipherFactory.Wrap(trconn)

	res := make(chan error, 1)
	rres := make(chan error, 1)
	go Pipe(tconn, wrconn, buf, res)
	go Pipe(wrconn, tconn, rbuf, rres)

	select {
	case err = <-res:
	case err = <-rres:
	}
	return
}
