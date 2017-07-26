package shadowsocks

/* DetectSocks5 detects whether the buffer contains valid socks5 request.
   Protocol definition: RFC 1928
   https://www.ietf.org/rfc/rfc1928.txt
*/
func DetectSocks5(buf *SSBuffer) bool {
	if len(buf.buf) < 3 {
		return false
	}
	if buf.buf[0] == 0x05 { // version
		nmethod := int(buf.buf[1])
		if len(buf.buf) < 2+nmethod {
			return false
		}
		return true
	} else {
		return false
	}
}

// HandleSocks5 handles a socks5 connection.
func (ctx *ClientContext) HandleSocks5(tconn SSConn, buf *SSBuffer) (err error) {
	nmethod := int(buf.buf[1])
	hasNoAuth := false
	for i := 0; i < nmethod; i++ {
		if buf.buf[2+i] == 0x00 {
			hasNoAuth = true
			break
		}
	}

	rbuf := NewBuffer()
	if !hasNoAuth {
		rbuf.buf = []byte{0x05, 0xFF}
		tconn.SSWrite(rbuf)
		return ERR_SOCKS5_NO_VALID_AUTH
	}
	rbuf.buf = rbuf.buf[:2]
	copy(rbuf.buf, []byte{0x05, 0x00})
	tconn.SSWrite(rbuf)

	buf.buf = buf.buf[:0]
	for len(buf.buf) < 7 {
		if err = tconn.SSRead(buf); err != nil {
			return
		}
	}
	cmd := buf.buf[1]
	if cmd != 0x01 {
		return ERR_SOCKS5_COMMAND_NOT_SUPPORTED
	}
	atyp := buf.buf[3]
	var hostlen int
	if atyp == 0x01 { // IPv4
		hostlen = 4
	} else if atyp == 0x04 { // IPv6
		hostlen = 16
	} else if atyp == 0x03 { // Host
		hostlen = 1 + int(buf.buf[4])
	} else {
		return ERR_SOCKS5_INVALID_PROTOCOL
	}
	for len(buf.buf) < 4+hostlen+2 {
		if err = tconn.SSRead(buf); err != nil {
			return
		}
	}
	copy(buf.buf, buf.buf[3:])
	buf.buf = buf.buf[:len(buf.buf)-3]

	rbuf.buf = rbuf.buf[:10]
	// We have no server bound address!
	copy(rbuf.buf, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err = tconn.SSWrite(rbuf); err != nil {
		return
	}

	err = tconn.(PlainConn).SSReadTimeout(buf, 5) // Wait 5 millis for data
	if err != nil {
		return
	}

	var wrconn SSConn
	wrconn, err = ctx.DialServer()
	if err != nil {
		return
	}
	defer wrconn.Close()

	res := make(chan error, 1)
	DPipe(tconn, wrconn, buf, rbuf, res)

	err = <-res
	return
}
