package shadowsocks

type DelayInitConn struct {
	origConn SSConn
	initBuf  []byte
}

func (c *DelayInitConn) SSRead(buf *SSBuffer) error {
	return c.origConn.SSRead(buf)
}

func (c *DelayInitConn) SSWrite(buf *SSBuffer) error {
	if c.initBuf != nil {
		li := len(c.initBuf)
		lb := len(buf.buf)
		tmpbuf := make([]byte, li+lb)
		copy(tmpbuf[:li], c.initBuf)
		copy(tmpbuf[li:], buf.buf)
		c.initBuf = nil
		return c.origConn.SSWrite(&SSBuffer{buf: tmpbuf})
	}
	return c.origConn.SSWrite(buf)
}

func (c *DelayInitConn) Close() error {
	return c.origConn.Close()
}

func (c *DelayInitConn) Alive() bool {
	return c.origConn.Alive()
}

func (c *DelayInitConn) RemoteAddr() string {
	return c.origConn.RemoteAddr()
}

func NewDelayInitConn(conn SSConn, initBuf []byte) *DelayInitConn {
	return &DelayInitConn{
		origConn: conn,
		initBuf:  initBuf,
	}
}
