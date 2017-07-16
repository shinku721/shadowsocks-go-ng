package shadowsocks

type DelayInitConn struct {
  origConn SSConn
  initBuf []byte
}

func (c *DelayInitConn) SSRead(buf *SSBuffer) error {
  return c.origConn.SSRead(buf)
}

func (c *DelayInitConn) SSWrite(buf *SSBuffer) error {
  if c.initBuf != nil {
    li := len(c.initBuf)
    lb := len(buf.buf)
    if li + lb > cap(buf.buf) {
      if err := buf.Expand(li + lb); err != nil {
        return err
      }
    }
    copy(buf.buf[li:li+lb], buf.buf[:lb])
    copy(buf.buf[:li], c.initBuf)
    c.initBuf = nil
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

func NewDelayInitConn(conn SSConn, initBuf []byte) (*DelayInitConn) {
  return &DelayInitConn{
    origConn: conn,
    initBuf: initBuf,
  }
}