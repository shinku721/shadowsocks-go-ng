package shadowsocks

import (
	"io"
	"log"
	"net"
	"time"
)

// SSBuffer contains a buffer, currently a simple []byte.
// The content is to be sent. The capacity of the slice
// will be reused when reading.
type SSBuffer struct {
	buf []byte
}

// NewSSBuffer creates a buffer with default size.
func NewSSBuffer() *SSBuffer {
	return &SSBuffer{buf: make([]byte, 0, DEFAULT_BUF_SIZE)}
}

// Expand expands a buffer to either twice of its original
// size or the inputed size, unless the size exceeds the
// maximum buffer size when it generates a BUF_SIZE_EXCEED
// error.
func (b *SSBuffer) Expand(n int) error {
	log.Print("SSBuffer.Expand is called, consider reconfiguring the program to eliminate it!")
	s := cap(b.buf)
	if s >= MAX_BUF_SIZE {
		return ERR_BUF_SIZE_EXCEED
	}
	s *= 2
	if s < n {
		s = n
	}
	if s >= MAX_BUF_SIZE {
		s = MAX_BUF_SIZE
	}
	nbuf := make([]byte, len(b.buf), s)
	copy(nbuf, b.buf)
	b.buf = nbuf
	return nil
}

// SSConn represents a Shadowsocks accepted connection (maybe).
type SSConn interface {
	// SSRead reads some data into buffer. The size is uncertain.
	// Data is appended to the buffer.
	SSRead(*SSBuffer) error
	// SSWrite writes the data to the connection. It should write
	// the whole buffer and reset the buffer, otherwise it will
	// report an error.
	SSWrite(*SSBuffer) error
	// Close closes the connection.
	Close() error
	// Alive checks whether the connection is alive.
	Alive() bool
	// RemoteAddr returns the address of remote endpoint
	// note this should not used to Dial. It is currently
	// used for debugging.
	RemoteAddr() string
}

// Pipe is a utility to pipe from the reader to the writer, and
// writes the error to res (may be nil).
func Pipe(reader, writer SSConn, buf *SSBuffer, res chan error) {
	var err error
	defer func() { res <- err }()
	for {
		if err = writer.SSWrite(buf); err != nil {
			return
		}
		err = reader.SSRead(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			return
		}
	}
	if err = writer.SSWrite(buf); err != nil {
		return
	}
}

// DPipe is a utility to pipe bi-directionally.
func DPipe(conn1, conn2 SSConn, buf12, buf21 *SSBuffer, res chan error) {
	res1 := make(chan error, 1)
	res2 := make(chan error, 1)
	go Pipe(conn1, conn2, buf12, res1)
	go Pipe(conn2, conn1, buf21, res2)

	var err error
	// No need to wait for the other res because go seems
	// not to have any half-open capability
	select {
	case err = <-res1:
	case err = <-res2:
	}
	res <- err
}

// PlainConn is a SSConn wrapped on TCPConn.
type PlainConn struct {
	TCPConn *net.TCPConn
}

func (c PlainConn) SSRead(b *SSBuffer) (err error) {
	if len(b.buf) == cap(b.buf) {
		if err = b.Expand(len(b.buf)); err != nil {
			return
		}
	}
	lmax := cap(b.buf)
	if len(b.buf)+MAX_READ_SIZE < lmax {
		lmax = len(b.buf) + MAX_READ_SIZE
	}
	buf := b.buf[len(b.buf):lmax]
	var n int
	if n, err = c.TCPConn.Read(buf); err != nil {
		return
	}
	b.buf = b.buf[:len(b.buf)+n]
	return nil
}

func (c PlainConn) SSReadTimeout(b *SSBuffer, millis int64) error {
	c.TCPConn.SetReadDeadline(time.Now().Add(time.Duration(millis) * time.Millisecond))
	defer c.TCPConn.SetReadDeadline(time.Time{})
	err := c.SSRead(b)
	if e, t := err.(net.Error); t && e.Timeout() {
		return nil
	}
	return err
}

func (c PlainConn) SSWrite(b *SSBuffer) error {
	if _, err := c.TCPConn.Write(b.buf); err != nil {
		return err
	}
	b.buf = b.buf[:0]
	return nil
}

func (c PlainConn) Close() error {
	return c.TCPConn.Close()
}

func (c PlainConn) Alive() bool {
	unit := []byte{}
	c.TCPConn.SetReadDeadline(time.Now())
	if _, err := c.TCPConn.Read(unit); err == io.EOF {
		return false
	}
	c.TCPConn.SetReadDeadline(time.Time{})
	return true
}

func (c PlainConn) RemoteAddr() string {
	return c.TCPConn.LocalAddr().String() + "<->" + c.TCPConn.RemoteAddr().String()
}
