// +build enable_stream_ciphers

package shadowsocks

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type NewStreamCipherFunc func([]byte, []byte) (cipher.Stream, error)

/* StreamCipherFactory implements CipherFactory with stream ciphers.
   Specification:
   https://shadowsocks.org/en/spec/Stream-Ciphers.html
*/
type StreamCipherFactory struct {
	key         []byte
	keySize     int
	ivSize      int
	newEncipher NewStreamCipherFunc
	newDecipher NewStreamCipherFunc
}

func NewStreamCipherFactory(newEncipher, newDecipher NewStreamCipherFunc, keySize, ivSize int, key []byte) CipherFactory {
	return &StreamCipherFactory{
		key:         key,
		keySize:     keySize,
		ivSize:      ivSize,
		newEncipher: newEncipher,
		newDecipher: newDecipher,
	}
}

func (s *StreamCipherFactory) Wrap(conn PlainConn) SSConn {
	return &StreamCipherConn{conn: conn, factory: s}
}

// StreamCipherConn implements SSConn with given stream cipher.
type StreamCipherConn struct {
	conn         PlainConn
	factory      *StreamCipherFactory
	readerStream cipher.Stream
	writerStream cipher.Stream
}

func (s *StreamCipherConn) SSRead(b *SSBuffer) (err error) {
	if s.readerStream == nil {
		iv := make([]byte, s.factory.ivSize)
		_, err = io.ReadFull(s.conn.TCPConn, iv)
		if err != nil {
			return
		}
		if saltFilter.Contains(iv) {
			return ERR_DUP_SALT
		}
		saltFilter.Add(iv)
		s.readerStream, err = s.factory.newDecipher(s.factory.key, iv)
		if err != nil {
			return
		}
	}

	if err = s.conn.SSRead(b); err != nil {
		return
	}
	s.readerStream.XORKeyStream(b.buf, b.buf)
	return
}

func (s *StreamCipherConn) SSWrite(b *SSBuffer) (err error) {
	var iv []byte
	if s.writerStream == nil {
		iv = make([]byte, s.factory.ivSize)
		if _, err = rand.Read(iv); err != nil {
			return
		}
		s.writerStream, err = s.factory.newEncipher(s.factory.key, iv)
		if err != nil {
			return
		}
	}

	s.writerStream.XORKeyStream(b.buf, b.buf)

	if iv != nil {
		if cap(b.buf)-len(b.buf) < len(iv) {
			if err = b.Expand(len(b.buf) + len(iv)); err != nil {
				return
			}
		}
		copy(b.buf[len(iv):len(b.buf)+len(iv)], b.buf)
		b.buf = b.buf[:len(b.buf)+len(iv)]
		copy(b.buf, iv)
	}

	return s.conn.SSWrite(b)
}

func (s *StreamCipherConn) Close() error {
	return s.conn.Close()
}

func (s *StreamCipherConn) Alive() bool {
	return s.conn.Alive()
}

func (s *StreamCipherConn) RemoteAddr() string {
	return s.conn.RemoteAddr()
}
