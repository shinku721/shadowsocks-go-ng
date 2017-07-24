package shadowsocks

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"golang.org/x/crypto/hkdf"
	"io"
)

type NewAEADCipherFunc func([]byte) (cipher.AEAD, error)

/* AEADCipherFactory implements CipherFactory with AEAD ciphers.
   Specification:
   https://shadowsocks.org/en/spec/AEAD-Ciphers.html
*/
type AEADCipherFactory struct {
	newCipher NewAEADCipherFunc
	keySize   int
	saltSize  int
	key       []byte
}

func NewAEADCipherFactory(newCipher NewAEADCipherFunc, keySize, saltSize int, key []byte) CipherFactory {
	return &AEADCipherFactory{
		newCipher: newCipher,
		keySize:   keySize,
		saltSize:  saltSize,
		key:       key,
	}
}

func (a *AEADCipherFactory) Wrap(c PlainConn) SSConn {
	return &AEADConn{conn: c, factory: a}
}

// AEADCipherConn implements SSConn with given AEAD cipher.
type AEADConn struct {
	conn        PlainConn
	factory     *AEADCipherFactory
	readerNonce Nonce
	readerAEAD  cipher.AEAD
	writerNonce Nonce
	writerAEAD  cipher.AEAD
}

func (c *AEADConn) SSRead(b *SSBuffer) (err error) {
	firstTime := c.readerAEAD == nil
	var salt []byte
	if firstTime {
		salt = make([]byte, c.factory.saltSize)
		_, err = io.ReadFull(c.conn.TCPConn, salt)
		if err != nil {
			return
		}
		if saltFilter.Contains(salt) {
			return AUTH_ERROR // todo: use another error message
		}
		h := hkdf.New(sha1.New, c.factory.key, salt, []byte(HKDF_INFO))
		skey := make([]byte, c.factory.keySize)
		_, err = io.ReadFull(h, skey)
		if err != nil {
			return
		}
		c.readerAEAD, err = c.factory.newCipher(skey)
		if err != nil {
			return
		}
		c.readerNonce = NewNonce(c.readerAEAD.NonceSize())
	}

	TAG_SIZE := c.readerAEAD.Overhead()

	pos := len(b.buf)
	if cap(b.buf)-pos < LEN_SIZE+TAG_SIZE {
		b.Expand(pos + LEN_SIZE + TAG_SIZE)
	}

	lbuf := b.buf[pos : pos+LEN_SIZE+TAG_SIZE]
	_, err = io.ReadFull(c.conn.TCPConn, lbuf)
	if err != nil {
		return
	}

	_, err = c.readerAEAD.Open(lbuf[:0], c.readerNonce, lbuf, nil)
	if err != nil {
		return AUTH_ERROR
	}
	c.readerNonce.Inc()

	var n16 int16
	binary.Read(bytes.NewBuffer(lbuf[:LEN_SIZE]), binary.BigEndian, &n16)
	n := int(n16)
	if n != (n & 0x3fff) {
		return INVALID_CHUNK_SIZE
	}
	if cap(b.buf)-pos < n+TAG_SIZE {
		b.Expand(pos + n + TAG_SIZE)
	}

	dbuf := b.buf[pos : pos+n+TAG_SIZE]
	_, err = io.ReadFull(c.conn.TCPConn, dbuf)
	if err != nil {
		return
	}

	_, err = c.readerAEAD.Open(dbuf[:0], c.readerNonce, dbuf, nil)
	if err != nil {
		return AUTH_ERROR
	}
	c.readerNonce.Inc()

	b.buf = b.buf[:pos+n]
	
	if firstTime {
		saltFilter.Add(salt)
	}
	return
}

func (c *AEADConn) SSWrite(b *SSBuffer) (err error) {
	if len(b.buf) == 0 {
		return
	}
	var salt []byte
	if c.writerAEAD == nil {
		salt = make([]byte, c.factory.saltSize)
		if _, err = rand.Read(salt); err != nil {
			return
		}

		h := hkdf.New(sha1.New, c.factory.key, salt, []byte(HKDF_INFO))
		skey := make([]byte, c.factory.keySize)
		_, err = io.ReadFull(h, skey)
		if err != nil {
			return
		}
		c.writerAEAD, err = c.factory.newCipher(skey)
		if err != nil {
			return
		}
		c.writerNonce = NewNonce(c.writerAEAD.NonceSize())
	}
	TAG_SIZE := c.writerAEAD.Overhead()

	scbuf := make([]byte, c.factory.saltSize+LEN_SIZE+TAG_SIZE+MAX_WRITE_CHUNK_SIZE+TAG_SIZE)
	cbuf := scbuf
	saltLen := 0
	if salt != nil {
		copy(cbuf, salt)
		cbuf = cbuf[c.factory.saltSize:]
		saltLen = c.factory.saltSize
	}

	pos := 0
	for pos < len(b.buf) {
		s := len(b.buf) - pos
		if s > MAX_WRITE_CHUNK_SIZE {
			s = MAX_WRITE_CHUNK_SIZE
		}
		s16 := int16(s)
		binary.Write(bytes.NewBuffer(cbuf[:0]), binary.BigEndian, &s16)
		c.writerAEAD.Seal(cbuf[:0], c.writerNonce, cbuf[:LEN_SIZE], nil)
		c.writerNonce.Inc()

		cbuf = cbuf[LEN_SIZE+TAG_SIZE:]
		c.writerAEAD.Seal(cbuf[:0], c.writerNonce, b.buf[pos:pos+s], nil)
		c.writerNonce.Inc()

		if _, err = c.conn.TCPConn.Write(scbuf[:saltLen+LEN_SIZE+s+TAG_SIZE*2]); err != nil {
			return err
		}
		saltLen = 0
		cbuf = scbuf

		pos += s
	}

	b.buf = b.buf[:0]
	return
}

func (c *AEADConn) Close() (err error) {
	return c.conn.Close()
}

func (c *AEADConn) Alive() bool {
	return c.conn.Alive()
}

func (c *AEADConn) RemoteAddr() string {
	return c.conn.RemoteAddr()
}
