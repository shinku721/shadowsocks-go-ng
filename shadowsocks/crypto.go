package shadowsocks

import (
	"crypto/md5"
	"io"
)

const LEN_SIZE = 2
const HKDF_INFO = "ss-subkey"

// Nonce is a nonce.
type Nonce []byte

// NewNonce creates a nonce with given size.
func NewNonce(n int) Nonce {
	return make([]byte, n, n)
}

// Inc increases the nonce.
func (non Nonce) Inc() {
	for i := 0; i < len(non); i++ {
		non[i]++
		if non[i] != 0 {
			break
		}
	}
}

// KeyDeriver is a context of key deriving.
type KeyDeriver struct {
	pass []byte
	last []byte
	pos  int
}

// NewKeyDeriver creates a new KeyDeriver.
func NewKeyDeriver(pass []byte) io.Reader {
	return &KeyDeriver{
		pass: pass,
		last: make([]byte, 0),
		pos:  0,
	}
}

// Read implements io.Reader. It writes derived key into
// the buffer and returns bytes written. err is guaranteed
// to be nil.
func (r *KeyDeriver) Read(p []byte) (n int, err error) {
	h := md5.New()
	for n = 0; n < len(p); {
		if r.pos == len(r.last) {
			h.Reset()
			h.Write(r.last)
			h.Write(r.pass)
			r.last = h.Sum(nil)
			r.pos = 0
		}
		l := copy(p[n:], r.last[r.pos:])
		r.pos += l
		n += l
	}
	return
}

// DeriveKey derives the key of given size from the password.
func DeriveKey(key []byte, pass []byte) {
	NewKeyDeriver(pass).Read(key)
}

// CipherFactory is a factory that wraps PlainConn into encrypted
// connections.
type CipherFactory interface {
	Wrap(PlainConn) SSConn
}

type NewCipherFactoryFunc func([]byte) CipherFactory

type CipherInfo struct {
	newFactory NewCipherFactoryFunc
	keySize    int
}

var Ciphers = map[string]*CipherInfo{}
