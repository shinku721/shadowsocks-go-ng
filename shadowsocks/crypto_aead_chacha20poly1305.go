package shadowsocks

import (
	"golang.org/x/crypto/chacha20poly1305"
)

var chacha20poly1305info = CipherInfo{
	newFactory: NewChacha20Poly1305CipherFactory,
	keySize:    32,
}

func init() {
	Ciphers["chacha20-ietf-poly1305"] = &chacha20poly1305info
}

func NewChacha20Poly1305CipherFactory(key []byte) CipherFactory {
	return NewAEADCipherFactory(chacha20poly1305.New, 32, 32, key)
}
