package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
)

var aes256gcminfo = CipherInfo{
	newFactory: NewAES256GCMCipherFactory,
	keySize:    32,
}

var aes192gcminfo = CipherInfo{
	newFactory: NewAES256GCMCipherFactory,
	keySize:    24,
}

var aes128gcminfo = CipherInfo{
	newFactory: NewAES256GCMCipherFactory,
	keySize:    16,
}

func init() {
	Ciphers["aes-256-gcm"] = &aes256gcminfo
	Ciphers["aes-192-gcm"] = &aes192gcminfo
	Ciphers["aes-128-gcm"] = &aes128gcminfo
}

func NewAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func NewAES256GCMCipherFactory(key []byte) CipherFactory {
	return NewAEADCipherFactory(NewAESGCM, 32, 32, key)
}

func NewAES192GCMCipherFactory(key []byte) CipherFactory {
	return NewAEADCipherFactory(NewAESGCM, 24, 24, key)
}

func NewAES128GCMCipherFactory(key []byte) CipherFactory {
	return NewAEADCipherFactory(NewAESGCM, 16, 16, key)
}
