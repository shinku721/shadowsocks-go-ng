package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
)

var aes256gcminfo = CipherInfo{
	newFactory: newAES256GCMCipherFactory,
	keySize:    32,
}

var aes192gcminfo = CipherInfo{
	newFactory: newAES256GCMCipherFactory,
	keySize:    24,
}

var aes128gcminfo = CipherInfo{
	newFactory: newAES256GCMCipherFactory,
	keySize:    16,
}

func init() {
	Ciphers["aes-256-gcm"] = &aes256gcminfo
	Ciphers["aes-192-gcm"] = &aes192gcminfo
	Ciphers["aes-128-gcm"] = &aes128gcminfo
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newAES256GCMCipherFactory(key []byte) CipherFactory {
	return NewAEADCipherFactory(newAESGCM, 32, 32, key)
}

func newAES192GCMCipherFactory(key []byte) CipherFactory {
	return NewAEADCipherFactory(newAESGCM, 24, 24, key)
}

func newAES128GCMCipherFactory(key []byte) CipherFactory {
	return NewAEADCipherFactory(newAESGCM, 16, 16, key)
}
