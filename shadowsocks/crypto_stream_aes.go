// +build enable_stream_ciphers

package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
)

func newCFBEnc(key []byte, iv []byte) (stream cipher.Stream, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

func newCFBDec(key []byte, iv []byte) (stream cipher.Stream, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

func newCTR(key []byte, iv []byte) (stream cipher.Stream, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	return cipher.NewCTR(block, iv), nil
}

var aes256cfbinfo = CipherInfo{
	newFactory: newAES256CFBCipherFactory,
	keySize:    32,
}

func newAES256CFBCipherFactory(key []byte) CipherFactory {
	return NewStreamCipherFactory(newCFBEnc, newCFBDec, 32, 16, key)
}

var aes192cfbinfo = CipherInfo{
	newFactory: newAES192CFBCipherFactory,
	keySize:    24,
}

func newAES192CFBCipherFactory(key []byte) CipherFactory {
	return NewStreamCipherFactory(newCFBEnc, newCFBDec, 24, 16, key)
}

var aes128cfbinfo = CipherInfo{
	newFactory: newAES128CFBCipherFactory,
	keySize:    16,
}

func newAES128CFBCipherFactory(key []byte) CipherFactory {
	return NewStreamCipherFactory(newCFBEnc, newCFBDec, 16, 16, key)
}

var aes256ctrinfo = CipherInfo{
	newFactory: newAES256CTRCipherFactory,
	keySize:    32,
}

func newAES256CTRCipherFactory(key []byte) CipherFactory {
	return NewStreamCipherFactory(newCTR, newCTR, 32, 16, key)
}

var aes192ctrinfo = CipherInfo{
	newFactory: newAES192CTRCipherFactory,
	keySize:    24,
}

func newAES192CTRCipherFactory(key []byte) CipherFactory {
	return NewStreamCipherFactory(newCTR, newCTR, 24, 16, key)
}

var aes128ctrinfo = CipherInfo{
	newFactory: newAES128CTRCipherFactory,
	keySize:    16,
}

func newAES128CTRCipherFactory(key []byte) CipherFactory {
	return NewStreamCipherFactory(newCTR, newCTR, 16, 16, key)
}

func init() {
	Ciphers["aes-256-cfb"] = &aes256cfbinfo
	Ciphers["aes-192-cfb"] = &aes192cfbinfo
	Ciphers["aes-128-cfb"] = &aes128cfbinfo
	Ciphers["aes-256-ctr"] = &aes256ctrinfo
	Ciphers["aes-192-ctr"] = &aes192ctrinfo
	Ciphers["aes-128-ctr"] = &aes128ctrinfo
}
