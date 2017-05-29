package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
)

func NewCFBEnc(key []byte, iv []byte) (stream cipher.Stream, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

func NewCFBDec(key []byte, iv []byte) (stream cipher.Stream, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

func NewCTR(key []byte, iv []byte) (stream cipher.Stream, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	return cipher.NewCTR(block, iv), nil
}

var aes256cfbinfo = CipherInfo{
	newFactory: NewAES256CFBCipherFactory,
	keySize:    32,
}

func NewAES256CFBCipherFactory(key []byte) CipherFactory {
	return NewStreamCipherFactory(NewCFBEnc, NewCFBDec, 32, 16, key)
}

var aes192cfbinfo = CipherInfo{
	newFactory: NewAES192CFBCipherFactory,
	keySize:    24,
}

func NewAES192CFBCipherFactory(key []byte) CipherFactory {
	return NewStreamCipherFactory(NewCFBEnc, NewCFBDec, 24, 16, key)
}

var aes128cfbinfo = CipherInfo{
	newFactory: NewAES128CFBCipherFactory,
	keySize:    16,
}

func NewAES128CFBCipherFactory(key []byte) CipherFactory {
	return NewStreamCipherFactory(NewCFBEnc, NewCFBDec, 16, 16, key)
}

var aes256ctrinfo = CipherInfo{
	newFactory: NewAES256CTRCipherFactory,
	keySize:    32,
}

func NewAES256CTRCipherFactory(key []byte) CipherFactory {
	return NewStreamCipherFactory(NewCTR, NewCTR, 32, 16, key)
}

var aes192ctrinfo = CipherInfo{
	newFactory: NewAES192CTRCipherFactory,
	keySize:    24,
}

func NewAES192CTRCipherFactory(key []byte) CipherFactory {
	return NewStreamCipherFactory(NewCTR, NewCTR, 24, 16, key)
}

var aes128ctrinfo = CipherInfo{
	newFactory: NewAES128CTRCipherFactory,
	keySize:    16,
}

func NewAES128CTRCipherFactory(key []byte) CipherFactory {
	return NewStreamCipherFactory(NewCTR, NewCTR, 16, 16, key)
}

func init() {
	Ciphers["aes-256-cfb"] = &aes256cfbinfo
	Ciphers["aes-192-cfb"] = &aes192cfbinfo
	Ciphers["aes-128-cfb"] = &aes128cfbinfo
	Ciphers["aes-256-ctr"] = &aes256ctrinfo
	Ciphers["aes-192-ctr"] = &aes192ctrinfo
	Ciphers["aes-128-ctr"] = &aes128ctrinfo
}
