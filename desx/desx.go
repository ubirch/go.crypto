// Package desx implements DES-X symmetric key encryption.
//
// For details, see http://en.wikipedia.org/wiki/DES-X.
package desx

import (
	"crypto/des"
	"errors"
)

var defaultIV = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// Encrypt encrypts plaintext in CBC mode and returns ciphertext.
// plaintext's length must be a multiple of 8. key is a 24 byte des key.
// iv is an 8 byte initialization vector. If iv is nil, zeros
// will be used as the initialization vector.
func Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	switch {
	case len(plaintext)%8 != 0:
		return nil, errors.New("invalid plaintext length")
	case len(key) != 24:
		return nil, errors.New("invalid key length")
	case iv == nil:
		iv = defaultIV
	case len(iv) != 8:
		return nil, errors.New("invalid iv length")
	}

	out := make([]byte, 0, len(plaintext))
	prevXor := make([]byte, 8)
	temp := make([]byte, 8)

	preWhiten := key[8:16]
	postWhiten := key[16:24]
	cipher, err := des.NewCipher(key[:8])
	if err != nil {
		panic(err)
	}
	copy(prevXor, iv)

	for i := 0; i < len(plaintext)/8; i++ {
		curPlain := plaintext[i*8 : i*8+8]
		cipher.Encrypt(temp, xorBlock3(preWhiten, prevXor, curPlain))
		curCipher := xorBlock2(postWhiten, temp)
		out = append(out, curCipher...)
		copy(prevXor, curCipher)
	}

	return out, nil
}

// Decrypt decrypts ciphertext in CBC mode and returns plaintext.
// ciphertext's length must be a multiple of 8. key is a 24 byte des key.
// iv is an 8 byte initialization vector. If iv is nil, zeros
// will be used as the initialization vector.
func Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	switch {
	case len(ciphertext)%8 != 0:
		return nil, errors.New("invalid ciphertext length")
	case len(key) != 24:
		return nil, errors.New("invalid key length")
	case iv == nil:
		iv = defaultIV
	case len(iv) != 8:
		return nil, errors.New("invalid iv length")
	}

	out := make([]byte, 0, len(ciphertext))
	prevXor := make([]byte, 8)
	temp := make([]byte, 8)

	preWhiten := key[8:16]
	postWhiten := key[16:24]
	cipher, err := des.NewCipher(key[:8])
	if err != nil {
		panic(err)
	}
	copy(prevXor, iv)

	for i := 0; i < len(ciphertext)/8; i++ {
		curCipher := ciphertext[i*8 : i*8+8]
		cipher.Decrypt(temp, xorBlock2(postWhiten, curCipher))
		curPlain := xorBlock3(prevXor, preWhiten, temp)
		out = append(out, curPlain...)
		copy(prevXor, curCipher)
	}

	return out, nil
}

// xorBlock2 xors two byte slices of length 8.
func xorBlock2(a, b []byte) []byte {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// xorBlock3 xors three byte slices of length 8.
func xorBlock3(a, b, c []byte) []byte {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = a[i] ^ b[i] ^ c[i]
	}
	return out
}
