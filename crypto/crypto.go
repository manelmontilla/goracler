package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

var (
	ErrInvalidPad = errors.New("error invalid pad")
)

// GenerateKey generates a 16 bytes key and returns its hex representation.
func GenerateKey() (string, error) {
	var key = make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	s := hex.EncodeToString(key)
	return s, nil
}

// CBCEncrypt returns iv||ciphertext in base64.
func CBCEncrypt(hiv, key, msg string) (string, error) {
	k, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}
	c, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	// Implement the CBC mode. c[i] = e(k,c[i-1] + m[i]), c[-1] = iv.
	// Where len(m[i]) = 16 bytes.
	iv, err := hex.DecodeString(hiv)
	if err != nil {
		return "", err
	}
	prev := iv
	m := PCKCS5Pad([]byte(msg))
	// ciphertext = iv||c[0]..c[n-1].
	var ct = bytes.NewBuffer(make([]byte, 0, len(m)+16))
	// Prepend the iv to the ciphertext.
	ct.Write(iv)
	for i := 0; i < (len(m) / 16); i++ {
		b := m[i*16 : (i*16)+16]
		x := BlockXOR(b, prev)
		c.Encrypt(x, x)
		ct.Write(x)
		prev = x
	}
	cypertxt := ct.Bytes()
	out := hex.EncodeToString(cypertxt)
	return out, nil
}

// CBCDecrypt accepts a key and ciphertext in the form: iv||cypher returns a
// message. The ciphertext is hex encoded. WARNING: This function is vulnerable
// to padding oracle attacks and should only be used for test pourposes.
func CBCDecrypt(key, ciphertext string) (string, error) {
	d, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	k, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}
	bc, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	iv := d[0:16]
	c := d[16:len(d)]
	m := bytes.NewBuffer(make([]byte, 0, len(c)))
	prev := iv
	for i := 0; i < (len(c) / 16); i++ {
		ci := c[i*16 : (16*i)+16]
		aux := make([]byte, 16, 16)
		bc.Decrypt(aux, ci)
		m.Write(BlockXOR(aux, prev))
		prev = ci
	}
	ct := m.Bytes()
	ctremoved, err := DecryptRemovePCKCS5Pad(ct)
	return string(ctremoved), err
}

// BlockXOR xors a block with a given "key". The key length must be grater or
// equal than the block length.
func BlockXOR(block, key []byte) []byte {
	res := make([]byte, len(block))
	for i := 0; i < len(block); i++ {
		res[i] = block[i] ^ key[i%len(key)]
	}
	return res
}

// PCKCS5Pad  pads the given array to size 16.
func PCKCS5Pad(m []byte) []byte {
	var b bytes.Buffer
	b.Write(m)
	r := 16 - len(m)%16
	for i := 0; i < r; i++ {
		b.WriteByte(byte(r))
	}
	return b.Bytes()
}

// DecryptRemovePCKCS5Pad remove the 16 size pad from given array.
func DecryptRemovePCKCS5Pad(m []byte) ([]byte, error) {
	p := int(m[len(m)-1])
	if p > 16 || p < 1 {
		return nil, ErrInvalidPad
	}
	// Check the pad
	j := p
	for j > 0 {
		if m[len(m)-1] != byte(p) {
			return nil, ErrInvalidPad
		}
		m = m[0 : len(m)-1]
		j--
	}
	return m, nil
}

func RemovePCKCS5Pad(s string) (string, error) {
	m := []byte(s)
	p := int(m[len(m)-1])
	if p > 16 || p < 1 {
		return "", ErrInvalidPad
	}
	// Check the pad
	j := p
	for j > 0 {
		if m[len(m)-1] != byte(p) {
			return "", ErrInvalidPad
		}
		m = m[0 : len(m)-1]
		j--
	}
	return string(m), nil
}
