package goracler

import (
	"encoding/hex"
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"github.com/manelmontilla/goracler/crypto"
)

type testOracle struct {
	key string
}

func (t testOracle) Do(c []byte) (int, error) {
	htry := hex.EncodeToString(c)
	_, err := crypto.CBCDecrypt(t.key, htry)
	if err != nil && err != crypto.ErrInvalidPad {
		return 0, err
	}
	if err == crypto.ErrInvalidPad {
		return 0, nil
	}
	return 1, nil
}

func Test_decryptParallel(t *testing.T) {
	key := "ee581a043ac19191c7d551710bab13a9"
	msg := "Hello world"
	iv := "91db4482c4ffa9858338ab0e98ddf96c"
	ct, err := crypto.CBCEncrypt(iv, key, msg)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	oracle := testOracle{
		key: key,
	}
	c, err := hex.DecodeString(ct)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	var l log.Logger
	l.SetOutput(ioutil.Discard)
	m, err := decryptBlock(c[0:CipherBlockLen], c[CipherBlockLen:CipherBlockLen*2], oracle, l)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	m, err = crypto.DecryptRemovePCKCS5Pad(m)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if strings.Compare(string(m), msg) != 0 {
		t.Errorf("invalid clear text message, got %s", string(m))
	}
}
