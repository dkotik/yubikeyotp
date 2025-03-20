package yubikeyotp

import (
	"crypto/rand"
	"errors"
	"time"
)

const (
	defaultNonceCharacterSet           = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`
	defaultNonceCharacterSetLength     = int64(len(defaultNonceCharacterSet))
	defaultNonceCharacterSetLengthByte = byte(len(defaultNonceCharacterSet))
)

// Nonce is a unique identifier for a request.
// It must include 40 bytes generated
// by specification. Nonce should be filled from a
// secure random number generator and differentiated
// from previous nonces by time or a sequential counter.
type Nonce [40]byte

func (n Nonce) String() string {
	return string(n[:])
}

// NonceGenerator provides secure random values for request validation.
// A nonce must never repeat by using a unique machine or incremental identifier and a timestamp.
type NonceGenerator interface {
	GenerateNonce() (Nonce, error)
}

// NonceGeneratorFunc satisfies the [NonceGenerator] interface.
type NonceGeneratorFunc func() (Nonce, error)

func (f NonceGeneratorFunc) GenerateNonce() (Nonce, error) {
	return f()
}

func cryptoRandNonceGeneratorWithFourLeadingTimeBytes() (nonce Nonce, err error) {
	t := time.Now().UnixNano()

	// four time-based bytes
	nonce[0] = defaultNonceCharacterSet[t%defaultNonceCharacterSetLength]
	t /= defaultNonceCharacterSetLength
	nonce[1] = defaultNonceCharacterSet[t%defaultNonceCharacterSetLength]
	t /= defaultNonceCharacterSetLength
	nonce[2] = defaultNonceCharacterSet[t%defaultNonceCharacterSetLength]
	t /= defaultNonceCharacterSetLength
	nonce[3] = defaultNonceCharacterSet[t%defaultNonceCharacterSetLength]

	// fill the rest with secure random bytes
	n, err := rand.Read(nonce[4:])
	if err != nil {
		return nonce, err
	}
	if n < 40-4 {
		return nonce, errors.New("not enough random bytes")
	}
	for i := 4; i < 40; i++ {
		nonce[i] = defaultNonceCharacterSet[nonce[i]%defaultNonceCharacterSetLengthByte]
	}
	return nonce, nil
}
