package yubikeyotp

import (
	"bytes"
	"testing"
)

func TestDefaultNonceGeneration(t *testing.T) {
	nonce, err := cryptoRandNonceGeneratorWithFourLeadingTimeBytes()
	if err != nil {
		t.Errorf("Error generating nonce: %v", err)
	}

	for _, b := range nonce {
		if bytes.IndexByte([]byte(defaultNonceCharacterSet), b) == -1 {
			t.Errorf("Nonce contains invalid byte: %d", b)
		}
	}

	// t.Fatalf("%s", nonce)
}
