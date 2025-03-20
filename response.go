package yubikeyotp

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

type response struct {
	// ReceivedOneTimePassword matches the provided by YubiKey touch in the Request.
	ReceivedOneTimePassword string `query:"otp"`
	// SignatureInBase64 (RFC 4648) encoded HMAC-SHA1 signature that validates the response.
	SignatureInBase64 string `query:"h"`
	// Nonce prevents replay attacks. Matches the nonce provded in the Request.
	ReceivedNonce string `query:"nonce"`
	// SessionCounter is the YubiKey internal usage counter when key was pressed.
	SessionCounter string `query:"sessioncounter"`
	// SessionUse is the YubiKey internal session usage counter when key was pressed.
	SessionUse string `query:"sessionuse"`
	// Status represents the outcome of the request.
	Status string `query:"status"`
	// SyncFactor value from 0 to 100 indicates the percentage of syncing for this response.
	SyncFactor string `query:"sl"`
	// RequestTimestamp in UTC.
	RequestTimestamp string `query:"t"`
	// ActivationTimestamp indicates when YubiKey was pressed.
	ActivationTimestamp string `query:"timestamp"`
}

// Verify checks the response status and signature. Returns `nil` is response is verified.
func (r *response) Verify(secret []byte) (err error) {
	switch r.Status {
	case "OK":
		// passed
	case "BAD_OTP":
		return ErrRequestInvalidFormat
	case "REPLAYED_OTP", "REPLAYED_REQUEST":
		return ErrRequestReplayed
	case "BAD_SIGNATURE":
		return ErrRequestBadSignature
	case "MISSING_PARAMETER":
		return ErrRequestMissingParameter
	case "NO_SUCH_CLIENT":
		return ErrRequestClientDoesNotExist
	case "OPERATION_NOT_ALLOWED":
		return ErrRequestForbidden
	case "NOT_ENOUGH_ANSWERS":
		return ErrRequestDeadlineExceeded
	case "BACKEND_ERROR":
		return ErrRequestBackendError
	default:
		return ErrRequestUnknownFailure
	}

	signature := hmac.New(sha1.New, secret)
	r.encodeForVerification(signature)
	if base64.StdEncoding.EncodeToString(signature.Sum(nil)) != r.SignatureInBase64 {
		return ErrResponseBadSignature
	}
	return nil
}

// encodeForVerification gathers response fields into a URLEncoded query for signature verification. Keys must be alphabetically sorted.
func (r *response) encodeForVerification(w io.Writer) {
	_, _ = w.Write([]byte("nonce="))
	_, _ = w.Write([]byte(r.ReceivedNonce))
	_, _ = w.Write([]byte("&otp="))
	_, _ = w.Write([]byte(r.ReceivedOneTimePassword))
	_, _ = w.Write([]byte("&sessioncounter="))
	_, _ = w.Write([]byte(r.SessionCounter))
	_, _ = w.Write([]byte("&sessionuse="))
	_, _ = w.Write([]byte(r.SessionUse))
	_, _ = w.Write([]byte("&sl="))
	_, _ = w.Write([]byte(r.SyncFactor))
	_, _ = w.Write([]byte("&status="))
	_, _ = w.Write([]byte(r.Status))
	_, _ = w.Write([]byte("&t="))
	_, _ = w.Write([]byte(r.RequestTimestamp))
	_, _ = w.Write([]byte("&timestamp="))
	_, _ = w.Write([]byte(r.ActivationTimestamp))
}

func parseResponse(source io.Reader) (*response, error) {
	r := &response{}
	scanner := bufio.NewScanner(source)
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		switch key {
		case "h":
			r.SignatureInBase64 = value
		case "t":
			r.RequestTimestamp = value
		case "timestamp":
			r.ActivationTimestamp = value
		case "otp":
			r.ReceivedOneTimePassword = value
		case "nonce":
			r.ReceivedNonce = value
		case "sessioncounter":
			r.SessionCounter = value
		case "sessionuse":
			r.SessionUse = value
		case "status":
			r.Status = value
		case "sl":
			r.SyncFactor = value
		default:
			if value != "" {
				return nil, fmt.Errorf("received an unexpected API field %q with value %q", key, value)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return r, nil
}
