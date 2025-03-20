package yubikeyotp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/url"
	"strconv"
)

// Request holds the parameters for a Yubi Key OTP authentication request.
// Client ID and secret are obtained from Yubi Corporation: <https://upgrade.yubico.com/getapikey/>.
type Request struct {
	// OneTimePassword is provided by touching Yubi Key.
	OneTimePassword string
	// ClientID identifies the authenticating user.
	ClientID uint
	// ClientSecret is the secret key for signing the request.
	ClientSecret string
}

func (a *Authenticator) buildSignedRequestQuery(
	oneTimePassword string,
	clientID uint,
	secret []byte,
	nonce Nonce,
) string {
	b := bytes.Buffer{}
	_, _ = b.WriteString("id=")
	_, _ = b.WriteString(strconv.Itoa(int(clientID)))
	// Nonce prevents replay attacks. Must contain 16 to 40 characters by specification.
	_, _ = b.WriteString("&nonce=")
	_, _ = b.WriteString(url.QueryEscape(nonce.String()))
	_, _ = b.WriteString("&otp=")
	_, _ = b.WriteString(url.QueryEscape(oneTimePassword))
	// SyncFactor can be encoded as strings "fast" or "secure" to use server-configured values. If the value is absent, the server decides. "0" is equivalent to "fast" and "100" to "secure."
	_, _ = b.WriteString("&sl=")
	_, _ = b.WriteString(a.syncFactor)
	// Timeout sets the synchronization limit. If absent, the server decides.
	_, _ = b.WriteString("&timeout=")
	_, _ = b.WriteString(a.syncTimeLimit)
	_, _ = b.WriteString("&timestamp=1")

	// base64 (RFC 4648) HMAC-SHA1 signature
	signature := hmac.New(sha1.New, secret)
	_, _ = signature.Write(b.Bytes())
	_, _ = b.WriteString("&h=")
	_, _ = b.WriteString(base64.StdEncoding.EncodeToString(signature.Sum(nil)))

	return b.String()
}
