package yubikeyotp

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

const (
	envYubiKeyClientID                 = "TEST_YUBIKEY_CLIENT_ID"
	envYubiKeyClientSecret             = "TEST_YUBIKEY_CLIENT_SECRET"
	envYubiKeyOneTimePasswordFromTouch = "TEST_YUBIKEY_ONE_TIME_PASSWORD_FROM_TOUCH"
)

/*
TestAuthentication tests the authentication process using a YubiKey OTP.
Touch the Yubi Key to generate a one-time password that can be used to authenticate.
Each touch can only be used once.

	$ export TEST_YUBIKEY_CLIENT_ID=<ID>
	$ export TEST_YUBIKEY_CLIENT_SECRET=<SECRET>
	$ export TEST_YUBIKEY_ONE_TIME_PASSWORD_FROM_TOUCH=<Touch the Yubi Key>
	$ go test -count=1 .
*/
func TestAuthentication(t *testing.T) {
	clientID := strings.TrimSpace(os.Getenv(envYubiKeyClientID))
	if clientID == "" {
		t.Skip("YubiKey OTP client ID is not provided. Use environment variable TEST_YUBIKEY_CLIENT_ID.")
	}
	secretKey := strings.TrimSpace(os.Getenv(envYubiKeyClientSecret))
	if secretKey == "" {
		t.Skip("YubiKey OTP client secret is not provided. Use environment variable TEST_YUBIKEY_CLIENT_SECRET.")
	}
	token := strings.TrimSpace(os.Getenv(envYubiKeyOneTimePasswordFromTouch))
	if token == "" {
		t.Skip("YubiKey OTP one-time password from touch is not provided. Use environment variable TEST_YUBIKEY_ONE_TIME_PASSWORD_FROM_TOUCH.")
	}

	id, err := strconv.Atoi(clientID)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := New()
	if err != nil {
		t.Fatal(err)
	}

	if err = authenticator.Authenticate(t.Context(), Request{
		ClientID:        uint(id),
		ClientSecret:    secretKey,
		OneTimePassword: token,
	}); err != nil {
		t.Fatal(err)
	}
}
