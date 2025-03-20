# Yubi Key One Time Password Authenticator

One time password authenticator for hardware Yubi keys.

Hardware tokens are one of the [best ways][fidoAlliance] to secure two-factor authentication work flows.

## Usage

1. Acquire a client ID and secret from Yubi corporation for your token: <https://upgrade.yubico.com/getapikey/>
2. Wait around 5 minutes until all validation servers know about your newly generated secret.
3. Install the library: `go get -u github.com/dkotik/yubikeyotp`

```go
import "github.com/dkotik/yubikeyotp"

func main() {
	authenticator, err := yubikeyotp.New(
		yubikeyotp.WithRetryStrategy(yubikeyotp.RetryWithBackOff{
			AttemptLimit:           3,
			AttemptDelay:           time.Second * 2,
			AttemptDelayLimit:      time.Minute,
			AttemptDelayMultiplier: 1.3,
		}),
		yubikeyotp.WithSynchronizationFactor(100),
	)
	if err != nil {
		panic(err)
	}

	if err = authenticator.Authenticate(context.Background(), Request{
		OneTimePassword: token,
		ClientID:        uint(id),
		ClientSecret:    secretKey,
	}); err != nil {
		panic(err)
	}
	// if there was no error, authentication succeeded
}
```

[fidoAlliance]: https://fidoalliance.org/apple-google-and-microsoft-commit-to-expanded-support-for-fido-standard-to-accelerate-availability-of-passwordless-sign-ins/ "the importance of FIDO tokens for authentication"

## Links

- Yubi Key OTP documentation: <https://developers.yubico.com/OTP/>
- Yubi Key API documentation: <https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html>
- Similar projects:
    - <https://github.com/GeertJohan/yubigo>
