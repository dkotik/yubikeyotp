package yubikeyotp

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// Authenticator verifies one-time passwords using YubiKey API.
// Create only with [New] constructor.
type Authenticator struct {
	clientPool             *sync.Pool
	nonceGenerator         NonceGenerator
	retryLimit             int
	retryBackoffDelay      time.Duration
	retryBackoffMultiplier time.Duration
	syncFactor             string
	syncTimeLimit          string

	mu                   sync.Mutex
	currentEndpointIndex int
	endpoints            []string
}

// New creates a new YubiKey one-time password [Authenticator].
func New(withOptions ...Option) (_ *Authenticator, err error) {
	o := options{}
	for _, option := range append(
		withOptions,
		defaultNonceGenerator,
		defaultSynchronizationFactor,
		defaultSynchronizationTimeLimit,
		defaultEndpoints,
		defaultRetryWithBackOff,
		defaultClientPool,
	) {
		if err = option(&o); err != nil {
			return nil, fmt.Errorf("unable to initialize Yubi Key authenticator: %w", err)
		}
	}

	return &Authenticator{
		clientPool:             o.ClientPool,
		nonceGenerator:         o.NonceGenerator,
		retryLimit:             int(o.Retry.AttemptLimit),
		retryBackoffDelay:      o.Retry.AttemptDelay,
		retryBackoffMultiplier: time.Duration(o.Retry.AttemptDelayMultiplier),
		syncFactor:             fmt.Sprintf("%d", *o.SynchronizationFactor),
		syncTimeLimit:          fmt.Sprintf("%d", *o.SynchronizationTimeLimit),

		mu:        sync.Mutex{},
		endpoints: o.Endpoints,
	}, nil
}

// Authenticate verifies a one-time password using YubiKey API.
func (a *Authenticator) Authenticate(ctx context.Context, r Request) error {
	secret, err := base64.StdEncoding.DecodeString(r.ClientSecret)
	if err != nil {
		return fmt.Errorf("invalid client secret: %w", err)
	}
	nonce, err := a.nonceGenerator.GenerateNonce()
	if err != nil {
		return err
	}

	httpResponse, err := a.sendQuery(ctx, a.buildSignedRequestQuery(
		r.OneTimePassword,
		r.ClientID,
		secret,
		nonce,
	))
	if err != nil {
		return fmt.Errorf("network client failed: %w", err)
	}
	defer httpResponse.Body.Close()
	response, err := parseResponse(httpResponse.Body)
	if err != nil {
		return fmt.Errorf("could not parse response: %w", err)
	}

	if err = response.Verify(secret); err != nil {
		return fmt.Errorf("could not verify response: %w", err)
	}
	return nil
}
