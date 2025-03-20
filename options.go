package yubikeyotp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

type RetryWithBackOff struct {
	AttemptLimit           uint8
	AttemptDelay           time.Duration
	AttemptDelayLimit      time.Duration
	AttemptDelayMultiplier float64
}

type options struct {
	NonceGenerator           NonceGenerator
	SynchronizationFactor    *uint8
	SynchronizationTimeLimit *uint8
	Retry                    *RetryWithBackOff
	Endpoints                []string
	ClientPool               *sync.Pool
}

// Option configures [Authenticator] initialization.
type Option func(*options) error

func defaultNonceGenerator(o *options) error {
	if o.NonceGenerator != nil {
		return nil
	}
	o.NonceGenerator = NonceGeneratorFunc(cryptoRandNonceGeneratorWithFourLeadingTimeBytes)
	return nil
}

func defaultSynchronizationFactor(o *options) error {
	if o.SynchronizationFactor != nil {
		return nil
	}
	return WithSynchronizationFactor(100)(o)
}

func defaultSynchronizationTimeLimit(o *options) error {
	if o.SynchronizationTimeLimit != nil {
		return nil
	}
	return WithSynchronizationTimeLimit(time.Second * 6)(o)
}

func defaultRetryWithBackOff(o *options) error {
	if o.Retry != nil {
		return nil
	}
	return WithRetryStrategy(RetryWithBackOff{
		AttemptLimit:           3,
		AttemptDelay:           time.Second * 2,
		AttemptDelayLimit:      time.Minute,
		AttemptDelayMultiplier: 1.3,
	})(o)
}

func defaultEndpoints(o *options) error {
	if len(o.Endpoints) > 0 {
		return nil
	}
	return WithEndpoints(DefaultEndpoints...)(o)
}

func defaultClientPool(o *options) error {
	if o.ClientPool != nil {
		return nil
	}
	return WithClientPool(&sync.Pool{
		New: func() any {
			return &http.Client{
				Timeout: time.Second * 5,
				Transport: &http.Transport{
					MaxConnsPerHost:     20,
					MaxIdleConnsPerHost: 5,
					DialContext: (&net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 60 * time.Second,
					}).DialContext,
					TLSHandshakeTimeout:   3 * time.Second,
					ResponseHeaderTimeout: 3 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				},
			}
		},
	})(o)
}

// WithNonceGenerator specifies a random value provider that secures cryptographic signature of API requests.
func WithNonceGenerator(n NonceGenerator) Option {
	return func(o *options) error {
		if n == nil {
			return errors.New("nonce generator is nil")
		}
		if _, err := n.GenerateNonce(); err != nil {
			return fmt.Errorf("nonce generator does not work: %w", err)
		}
		o.NonceGenerator = n
		return nil
	}
}

// WithSynchronizationFactor sets Yubi Key API SyncFactor,
// which indicates the percentage of server concensus required by client. Lower value is faster.
// Default value is 100 for maximum security.
func WithSynchronizationFactor(percent uint8) Option {
	return func(o *options) error {
		if percent > 100 {
			return errors.New("synchronization factor must be between 0 and 100")
		}
		o.SynchronizationFactor = &percent
		return nil
	}
}

// WithSynchronizationTimeLimit sets Yubi Key API SyncTimeLimit,
// which indicates the maximum time in seconds that the client will wait for server concensus.
// Default value is 6 seconds.
func WithSynchronizationTimeLimit(d time.Duration) Option {
	return func(o *options) error {
		limit := uint8(d.Seconds())
		if limit > 120 {
			return errors.New("synchronization time limit must be between 1 and 120 seconds")
		}
		o.SynchronizationTimeLimit = &limit
		return nil
	}
}

// WithRetryStrategy specifies a retry strategy for network failures during API requests.
func WithRetryStrategy(r RetryWithBackOff) Option {
	return func(o *options) error {
		if r.AttemptLimit == 0 {
			return errors.New("retry limit must be greater than zero")
		}
		if r.AttemptDelay <= time.Millisecond*30 {
			return errors.New("retry delay must be greater than 30 milliseconds")
		}
		if r.AttemptDelay > time.Minute {
			return errors.New("retry delay must be less than one minute")
		}
		if r.AttemptDelayLimit < r.AttemptDelay {
			return errors.New("retry delay limit must be greater than retry delay")
		}
		if r.AttemptDelayMultiplier <= 1 {
			return errors.New("retry multiplier must be greater than one")
		}
		if r.AttemptDelayMultiplier > 10 {
			return errors.New("retry multiplier must be less than 10")
		}
		o.Retry = &r
		return nil
	}
}

func WithEndpoints(endpoints ...string) Option {
	return func(o *options) error {
		if len(endpoints) == 0 {
			return errors.New("endpoints list is empty")
		}
		for _, endpoint := range endpoints {
			if endpoint == "" {
				return errors.New("endpoint cannot be empty")
			}
			if endpoint != strings.TrimSpace(endpoint) {
				return errors.New("endpoint cannot contain leading or trailing whitespace")
			}
			if slices.Index(o.Endpoints, endpoint) != -1 {
				return fmt.Errorf("endpoint %q was already added", endpoint)
			}
		}
		o.Endpoints = append(o.Endpoints, endpoints...)
		return nil
	}
}

func WithClientPool(pool *sync.Pool) Option {
	return func(o *options) error {
		if pool == nil {
			return errors.New("network client pool is nil")
		}
		client := pool.Get()
		defer pool.Put(client)
		if client == nil {
			return errors.New("client pool returned a nil http.Client")
		}
		if _, ok := client.(*http.Client); !ok {
			return errors.New("client pool does not contain a reference to an http.Client")
		}
		o.ClientPool = pool
		return nil
	}
}
