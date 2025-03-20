package yubikeyotp

import (
	"context"
	"net/http"
	"time"
)

// DefaultEndpoints is a list of official YubiKey OTP API endpoints.
var DefaultEndpoints = []string{
	"https://api.yubico.com/wsapi/2.0/verify",
	"https://api2.yubico.com/wsapi/2.0/verify",
	"https://api3.yubico.com/wsapi/2.0/verify",
	"https://api4.yubico.com/wsapi/2.0/verify",
	"https://api5.yubico.com/wsapi/2.0/verify",
}

func (a *Authenticator) GetCurrentEndpoint() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.endpoints[a.currentEndpointIndex]
}

func (a *Authenticator) rotateEndpoint() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.currentEndpointIndex++
	if total := len(DefaultEndpoints); a.currentEndpointIndex >= total {
		a.currentEndpointIndex = 0
	}
	return a.endpoints[a.currentEndpointIndex]
}

func (a *Authenticator) sendQuery(
	ctx context.Context,
	query string,
) (response *http.Response, err error) {
	client := a.clientPool.Get().(*http.Client)
	defer a.clientPool.Put(client)

	delay := a.retryBackoffDelay
	endpoint := a.GetCurrentEndpoint()

	for range a.retryLimit {
		request, err := http.NewRequest("GET", endpoint+"?"+query, nil)
		if err != nil {
			return nil, err
		}
		response, err = client.Do(request.WithContext(ctx))
		if err == nil {
			return response, nil
		}
		// TODO: errors.Join or log the attempt error somewhere?

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
			delay *= a.retryBackoffMultiplier
			endpoint = a.rotateEndpoint()
		}
	}
	return nil, err
}
