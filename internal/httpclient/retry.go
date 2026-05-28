// Package httpclient provides a shared HTTP transport with automatic retry
// and backoff for transient failures (429, 503, network errors).
package httpclient

import (
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

const (
	defaultMaxRetries = 3
	defaultMaxBackoff = 30 * time.Second
	baseBackoff       = 1 * time.Second
)

// RetryTransport wraps an http.RoundTripper and automatically retries on 429
// Too Many Requests and 503 Service Unavailable, respecting the Retry-After
// header. Network errors are retried with exponential backoff plus full jitter.
// All other status codes (including other 4xx) are returned immediately.
type RetryTransport struct {
	Base       http.RoundTripper
	MaxRetries int
	MaxBackoff time.Duration
}

// New returns a RetryTransport wrapping http.DefaultTransport with sensible
// defaults (3 retries, 30 s max backoff).
func New() *RetryTransport {
	return &RetryTransport{
		Base:       http.DefaultTransport,
		MaxRetries: defaultMaxRetries,
		MaxBackoff: defaultMaxBackoff,
	}
}

// NewWrapping returns a RetryTransport that wraps the supplied base transport.
// Use this when the caller already has a custom transport (e.g. a TLS-pinned
// or SSRF-safe dialer) that should be preserved.
func NewWrapping(base http.RoundTripper) *RetryTransport {
	return &RetryTransport{
		Base:       base,
		MaxRetries: defaultMaxRetries,
		MaxBackoff: defaultMaxBackoff,
	}
}

func (t *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	maxRetries := t.MaxRetries
	if maxRetries <= 0 {
		maxRetries = defaultMaxRetries
	}
	maxBackoff := t.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = defaultMaxBackoff
	}

	var resp *http.Response
	var err error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := backoffDelay(attempt-1, maxBackoff, resp)
			// Respect context cancellation during the sleep.
			select {
			case <-req.Context().Done():
				if resp != nil {
					resp.Body.Close()
				}
				return nil, req.Context().Err()
			case <-time.After(delay):
			}
			// Drain and close the previous response body before retrying.
			if resp != nil {
				resp.Body.Close()
				resp = nil
			}
		}

		resp, err = base.RoundTrip(req)
		if err != nil {
			// Network error — retry if attempts remain.
			continue
		}
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
			return resp, nil
		}
		// 429 or 503 — retry if attempts remain.
	}

	if err != nil {
		return nil, err
	}
	return resp, nil
}

// backoffDelay computes the sleep duration for a given retry attempt using
// exponential backoff with full jitter, capped at maxBackoff. If the response
// carries a Retry-After header, that value takes precedence.
func backoffDelay(attempt int, maxBackoff time.Duration, resp *http.Response) time.Duration {
	if resp != nil {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
				d := time.Duration(secs) * time.Second
				if d > maxBackoff {
					d = maxBackoff
				}
				return d
			}
			// Retry-After as HTTP-date is rare on these APIs; ignore it and
			// fall through to exponential backoff.
		}
	}

	// Full-jitter exponential backoff: rand(0, min(maxBackoff, base * 2^attempt))
	cap := baseBackoff << attempt // base * 2^attempt
	if cap > maxBackoff || cap < 0 {
		cap = maxBackoff
	}
	// rand.Int63n panics on 0, but cap is at least baseBackoff (1s).
	return time.Duration(rand.Int63n(int64(cap)))
}
