package httpclient

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// mockTransport counts calls and returns the configured responses in sequence.
type mockTransport struct {
	calls     atomic.Int32
	responses []*http.Response
}

func (m *mockTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	n := int(m.calls.Add(1)) - 1
	if n >= len(m.responses) {
		return m.responses[len(m.responses)-1], nil
	}
	return m.responses[n], nil
}

func fakeResp(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}
}

func TestRetryTransport_429ThenOK(t *testing.T) {
	mock := &mockTransport{
		responses: []*http.Response{
			fakeResp(http.StatusTooManyRequests),
			fakeResp(http.StatusOK),
		},
	}
	rt := &RetryTransport{Base: mock, MaxRetries: 3, MaxBackoff: time.Millisecond}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := mock.calls.Load(); got != 2 {
		t.Fatalf("expected 2 calls, got %d", got)
	}
}

func TestRetryTransport_503ThenOK(t *testing.T) {
	mock := &mockTransport{
		responses: []*http.Response{
			fakeResp(http.StatusServiceUnavailable),
			fakeResp(http.StatusOK),
		},
	}
	rt := &RetryTransport{Base: mock, MaxRetries: 3, MaxBackoff: time.Millisecond}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := mock.calls.Load(); got != 2 {
		t.Fatalf("expected 2 calls, got %d", got)
	}
}

func TestRetryTransport_404NoRetry(t *testing.T) {
	mock := &mockTransport{
		responses: []*http.Response{fakeResp(http.StatusNotFound)},
	}
	rt := &RetryTransport{Base: mock, MaxRetries: 3, MaxBackoff: time.Millisecond}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	if got := mock.calls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 call for 404 (no retry), got %d", got)
	}
}

func TestRetryTransport_ExhaustedReturnsLast(t *testing.T) {
	mock := &mockTransport{
		responses: []*http.Response{
			fakeResp(http.StatusTooManyRequests),
			fakeResp(http.StatusTooManyRequests),
			fakeResp(http.StatusTooManyRequests),
			fakeResp(http.StatusTooManyRequests),
		},
	}
	rt := &RetryTransport{Base: mock, MaxRetries: 3, MaxBackoff: time.Millisecond}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after exhaustion, got %d", resp.StatusCode)
	}
	// 1 initial attempt + 3 retries = 4 calls total
	if got := mock.calls.Load(); got != 4 {
		t.Fatalf("expected 4 calls (1 + 3 retries), got %d", got)
	}
}

func TestRetryTransport_RetryAfterHeader(t *testing.T) {
	mock := &mockTransport{
		responses: []*http.Response{
			{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"0"}}, Body: http.NoBody},
			fakeResp(http.StatusOK),
		},
	}
	rt := &RetryTransport{Base: mock, MaxRetries: 3, MaxBackoff: time.Millisecond}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
