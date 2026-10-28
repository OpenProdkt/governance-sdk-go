package governance

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"
)

// postReused sends one POST through the client and reports whether the connection came from the pool.
func postReused(t *testing.T, client *Client, url string) bool {
	t.Helper()
	var reused bool
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}
	ctx := httptrace.WithClientTrace(context.Background(), trace)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return reused
}

func TestNewClientWithTransportNeverReusesConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	client := NewClientWithTransport(server.URL, "", time.Second, transport)
	for i := 0; i < 2; i++ {
		if postReused(t, client, server.URL) {
			t.Fatalf("request %d reused a pooled connection with keep-alives disabled", i)
		}
	}
}

func TestNewClientDefaultTransportReusesConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "", time.Second)
	postReused(t, client, server.URL)
	if !postReused(t, client, server.URL) {
		t.Fatal("default client did not reuse a connection; the reuse check cannot detect pooling")
	}
}
