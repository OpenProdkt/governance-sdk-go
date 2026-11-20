package governance

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func validObservation() *DefinitionObservation {
	return &DefinitionObservation{Digest: "sha256:" + strings.Repeat("ab", 32), Canon: DefinitionObservationCanon, ServerVersion: "1.2.3"}
}

func TestDefinitionObservationWireShape(t *testing.T) {
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, body)
		w.Header().Set("content-type", "application/json")
		io.WriteString(w, `{"decision":"allow","decisionId":"d"}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, "key", time.Second)
	principal := &PrincipalContext{BearerToken: "principal"}

	// Absent when unset, on both endpoints.
	if _, err := client.EvaluateProxy(context.Background(), EvaluateRequest{Version: "v1", OperationID: "op", Transport: TransportContext{Kind: "http"}}, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authorize(context.Background(), AuthorizationRequest{OperationID: "op", AssetKey: "app.svc.prod"}); err != nil {
		t.Fatal(err)
	}
	// Present with exactly digest, canon and server_version.
	if _, err := client.EvaluateProxy(context.Background(), EvaluateRequest{Version: "v1", OperationID: "op", Transport: TransportContext{Kind: "http"}, DefinitionObservation: validObservation()}, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authorize(context.Background(), AuthorizationRequest{OperationID: "op", AssetKey: "app.svc.prod", DefinitionObservation: validObservation()}); err != nil {
		t.Fatal(err)
	}
	// server_version is optional.
	withoutVersion := validObservation()
	withoutVersion.ServerVersion = ""
	if _, err := client.Authorize(context.Background(), AuthorizationRequest{OperationID: "op", AssetKey: "app.svc.prod", DefinitionObservation: withoutVersion}); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 5 {
		t.Fatalf("expected 5 requests, got %d", len(bodies))
	}
	for _, body := range bodies[:2] {
		if strings.Contains(string(body), "definition_observation") {
			t.Fatalf("unset observation was sent: %s", body)
		}
	}
	want := `"definition_observation":{"digest":"sha256:` + strings.Repeat("ab", 32) + `","canon":"mcp-tool-definition:v1","server_version":"1.2.3"}`
	for _, body := range bodies[2:4] {
		if !strings.Contains(string(body), want) {
			t.Fatalf("observation not serialized exactly: %s", body)
		}
	}
	if strings.Contains(string(bodies[4]), "server_version") {
		t.Fatalf("empty server_version was sent: %s", bodies[4])
	}
}

func TestDefinitionObservationValidation(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; t.Error("invalid observation reached server") }))
	defer server.Close()
	client := NewClient(server.URL, "key", time.Second)
	principal := &PrincipalContext{BearerToken: "principal"}
	mutate := func(f func(*DefinitionObservation)) *DefinitionObservation {
		o := validObservation()
		f(o)
		return o
	}
	cases := map[string]*DefinitionObservation{
		"empty digest":      mutate(func(o *DefinitionObservation) { o.Digest = "" }),
		"uppercase digest":  mutate(func(o *DefinitionObservation) { o.Digest = "sha256:" + strings.Repeat("AB", 32) }),
		"short digest":      mutate(func(o *DefinitionObservation) { o.Digest = "sha256:" + strings.Repeat("ab", 31) }),
		"no prefix":         mutate(func(o *DefinitionObservation) { o.Digest = strings.Repeat("ab", 32) }),
		"trailing newline":  mutate(func(o *DefinitionObservation) { o.Digest += "\n" }),
		"empty canon":       mutate(func(o *DefinitionObservation) { o.Canon = "" }),
		"unknown canon":     mutate(func(o *DefinitionObservation) { o.Canon = "mcp-tool-definition:v2" }),
		"canon case":        mutate(func(o *DefinitionObservation) { o.Canon = "MCP-tool-definition:v1" }),
		"control version":   mutate(func(o *DefinitionObservation) { o.ServerVersion = "1.0\n" }),
		"del version":       mutate(func(o *DefinitionObservation) { o.ServerVersion = "1.0\x7f" }),
		"long version":      mutate(func(o *DefinitionObservation) { o.ServerVersion = strings.Repeat("v", 129) }),
		"invalid utf8":      mutate(func(o *DefinitionObservation) { o.ServerVersion = "1.0\xff" }),
		"oversized encoded": mutate(func(o *DefinitionObservation) { o.ServerVersion = strings.Repeat("\u20ac", 128) }),
	}
	for name, observation := range cases {
		t.Run(name, func(t *testing.T) {
			var invalid *InvalidAuthorizationInputError
			_, err := client.EvaluateProxy(context.Background(), EvaluateRequest{Version: "v1", OperationID: "op", Transport: TransportContext{Kind: "http"}, DefinitionObservation: observation}, principal)
			if !errors.As(err, &invalid) {
				t.Fatalf("proxy: want InvalidAuthorizationInputError, got %v", err)
			}
			_, err = client.Authorize(context.Background(), AuthorizationRequest{OperationID: "op", AssetKey: "app.svc.prod", DefinitionObservation: observation})
			if !errors.As(err, &invalid) {
				t.Fatalf("authorize: want InvalidAuthorizationInputError, got %v", err)
			}
		})
	}
	if calls != 0 {
		t.Fatal("unexpected network call")
	}
}

func TestDefinitionObservationSizeIsMeasuredOnTheWireEncoding(t *testing.T) {
	ascii := validObservation()
	ascii.ServerVersion = strings.Repeat("v", 128)
	if err := validateDefinitionObservation(ascii); err != nil {
		t.Fatalf("maximal ASCII observation rejected: %v", err)
	}
	// json.Marshal escapes "<" as \u003c (6 bytes), so 128 of them exceed 512 bytes on the wire.
	escaped := validObservation()
	escaped.ServerVersion = strings.Repeat("<", 128)
	if err := validateDefinitionObservation(escaped); err == nil {
		t.Fatal("observation that exceeds 512 encoded bytes accepted")
	}
}
