package authutil

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
)

func TestJARHTTPClientVerifiesConformanceTLS(t *testing.T) {
	t.Parallel()

	client := JARHTTPClient(context.Background())
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("JARHTTPClient() transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("JARHTTPClient() TLS configuration is nil")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("JARHTTPClient() disables TLS certificate verification")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("JARHTTPClient() minimum TLS version = %d, want TLS 1.2 or newer", transport.TLSClientConfig.MinVersion)
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("JARHTTPClient() does not trust the ephemeral conformance certificate")
	}
}
