package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"time"
)

const fixtureHost = "conformance.localhost"

type probeEvent struct {
	Endpoint   string `json:"endpoint"`
	Family     string `json:"family"`
	Phase      string `json:"phase"`
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Ordinal    int    `json:"ordinal,omitempty"`
	Count      int    `json:"count"`
}

func main() {
	if runtime.Version() != "go1.27.3" {
		if err := json.NewEncoder(os.Stdout).Encode(probeEvent{Endpoint: "suite_readiness", Family: "set", Phase: "toolchain", Status: "unexpected_pin"}); err != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
	pem, err := os.ReadFile("examples/keys/server.crt")
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		if err := json.NewEncoder(os.Stdout).Encode(probeEvent{Endpoint: "suite_readiness", Family: "set", Phase: "trust", Status: "invalid_fixture_trust"}); err != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	passed := runProbe(ctx, roots, net.DefaultResolver.LookupNetIP, (&net.Dialer{}).DialContext, os.Stdout)
	cancel()
	if !passed {
		os.Exit(1)
	}
}

func validatedAddresses(addresses []netip.Addr) ([]netip.Addr, string) {
	seen := make(map[netip.Addr]bool, 8)
	validated := make([]netip.Addr, 0, 8)
	for _, address := range addresses {
		if !address.IsValid() || address.Is4In6() || address.Zone() != "" || !address.IsLoopback() {
			return nil, "prohibited_answer"
		}
		if seen[address] {
			continue
		}
		if len(validated) == 8 {
			return nil, "answer_limit"
		}
		seen[address] = true
		validated = append(validated, address)
	}
	if len(validated) == 0 {
		return nil, "no_answers"
	}
	return validated, "ok"
}

func runProbe(ctx context.Context, roots *x509.CertPool,
	resolve func(context.Context, string, string) ([]netip.Addr, error),
	dial func(context.Context, string, string) (net.Conn, error), output io.Writer,
) bool {
	outputOK := true
	record := func(family, phase, status string, started time.Time, httpStatus, ordinal, count int) {
		if err := json.NewEncoder(output).Encode(probeEvent{"suite_readiness", family, phase, status,
			time.Since(started).Milliseconds(), httpStatus, ordinal, count}); err != nil {
			outputOK = false
		}
	}
	started := time.Now()
	resolveCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	addresses, err := resolve(resolveCtx, "ip", fixtureHost)
	cancel()
	if err != nil {
		record("set", "resolve", errorClass(err), started, 0, 0, 0)
		return false
	}
	addresses, status := validatedAddresses(addresses)
	if status != "ok" {
		record("set", "resolve", status, started, 0, 0, 0)
		return false
	}
	for _, family := range []string{"v4", "v6"} {
		count := 0
		for _, address := range addresses {
			if addressFamily(address) == family {
				count++
			}
		}
		status := "native_loopback"
		if count == 0 {
			status = "not_observed"
		}
		record(family, "resolve", status, started, 0, 0, count)
	}
	passed := true
	for i, address := range addresses {
		family := addressFamily(address)
		record(family, "address", "native_loopback", time.Now(), 0, i+1, len(addresses))
		if !probeAddress(ctx, roots, address, dial, func(phase, status string, started time.Time, httpStatus int) {
			record(family, phase, status, started, httpStatus, i+1, len(addresses))
		}) {
			passed = false
		}
	}
	status = "failed"
	if passed && outputOK {
		status = "passed"
	}
	record("set", "terminal", status, started, 0, 0, len(addresses))
	return passed && outputOK
}

func addressFamily(address netip.Addr) string {
	if address.Is4() {
		return "v4"
	}
	return "v6"
}

func probeAddress(parent context.Context, roots *x509.CertPool, address netip.Addr,
	dial func(context.Context, string, string) (net.Conn, error),
	record func(string, string, time.Time, int),
) bool {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	raw, err := dial(ctx, "tcp", net.JoinHostPort(address.String(), "8443"))
	if err != nil {
		record("tcp", errorClass(err), started, 0)
		return false
	}
	defer func() { _ = raw.Close() }()
	deadline, _ := ctx.Deadline()
	if raw.SetDeadline(deadline) != nil {
		record("tcp", "other_error", started, 0)
		return false
	}
	record("tcp", "ok", started, 0)
	connection := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: fixtureHost})
	started = time.Now()
	if err := connection.HandshakeContext(ctx); err != nil {
		record("tls", errorClass(err), started, 0)
		return false
	}
	record("tls", "ok", started, 0)
	started = time.Now()
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+fixtureHost+":8443/api/runner/available", nil)
	if err != nil {
		record("http", "other_error", started, 0)
		return false
	}
	request.Close = true
	if err := request.Write(connection); err != nil {
		record("http", errorClass(err), started, 0)
		return false
	}
	// HEAD has no response body; bound the complete status/header block as well.
	limited := &io.LimitedReader{R: connection, N: 65537}
	response, err := http.ReadResponse(bufio.NewReader(limited), request)
	if limited.N == 0 {
		record("http", "header_limit", started, 0)
		return false
	}
	if err != nil {
		record("http", errorClass(err), started, 0)
		return false
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		record("http", "unexpected_http_status", started, response.StatusCode)
		return false
	}
	record("http", "ok", started, response.StatusCode)
	return true
}

func errorClass(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return "unreachable"
	}
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		return "tls_validation_failed"
	}
	return "other_error"
}
