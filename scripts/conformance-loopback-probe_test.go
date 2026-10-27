package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestValidatedAddresses(t *testing.T) {
	for _, test := range []struct {
		name, input, status string
		count               int
	}{
		{"native", "::1 127.0.0.1 ::1", "ok", 2},
		{"mapped", "127.0.0.1 ::ffff:127.0.0.1", "prohibited_answer", 0},
		{"mixed", "::1 8.8.8.8", "prohibited_answer", 0},
		{"mixed_reverse", "8.8.8.8 ::1", "prohibited_answer", 0},
		{"zone", "::1%zone", "prohibited_answer", 0},
		{"empty", "", "no_answers", 0},
		{"too_many", "127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5 127.0.0.6 127.0.0.7 127.0.0.8 127.0.0.9", "answer_limit", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := strings.Fields(test.input)
			input := make([]netip.Addr, 0, len(fields))
			for _, value := range fields {
				input = append(input, netip.MustParseAddr(value))
			}
			got, status := validatedAddresses(input)
			if status != test.status || len(got) != test.count {
				t.Fatal("address_set_verdict_differs")
			}
			if test.name == "native" && (!got[0].Is6() || !got[1].Is4()) {
				t.Fatal("resolver_order_changed")
			}
		})
	}
	if _, status := validatedAddresses([]netip.Addr{{}}); status != "prohibited_answer" {
		t.Fatal("invalid_address_accepted")
	}
}

func TestProbePhasesAndClosedOutput(t *testing.T) {
	certificate, roots := fixtureCertificate(t)
	for _, test := range []struct {
		name, input, mode, status string
		pass                      bool
		dials                     int
	}{
		{"ipv4_only", "127.0.0.1", "ok", "not_observed", true, 1},
		{"ipv6_only", "::1", "ok", "not_observed", true, 1},
		{"both_deduplicated", "::1 127.0.0.1 ::1", "ok", "passed", true, 2},
		{"mixed_no_dial", "127.0.0.1 8.8.8.8", "ok", "prohibited_answer", false, 0},
		{"mapped_no_dial", "::1 ::ffff:127.0.0.1", "ok", "prohibited_answer", false, 0},
		{"dns_failure", "", "dns_failure", "other_error", false, 0},
		{"first_tcp_timeout_still_checks_second", "::1 127.0.0.1", "tcp_timeout", "timeout", false, 2},
		{"tls_trust", "127.0.0.1", "bad_trust", "tls_validation_failed", false, 1},
		{"http_status", "127.0.0.1", "http_status", "unexpected_http_status", false, 1},
		{"redirect_not_followed", "127.0.0.1", "redirect", "unexpected_http_status", false, 1},
		{"header_limit", "127.0.0.1", "header_limit", "header_limit", false, 1},
		{"incomplete_headers", "127.0.0.1", "incomplete_headers", "other_error", false, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := strings.Fields(test.input)
			addresses := make([]netip.Addr, 0, len(fields))
			for _, value := range fields {
				addresses = append(addresses, netip.MustParseAddr(value))
			}
			resolve := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 4*time.Second || network != "ip" || host != fixtureHost {
					t.Fatal("resolver_contract_differs")
				}
				if test.mode == "dns_failure" {
					return nil, errors.New("PRIVATE_SENTINEL")
				}
				return addresses, nil
			}
			var peers sync.WaitGroup
			defer peers.Wait()
			dials := 0
			var invalidPeer bool
			var peerMu sync.Mutex
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				dials++
				deadline, ok := ctx.Deadline()
				if !ok || ctx.Err() != nil || time.Until(deadline) > 4*time.Second || network != "tcp" {
					t.Fatal("independent_address_deadline_missing")
				}
				if test.mode == "tcp_timeout" && dials == 1 {
					return nil, context.DeadlineExceeded
				}
				if address != net.JoinHostPort(addresses[dials-1].String(), "8443") {
					t.Fatal("validated_literal_not_pinned")
				}
				client, raw := net.Pipe()
				peers.Add(1)
				go func() {
					defer peers.Done()
					defer raw.Close()
					_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
					server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
					if server.Handshake() != nil {
						return
					}
					request, err := http.ReadRequest(bufio.NewReader(server))
					if err != nil {
						return
					}
					if server.ConnectionState().ServerName != fixtureHost || request.Method != http.MethodHead ||
						request.Host != fixtureHost+":8443" || request.URL.Path != "/api/runner/available" ||
						request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
						peerMu.Lock()
						invalidPeer = true
						peerMu.Unlock()
					}
					response := "HTTP/1.1 200 OK\r\nContent-Length: 123\r\nX-Private: PRIVATE_SENTINEL\r\n\r\n"
					switch test.mode {
					case "http_status":
						response = "HTTP/1.1 503 Unavailable\r\n\r\n"
					case "redirect":
						response = "HTTP/1.1 302 Found\r\nLocation: https://PRIVATE_SENTINEL/\r\n\r\n"
					case "header_limit":
						response = "HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", 65536) + "\r\n\r\n"
					case "incomplete_headers":
						response = "HTTP/1.1 200 OK\r\nX-Incomplete:"
					}
					_, _ = io.WriteString(server, response)
				}()
				return client, nil
			}
			trust := roots
			if test.mode == "bad_trust" {
				trust = x509.NewCertPool()
			}
			var output bytes.Buffer
			pass := runProbe(context.Background(), trust, resolve, dial, &output)
			peers.Wait()
			if pass != test.pass || dials != test.dials || invalidPeer || !strings.Contains(output.String(), `"status":"`+test.status+`"`) {
				t.Fatal("probe_verdict_or_phase_differs")
			}
			for _, forbidden := range []string{"PRIVATE_SENTINEL", fixtureHost, "127.0.0.1", "::1"} {
				if strings.Contains(output.String(), forbidden) {
					t.Fatal("diagnostic_data_leaked")
				}
			}
			decoder := json.NewDecoder(&output)
			phaseMatched := false
			wantPhase := "http"
			switch test.status {
			case "not_observed", "prohibited_answer":
				wantPhase = "resolve"
			case "passed":
				wantPhase = "terminal"
			case "timeout":
				wantPhase = "tcp"
			case "tls_validation_failed":
				wantPhase = "tls"
			}
			if test.mode == "dns_failure" {
				wantPhase = "resolve"
			}
			for decoder.More() {
				var event probeEvent
				if decoder.Decode(&event) != nil || event.Endpoint != "suite_readiness" || event.Status == "" {
					t.Fatal("closed_event_invalid")
				}
				if event.Phase == wantPhase && event.Status == test.status {
					phaseMatched = true
				}
			}
			if !phaseMatched {
				t.Fatal("error_phase_differs")
			}
		})
	}
}

func TestErrorClasses(t *testing.T) {
	for _, test := range []struct {
		err   error
		class string
	}{
		{context.DeadlineExceeded, "timeout"},
		{syscall.ECONNREFUSED, "connection_refused"},
		{syscall.ENETUNREACH, "unreachable"},
		{syscall.EHOSTUNREACH, "unreachable"},
		{errors.New("PRIVATE_SENTINEL"), "other_error"},
	} {
		if errorClass(test.err) != test.class {
			t.Fatal("error_class_differs")
		}
	}
}

func fixtureCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fake_tls_key_failed")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: fixtureHost},
		DNSNames: []string{fixtureHost}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fake_tls_certificate_failed")
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("fake_tls_trust_failed")
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}
