package authorize

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"
)

func TestJARDialSharesRemainingBudget(t *testing.T) {
	for _, test := range []struct {
		name      string
		addresses []netip.Addr
		allStall  bool
	}{
		{"stalled first reachable second", []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, false},
		{"all stalled", []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, true},
		{"single stalled", []netip.Addr{netip.MustParseAddr("::1")}, true},
		{"single reachable", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			calls := 0
			var lastAttempt context.Context
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			conn, err := dialJARNetworkTarget(ctx, "tcp", jarNetworkTarget{
				addresses: test.addresses, port: "443", allowAddress: loopbackJARIPAddress,
			}, func(attempt context.Context, _, address string) (net.Conn, error) {
				calls++
				lastAttempt = attempt
				if address == "127.0.0.1:443" && !test.allStall {
					if err := attempt.Err(); err != nil {
						return nil, err
					}
					return client, nil
				}
				<-attempt.Done()
				return nil, attempt.Err()
			})
			if test.allStall {
				if !errors.Is(err, context.DeadlineExceeded) || conn != nil {
					t.Fatalf("stalled dials = %v, %v", conn, err)
				}
			} else if err != nil || conn != client || ctx.Err() != nil {
				t.Fatalf("fallback did not succeed within parent budget: %v", err)
			}
			if lastAttempt == nil || lastAttempt.Err() == nil {
				t.Fatal("attempt context was not canceled promptly")
			}
			if calls != len(test.addresses) {
				t.Fatalf("dial calls = %d, want %d", calls, len(test.addresses))
			}
		})
	}
}

func TestJARDialStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := dialJARNetworkTarget(ctx, "tcp", jarNetworkTarget{
		addresses: []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")},
		port:      "443", allowAddress: loopbackJARIPAddress,
	}, func(attempt context.Context, _, _ string) (net.Conn, error) {
		calls++
		cancel()
		<-attempt.Done()
		return nil, attempt.Err()
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancellation = %v, dial calls = %d", err, calls)
	}
}

func TestJARDialFamilyFilterDoesNotConsumeBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	parentDeadline, _ := ctx.Deadline()
	calls := 0
	stopped := errors.New("dial stopped by test")
	_, err := dialJARNetworkTarget(ctx, "tcp4", jarNetworkTarget{
		addresses: []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")},
		port:      "443", allowAddress: loopbackJARIPAddress,
	}, func(attempt context.Context, network, address string) (net.Conn, error) {
		calls++
		deadline, _ := attempt.Deadline()
		if network != "tcp4" || address != "127.0.0.1:443" || !deadline.Equal(parentDeadline) {
			t.Fatal("family filtering changed the eligible literal or its single-address budget")
		}
		return nil, stopped
	})
	if calls != 1 || !errors.Is(err, stopped) {
		t.Fatalf("filtered dial calls = %d, error = %v", calls, err)
	}
}

func TestJARTransportKeepsOriginalDialCancellation(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancellation", true: "deadline"}[expire], func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			defer server.Close()
			uri, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			client, transport, err := newGuardedJARHTTPClient(ctx, server.Client(), jarNetworkTarget{
				hostname: uri.Hostname(), port: uri.Port(),
				addresses: []netip.Addr{netip.MustParseAddr(uri.Hostname())}, allowAddress: loopbackJARIPAddress,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			originalDial := transport.DialContext
			type result struct {
				deadlineStripped bool
				err              error
			}
			results := make(chan result, 1)
			transport.DialContext = func(detached context.Context, network, address string) (net.Conn, error) {
				_, hasDeadline := detached.Deadline()
				if expire {
					<-ctx.Done()
				} else {
					cancel()
				}
				conn, dialErr := originalDial(detached, network, address)
				if conn != nil {
					_ = conn.Close()
				}
				results <- result{!hasDeadline, dialErr}
				return nil, context.Canceled
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, _ := client.Do(req)
			if response != nil {
				_ = response.Body.Close()
			}
			select {
			case got := <-results:
				if !got.deadlineStripped || !errors.Is(got.err, ctx.Err()) {
					t.Fatalf("transport stripped deadline = %v, guarded dial error = %v", got.deadlineStripped, got.err)
				}
			case <-time.After(time.Second):
				t.Fatal("guarded dial did not finish")
			}
		})
	}
}
