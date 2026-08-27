package authorize

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var (
	errJARProhibitedNetwork  = errors.New("request_uri resolves to a prohibited network address")
	errJARUnsupportedNetwork = errors.New("request_uri HTTP client uses an unsupported network transport")
	jarIPv6GlobalUnicast     = netip.MustParsePrefix("2000::/3")

	// IsGlobalUnicast deliberately includes several non-public special-purpose
	// ranges. The policy also rejects globally reachable IANA special-purpose
	// exceptions, so keep an explicit denylist in addition to the predicates.
	// Registry snapshot (2025-10-09):
	// https://www.iana.org/assignments/iana-ipv4-special-registry
	// https://www.iana.org/assignments/iana-ipv6-special-registry
	jarSpecialUsePrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.31.196.0/24"),
		netip.MustParsePrefix("192.52.193.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("192.175.48.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("::/96"),
		netip.MustParsePrefix("::ffff:0:0/96"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("100:0:0:1::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("2620:4f:8000::/48"),
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParsePrefix("5f00::/16"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("fec0::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

type jarNetIPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type jarNetworkControl struct {
	resolver     jarNetIPResolver
	allowAddress func(netip.Addr) bool
}

type jarNetworkTarget struct {
	hostname     string
	port         string
	addresses    []netip.Addr
	allowAddress func(netip.Addr) bool
}

func resolveJARNetworkTarget(
	ctx context.Context,
	rawURI string,
	control jarNetworkControl,
) (jarNetworkTarget, error) {
	parsed, err := url.Parse(rawURI)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return jarNetworkTarget{}, invalidJARRequestURI()
	}
	if control.resolver == nil {
		control.resolver = net.DefaultResolver
	}
	if control.allowAddress == nil {
		control.allowAddress = publicJARIPAddress
	}

	hostname := parsed.Hostname()
	addresses := make([]netip.Addr, 0, 2)
	if literal, parseErr := netip.ParseAddr(hostname); parseErr == nil {
		addresses = append(addresses, literal)
	} else {
		addresses, err = control.resolver.LookupNetIP(ctx, "ip", hostname)
		if err != nil {
			return jarNetworkTarget{}, fmt.Errorf("could not resolve request_uri host: %w", err)
		}
	}

	seen := make(map[netip.Addr]struct{}, len(addresses))
	validated := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address.Is4In6() {
			return jarNetworkTarget{}, errJARProhibitedNetwork
		}
		address = address.Unmap()
		if !control.allowAddress(address) {
			return jarNetworkTarget{}, errJARProhibitedNetwork
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		validated = append(validated, address)
	}
	if len(validated) == 0 {
		return jarNetworkTarget{}, errors.New("request_uri host resolved to no addresses")
	}

	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	return jarNetworkTarget{
		hostname:     hostname,
		port:         port,
		addresses:    validated,
		allowAddress: control.allowAddress,
	}, nil
}

func publicJARIPAddress(address netip.Addr) bool {
	if address.Is4In6() {
		return false
	}
	address = address.Unmap()
	if !address.IsValid() || address.Zone() != "" || !address.IsGlobalUnicast() ||
		address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	if address.Is6() && !jarIPv6GlobalUnicast.Contains(address) {
		return false
	}
	for _, prefix := range jarSpecialUsePrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func newGuardedJARHTTPClient(
	baseClient *http.Client,
	target jarNetworkTarget,
) (*http.Client, *http.Transport, error) {
	if baseClient == nil {
		return nil, nil, errJARUnsupportedNetwork
	}
	var baseTransport *http.Transport
	switch transport := baseClient.Transport.(type) {
	case nil:
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok || defaultTransport == nil {
			return nil, nil, errJARUnsupportedNetwork
		}
		baseTransport = defaultTransport
	case *http.Transport:
		if transport == nil {
			return nil, nil, errJARUnsupportedNetwork
		}
		baseTransport = transport
	default:
		return nil, nil, errJARUnsupportedNetwork
	}

	transport := baseTransport.Clone()
	// TLS dial hooks and protocol adapters can bypass the guarded plain socket
	// path, so fail closed instead of attempting to wrap them.
	if transport.DialTLSContext != nil || transport.DialTLS != nil { //nolint:staticcheck
		return nil, nil, fmt.Errorf("%w: custom TLS dial hooks are not supported", errJARUnsupportedNetwork)
	}
	if len(transport.TLSNextProto) != 0 {
		return nil, nil, fmt.Errorf("%w: custom TLS protocol handlers are not supported", errJARUnsupportedNetwork)
	}
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, nil, fmt.Errorf("%w: insecure TLS verification is not supported", errJARUnsupportedNetwork)
	}
	// Never evaluate caller-controlled proxy selection against the live request.
	// This one-off transport is always direct, including when the provider's
	// normal HTTP client inherited ProxyFromEnvironment.
	transport.Proxy = nil

	// Do not delegate the final socket choice to caller-supplied plain dial
	// hooks: either hook could ignore the validated literal and resolve again.
	transport.Dial = nil //nolint:staticcheck
	baseDial := (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialJARNetworkTarget(ctx, network, target, baseDial)
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.ServerName = target.hostname

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: baseClient.Timeout,
	}, transport, nil
}

func dialJARNetworkTarget(
	ctx context.Context,
	network string,
	target jarNetworkTarget,
	dial func(context.Context, string, string) (net.Conn, error),
) (net.Conn, error) {
	var failures []error
	for _, address := range target.addresses {
		if !target.allowAddress(address) ||
			(strings.HasSuffix(network, "4") && !address.Is4()) ||
			(strings.HasSuffix(network, "6") && !address.Is6()) {
			continue
		}
		connection, err := dial(ctx, network, net.JoinHostPort(address.String(), target.port))
		if err == nil {
			return connection, nil
		}
		failures = append(failures, err)
	}
	if len(failures) == 0 {
		return nil, errJARProhibitedNetwork
	}
	return nil, errors.Join(failures...)
}
