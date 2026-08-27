package authorize

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestRedirectResponseRejectsDestinationOutsideCurrentRegistration(t *testing.T) {
	for _, responseMode := range []goidc.ResponseMode{
		goidc.ResponseModeQuery,
		goidc.ResponseModeFragment,
		goidc.ResponseModeFormPost,
	} {
		t.Run(string(responseMode), func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			client, _ := oidctest.NewClient(t)
			client.RedirectURIs = []string{"https://client.example.com/callback"}

			err := redirectResponse(ctx, client, goidc.AuthorizationParameters{
				RedirectURI:  "https://attacker.example/callback",
				ResponseMode: responseMode,
				ResponseType: goidc.ResponseTypeCode,
			}, response{authorizationCode: "authorization-code"})
			if err == nil {
				t.Fatal("redirectResponse() error = nil, want current-registration rejection")
			}

			recorder := ctx.Response.(*httptest.ResponseRecorder)
			if location := recorder.Header().Get("Location"); location != "" {
				t.Fatalf("Location = %q, want empty", location)
			}
			if body := recorder.Body.String(); body != "" {
				t.Fatalf("body = %q, want empty", body)
			}
		})
	}
}

func TestRedirectResponseReconstructsRegisteredNativeLoopbackDestination(t *testing.T) {
	tests := []struct {
		name       string
		registered string
		requested  string
		wantHost   string
	}{
		{
			name:       "ipv4",
			registered: "http://127.0.0.1/callback",
			requested:  "http://127.0.0.1:49152/callback",
			wantHost:   "127.0.0.1:49152",
		},
		{
			name:       "ipv6",
			registered: "http://[::1]/callback",
			requested:  "http://[::1]:49153/callback",
			wantHost:   "[::1]:49153",
		},
		{
			name:       "lowest numeric port",
			registered: "http://127.0.0.1/callback",
			requested:  "http://127.0.0.1:0/callback",
			wantHost:   "127.0.0.1:0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			client, _ := oidctest.NewClient(t)
			client.ApplicationType = goidc.ApplicationTypeNative
			client.RedirectURIs = []string{test.registered}

			err := redirectResponse(ctx, client, goidc.AuthorizationParameters{
				RedirectURI:  test.requested,
				ResponseMode: goidc.ResponseModeQuery,
				ResponseType: goidc.ResponseTypeCode,
			}, response{
				authorizationCode: "authorization-code",
				state:             "opaque-state",
			})
			if err != nil {
				t.Fatalf("redirectResponse() error = %v", err)
			}

			location := ctx.Response.(*httptest.ResponseRecorder).Header().Get("Location")
			redirectURL, err := url.Parse(location)
			if err != nil {
				t.Fatalf("url.Parse(%q) error = %v", location, err)
			}
			if redirectURL.Scheme != "http" || redirectURL.Host != test.wantHost || redirectURL.Path != "/callback" {
				t.Fatalf("redirect destination = %q, want http://%s/callback", redirectURL.String(), test.wantHost)
			}
			if redirectURL.Query().Get("code") != "authorization-code" || redirectURL.Query().Get("state") != "opaque-state" {
				t.Fatalf("redirect query = %q, want code and state", redirectURL.RawQuery)
			}
		})
	}
}

func TestCurrentAuthorizationRedirectURIRejectsUntrustedLoopbackComponents(t *testing.T) {
	client := &goidc.Client{ClientMeta: goidc.ClientMeta{
		ApplicationType: goidc.ApplicationTypeNative,
		RedirectURIs:    []string{"http://127.0.0.1/callback"},
	}}

	for _, requested := range []string{
		"http://127.0.0.1:49152/other",
		"http://127.0.0.1:70000/callback",
		"http://127.0.0.1:49152@attacker.example/callback",
		"http://attacker.example:49152/callback",
	} {
		t.Run(strings.ReplaceAll(requested, "/", "_"), func(t *testing.T) {
			if got, err := currentAuthorizationRedirectURI(client, requested); err == nil || got != "" {
				t.Fatalf("currentAuthorizationRedirectURI(%q) = %q, %v; want rejection", requested, got, err)
			}
		})
	}
}
