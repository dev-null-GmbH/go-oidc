package discovery

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	issuer, _ := url.Parse(config.Host)
	issuerPath := strings.TrimSuffix(issuer.Path, "/")
	if !config.OpenIDConfigurationDisabled {
		openidHandler := goidc.ApplyMiddlewares(
			oidc.Handler(config, handleOpenIDConfiguration),
			middlewares...,
		)
		router.Handle("GET "+issuerPath+"/.well-known/openid-configuration", openidHandler)
	}
	if !config.AuthorizationServerMetadataDisabled {
		authorizationServerHandler := goidc.ApplyMiddlewares(
			oidc.Handler(config, handleAuthorizationServerMetadata),
			middlewares...,
		)
		router.Handle(
			"GET /.well-known/oauth-authorization-server"+issuerPath,
			authorizationServerHandler,
		)
	}

	router.Handle("GET "+config.EndpointPrefix+config.JWKSEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleJWKS), middlewares...))
}

func handleOpenIDConfiguration(ctx oidc.Context) {
	openidConfig := NewConfiguration(ctx)
	if err := ctx.Write(openidConfig, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleAuthorizationServerMetadata(ctx oidc.Context) {
	metadata := NewAuthorizationServerMetadata(ctx)
	if err := ctx.Write(metadata, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleJWKS(ctx oidc.Context) {
	jwks, err := ctx.PublicJWKS()
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(jwks, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}
