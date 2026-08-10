package token

import (
	"errors"
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	router.Handle("POST "+config.EndpointPrefix+config.TokenEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCreate), middlewares...))

	if config.TokenIntrospectionEnabled {
		router.Handle("POST "+config.EndpointPrefix+config.TokenIntrospectionEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleIntrospection), middlewares...))
	}

	if config.TokenRevocationEnabled {
		router.Handle("POST "+config.EndpointPrefix+config.TokenRevocationEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleRevocation), middlewares...))
	}
}

func handleCreate(ctx oidc.Context) {
	ctx = ctx.BeginTokenEndpointEvidence()
	result := goidc.TokenEndpointResultServerError
	defer func() {
		ctx.EmitTokenEndpointEvidence(result)
	}()

	if mediaType := ctx.MediaType(); mediaType != "" && mediaType != "application/x-www-form-urlencoded" {
		err := goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("content type must be application/x-www-form-urlencoded"))
		if ctx.Err() == nil && ctx.WriteErrorResult(err) == nil {
			result = tokenEndpointResultFromError(err)
		}
		return
	}

	req := newRequest(ctx.Request)
	tokenResp, err := generateToken(ctx, req)
	if err != nil {
		var oidcErr goidc.Error
		if errors.As(err, &oidcErr) && oidcErr.Code == goidc.ErrorCodeUnauthorizedClient {
			err = oidcErr.WithStatusCode(http.StatusBadRequest)
		}
		if ctx.Err() == nil && ctx.WriteErrorResult(err) == nil {
			result = tokenEndpointResultFromError(err)
		}
		return
	}

	if ctx.Err() != nil {
		return
	}
	if err := ctx.Write(tokenResp, http.StatusOK); err != nil {
		if ctx.Err() == nil {
			ctx.WriteError(err)
		}
		return
	}
	result = goidc.TokenEndpointResultIssued
}

func handleIntrospection(ctx oidc.Context) {
	if mediaType := ctx.MediaType(); mediaType != "" && mediaType != "application/x-www-form-urlencoded" {
		ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("content type must be application/x-www-form-urlencoded")))
		return
	}

	req := newQueryRequest(ctx.Request)
	tokenInfo, err := introspect(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(tokenInfo, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleRevocation(ctx oidc.Context) {
	if mediaType := ctx.MediaType(); mediaType != "" && mediaType != "application/x-www-form-urlencoded" {
		ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("content type must be application/x-www-form-urlencoded")))
		return
	}

	req := newQueryRequest(ctx.Request)
	err := revoke(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	ctx.WriteStatus(http.StatusOK)
}
