package token

import (
	"errors"
	"net/http"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

const humanTokenMaxFormBytes int64 = 56 * 1024

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	createHandler := limitHumanTokenMiddlewareBody(
		config,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCreate), middlewares...),
	)
	router.Handle("POST "+config.EndpointPrefix+config.TokenEndpoint, createHandler)

	if config.TokenIntrospectionEnabled {
		router.Handle("POST "+config.EndpointPrefix+config.TokenIntrospectionEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleIntrospection), middlewares...))
	}

	if config.TokenRevocationEnabled {
		revocationHandler := limitHumanTokenMiddlewareBody(
			config,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleRevocation), middlewares...),
		)
		router.Handle("POST "+config.EndpointPrefix+config.TokenRevocationEndpoint, revocationHandler)
	}
}

func handleCreate(ctx oidc.Context) {
	ctx = ctx.BeginTokenEndpointEvidence()
	result := goidc.TokenEndpointResultServerError
	defer func() {
		ctx.EmitTokenEndpointEvidence(result)
	}()

	limitHumanTokenFormBody(ctx)
	if oidc.FormParseFailed(ctx.Request) {
		err := goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
		if ctx.Err() == nil && ctx.WriteErrorResult(err) == nil {
			result = tokenEndpointResultFromError(err)
		}
		return
	}
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
	if err := writeTokenResponse(ctx, tokenResp); err != nil {
		if ctx.Err() == nil {
			ctx.WriteError(err)
		}
		return
	}
	result = goidc.TokenEndpointResultIssued
}

func writeTokenResponse(ctx oidc.Context, tokenResp response) error {
	if tokenResp.noStore {
		ctx.Response.Header().Set("Cache-Control", "no-store")
		ctx.Response.Header().Set("Pragma", "no-cache")
		return ctx.Write(newStrictHumanResponse(tokenResp), http.StatusOK)
	}
	return ctx.Write(tokenResp, http.StatusOK)
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
	ctx.Response.Header().Set("Cache-Control", "no-store")
	ctx.Response.Header().Set("Pragma", "no-cache")
	limitHumanTokenFormBody(ctx)
	if oidc.FormParseFailed(ctx.Request) {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request"))
		return
	}
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

func limitHumanTokenFormBody(ctx oidc.Context) {
	// The client profile cannot be resolved safely until after form decoding,
	// so enabling the strict Human flow deliberately bounds the shared endpoint.
	if !ctx.HumanConfidentialBFFAuthorizationEnabled || ctx.Request == nil ||
		ctx.Request.Body == nil || ctx.Request.PostForm != nil {
		return
	}
	ctx.Request.Body = http.MaxBytesReader(ctx.Response, ctx.Request.Body, humanTokenMaxFormBytes)
}

func limitHumanTokenMiddlewareBody(config *oidc.Configuration, next http.Handler) http.Handler {
	if config == nil || !config.HumanConfidentialBFFAuthorizationEnabled {
		return next
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		request = oidc.ParseBoundedForm(response, request, humanTokenMaxFormBytes)
		next.ServeHTTP(response, request)
	})
}
