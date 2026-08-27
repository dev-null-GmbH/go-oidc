package authorize

import (
	"net/http"
	"slices"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

const humanAuthorizationMaxFormBytes int64 = 56 * 1024

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if config.HumanConfidentialBFFAuthorizationEnabled {
		browserRoute := config.EndpointPrefix + humanBrowserInteractionRoute
		consumeRoute := config.EndpointPrefix + humanConsumeInteractionRoute
		browserHandler := limitHumanAuthorizationMiddlewareBody(
			config,
			goidc.ApplyMiddlewares(
				oidc.Handler(config, handlerHumanBrowserInteraction), middlewares...,
			),
			humanInteractionMaxFormBytes,
		)
		consumeHandler := limitHumanAuthorizationMiddlewareBody(
			config,
			goidc.ApplyMiddlewares(
				oidc.Handler(config, handlerHumanConsumeInteraction), middlewares...,
			),
			humanInteractionMaxFormBytes,
		)
		router.Handle("GET "+browserRoute, browserHandler)
		router.Handle("POST "+browserRoute, browserHandler)
		router.Handle(browserRoute, browserHandler)
		router.Handle("GET "+consumeRoute, consumeHandler)
		router.Handle("POST "+consumeRoute, consumeHandler)
		router.Handle(consumeRoute, consumeHandler)
	}

	if slices.ContainsFunc(config.GrantTypes, func(gt goidc.GrantType) bool {
		return gt == goidc.GrantAuthorizationCode || gt == goidc.GrantImplicit
	}) {
		authorizationHandler := limitHumanAuthorizationMiddlewareBody(
			config,
			goidc.ApplyMiddlewares(oidc.Handler(config, handler), middlewares...),
			humanAuthorizationMaxFormBytes,
		)
		router.Handle("GET "+config.EndpointPrefix+config.AuthorizationEndpoint, authorizationHandler)
		router.Handle("POST "+config.EndpointPrefix+config.AuthorizationEndpoint, authorizationHandler)

		if config.LegacyAuthorizationCodeEnabled {
			router.Handle("POST "+config.EndpointPrefix+config.AuthorizationEndpoint+"/{callback}",
				goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...))
			router.Handle("GET "+config.EndpointPrefix+config.AuthorizationEndpoint+"/{callback}",
				goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...))
			router.Handle("POST "+config.EndpointPrefix+config.AuthorizationEndpoint+"/{callback}/{callback_path...}",
				goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...))
			router.Handle("GET "+config.EndpointPrefix+config.AuthorizationEndpoint+"/{callback}/{callback_path...}",
				goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...))
		}
	}

	if config.PAREnabled {
		parHandler := limitHumanAuthorizationMiddlewareBody(
			config,
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerPAR), middlewares...),
			humanAuthorizationMaxFormBytes,
		)
		router.Handle("POST "+config.EndpointPrefix+config.PAREndpoint, parHandler)
	}

	if slices.Contains(config.GrantTypes, goidc.GrantCIBA) {
		router.Handle("POST "+config.EndpointPrefix+config.CIBAEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerCIBA), middlewares...))
	}

	if slices.Contains(config.GrantTypes, goidc.GrantDeviceCode) {
		router.Handle("POST "+config.EndpointPrefix+config.DeviceAuthEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerInitDeviceAuth), middlewares...))

		router.Handle("GET "+config.EndpointPrefix+config.DeviceAuthVerificationEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerInitDeviceVerification), middlewares...))

		router.Handle("POST "+config.EndpointPrefix+config.DeviceAuthVerificationEndpoint+"/{callback}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerContinueDeviceVerification), middlewares...))
		router.Handle("GET "+config.EndpointPrefix+config.DeviceAuthVerificationEndpoint+"/{callback}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerContinueDeviceVerification), middlewares...))
		router.Handle("POST "+config.EndpointPrefix+config.DeviceAuthVerificationEndpoint+"/{callback}/{callback_path...}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerContinueDeviceVerification), middlewares...))
		router.Handle("GET "+config.EndpointPrefix+config.DeviceAuthVerificationEndpoint+"/{callback}/{callback_path...}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerContinueDeviceVerification), middlewares...))
	}
}

func handlerPAR(ctx oidc.Context) {
	limitHumanAuthorizationFormBody(ctx)
	if oidc.FormParseFailed(ctx.Request) {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request"))
		return
	}
	if mediaType := ctx.MediaType(); mediaType != "" && mediaType != "application/x-www-form-urlencoded" {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid content type").WithStatusCode(http.StatusUnsupportedMediaType))
		return
	}

	req := newFormRequest(ctx.Request)
	resp, err := pushAuth(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	ctx.Response.Header().Set("Cache-Control", "no-store")
	ctx.Response.Header().Set("Pragma", "no-cache")
	if err := ctx.Write(resp, http.StatusCreated); err != nil {
		ctx.WriteError(err)
	}
}

func handler(ctx oidc.Context) {
	var req request
	if ctx.Request.Method == http.MethodPost {
		limitHumanAuthorizationFormBody(ctx)
		if oidc.FormParseFailed(ctx.Request) {
			ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request"))
			return
		}
		if mediaType := ctx.MediaType(); mediaType != "" && mediaType != "application/x-www-form-urlencoded" {
			ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid content type").WithStatusCode(http.StatusUnsupportedMediaType))
			return
		}
		req = newFormRequest(ctx.Request)
	} else {
		req = newRequest(ctx.Request)
	}

	err := initAuth(ctx, req)
	if err != nil {
		if err := ctx.RenderError(err); err != nil {
			ctx.WriteError(err)
		}
		return
	}
}

func limitHumanAuthorizationFormBody(ctx oidc.Context) {
	// The client profile cannot be resolved safely until after form decoding,
	// so enabling the strict Human flow deliberately bounds the shared endpoint.
	if !ctx.HumanConfidentialBFFAuthorizationEnabled || ctx.Request == nil ||
		ctx.Request.Body == nil || ctx.Request.PostForm != nil {
		return
	}
	ctx.Request.Body = http.MaxBytesReader(
		ctx.Response,
		ctx.Request.Body,
		humanAuthorizationMaxFormBytes,
	)
}

func limitHumanAuthorizationMiddlewareBody(
	config *oidc.Configuration,
	next http.Handler,
	maximumBytes int64,
) http.Handler {
	if config == nil || !config.HumanConfidentialBFFAuthorizationEnabled {
		return next
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		request = oidc.ParseBoundedForm(response, request, maximumBytes)
		next.ServeHTTP(response, request)
	})
}

func handlerCallback(ctx oidc.Context) {
	callbackID := ctx.Request.PathValue("callback")
	err := continueAuth(ctx, callbackID)
	if err == nil {
		return
	}

	if err := ctx.RenderError(err); err != nil {
		ctx.WriteError(err)
	}
}

func handlerCIBA(ctx oidc.Context) {
	if mediaType := ctx.MediaType(); mediaType != "" && mediaType != "application/x-www-form-urlencoded" {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid content type").WithStatusCode(http.StatusUnsupportedMediaType))
		return
	}

	req := newFormRequest(ctx.Request)
	resp, err := initBackAuth(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(resp, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handlerInitDeviceAuth(ctx oidc.Context) {
	req := newFormRequest(ctx.Request)
	resp, err := initDeviceAuth(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(resp, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handlerInitDeviceVerification(ctx oidc.Context) {
	userCode := ctx.Request.URL.Query().Get("user_code")
	if err := initDeviceAuthVerification(ctx, userCode); err != nil {
		if renderErr := ctx.RenderError(err); renderErr != nil {
			ctx.WriteError(renderErr)
		}
	}
}

func handlerContinueDeviceVerification(ctx oidc.Context) {
	callbackID := ctx.Request.PathValue("callback")
	if err := continueDeviceAuthVerification(ctx, callbackID); err != nil {
		if renderErr := ctx.RenderError(err); renderErr != nil {
			ctx.WriteError(renderErr)
		}
	}
}
