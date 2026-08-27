package oidc

import (
	"context"
	"net/http"
)

type formParseFailureContextKey struct{}

// ParseBoundedForm applies a hard request-body limit before configured
// middleware can parse a form and preserves the first parse failure. Go's form
// parser retains valid fields alongside some syntax errors, while later calls
// to ParseForm return nil, so strict handlers must be able to fail closed on
// the original result.
func ParseBoundedForm(
	response http.ResponseWriter,
	request *http.Request,
	maximumBytes int64,
) *http.Request {
	if request == nil || request.Method != http.MethodPost || request.Body == nil ||
		request.PostForm != nil {
		return request
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumBytes)
	if err := request.ParseForm(); err != nil {
		return request.WithContext(context.WithValue(
			request.Context(),
			formParseFailureContextKey{},
			struct{}{},
		))
	}
	return request
}

// FormParseFailed reports whether ParseBoundedForm observed a parse failure
// before configured middleware ran.
func FormParseFailed(request *http.Request) bool {
	if request == nil {
		return false
	}
	_, failed := request.Context().Value(formParseFailureContextKey{}).(struct{})
	return failed
}
