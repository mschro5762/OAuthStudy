package middleware

import (
	"net/http"
	"net/url"
	"testing"
)

func TestCommonHandlers_CallsNext(t *testing.T) {
	calledFunc := false
	fn := func(_ http.ResponseWriter, req *http.Request) {
		calledFunc = true
	}
	wrapped := http.HandlerFunc(fn)

	handler := CommonHandlers(wrapped)

	req := http.Request{
		URL: &url.URL{Path: "/"},
	}
	handler.ServeHTTP(nil, &req)

	if !calledFunc {
		t.Fail()
	}
}
