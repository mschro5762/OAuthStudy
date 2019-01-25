package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/contexthelper"
)

func TestRequestLogHandler_ServeHTTP_CallsNext(t *testing.T) {
	fnCalled := false
	fn := func(_ http.ResponseWriter, _ *http.Request) {
		fnCalled = true
	}
	wrapped := http.HandlerFunc(fn)

	handler := RequestLogHandler(wrapped)
	req := &http.Request{
		URL: &url.URL{Path: "/"},
	}
	req = req.WithContext(contexthelper.NewContextWithLogger(zap.NewNop()))
	rsp := httptest.NewRecorder()

	handler.ServeHTTP(rsp, req)

	if !fnCalled {
		t.Fail()
	}
}
