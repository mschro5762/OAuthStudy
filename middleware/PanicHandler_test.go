package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mschro5762/OAuthStudy/contexthelper"

	"go.uber.org/zap"
)

func TestPanicHandler_ServeHTTP_CallsNext(t *testing.T) {
	fnCalled := false
	fn := func(_ http.ResponseWriter, _ *http.Request) {
		fnCalled = true
	}
	wrapped := http.HandlerFunc(fn)

	logger := zap.NewNop()
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
		Body:   http.NoBody,
	}
	req = req.WithContext(contexthelper.NewContextWithLogger(logger))
	rsp := httptest.NewRecorder()

	panicHandler := PanicHandler(wrapped)
	panicHandler.ServeHTTP(rsp, req)

	if !fnCalled {
		t.Fail()
	}
}

func TestPanicHandler_ServeHTTP_NextPanics_Recovers(t *testing.T) {
	defer func() {
		// The handler should recover
		if r := recover(); r != nil {
			t.Fail()
		}
	}()

	fn := func(_ http.ResponseWriter, _ *http.Request) {
		panic("Test!")
	}

	logger := zap.NewNop()
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
		Body:   http.NoBody,
	}
	req = req.WithContext(contexthelper.NewContextWithLogger(logger))
	rsp := httptest.NewRecorder()

	panicHandler := PanicHandler(http.HandlerFunc(fn))

	panicHandler.ServeHTTP(rsp, req)
}

func TestPanicHandler_ServeHTTP_NextPanics_Writes500ToResponse(t *testing.T) {
	fn := func(_ http.ResponseWriter, _ *http.Request) {
		panic("Test!")
	}
	wrapped := http.HandlerFunc(fn)

	logger := zap.NewNop()
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
		Body:   http.NoBody,
	}
	req = req.WithContext(contexthelper.NewContextWithLogger(logger))
	rsp := httptest.NewRecorder()

	panicHandler := PanicHandler(wrapped)

	panicHandler.ServeHTTP(rsp, req)

	if rsp.Code != http.StatusInternalServerError {
		t.Fail()
	}
}
