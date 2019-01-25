package middleware

import (
	"errors"
	"github.com/mschro5762/OAuthStudy/contexthelper"
	"net/http"
	"testing"

	"go.uber.org/zap"
)

func TestContextLoggerHandler_ServeHTTP_CallsNext(t *testing.T) {
	fnCalled := false
	fn := func(_ http.ResponseWriter, _ *http.Request) {
		fnCalled = true
	}
	wrapped := http.HandlerFunc(fn)

	handler := DefaultContextLoggerHandler(wrapped)
	req := http.Request{}
	handler.ServeHTTP(nil, &req)

	if !fnCalled {
		t.Fail()
	}
}

func TestContextLoggerHandler_ServeHTTP_AddsLoggerToRequestContext(t *testing.T) {
	fn := func(_ http.ResponseWriter, req *http.Request) {
		logger := contexthelper.LoggerFromContext(req.Context())

		if logger == nil {
			t.Fail()
		}
	}
	wrapped := http.HandlerFunc(fn)

	handler := DefaultContextLoggerHandler(wrapped)

	req := http.Request{}
	handler.ServeHTTP(nil, &req)
}

type observableLogger struct {
	*zap.Logger
	Fields     []zap.Field
	SyncCalled bool
}

func (ol *observableLogger) With(fields ...zap.Field) *zap.Logger {
	ol.Fields = append(ol.Fields, fields...)

	return ol.Logger.With(fields...)
}

func (ol *observableLogger) Sync() error {
	ol.SyncCalled = true
	return ol.Logger.Sync()
}

func TestContextLoggerHandler_ServeHTTP_AddsRequestIdToLogger(t *testing.T) {
	fn := func(_ http.ResponseWriter, _ *http.Request) {
		// NOP
	}
	wrapped := http.HandlerFunc(fn)

	ol := observableLogger{
		Logger: zap.NewNop(),
		Fields: make([]zap.Field, 1),
	}

	handler := CustomContextLoggerHandler(wrapped, func() (contexthelper.ILogger, error) { return &ol, nil })

	req := http.Request{}
	handler.ServeHTTP(nil, &req)

	var foundReqID zap.Field
	for _, f := range ol.Fields {
		if f.Key == "reqId" {
			foundReqID = f
		}
	}

	if (foundReqID == zap.Field{}) || (foundReqID.String == "") {
		t.Fail()
	}
}

func TestContextLoggerHandler_ServeHTTP_LoggerFactoryReturnsError_Panics(t *testing.T) {
	defer func() {
		// The handler should recover
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	fn := func(_ http.ResponseWriter, _ *http.Request) {
		panic("Test!")
	}
	wrapped := http.HandlerFunc(fn)

	handler := CustomContextLoggerHandler(wrapped, func() (contexthelper.ILogger, error) { return nil, errors.New("test error") })

	handler.ServeHTTP(nil, nil)
}

func TestContextLoggerHandler_ServeHTTP_CallsLoggerSync(t *testing.T) {
	fn := func(_ http.ResponseWriter, _ *http.Request) {
		// NOP
	}
	wrapped := http.HandlerFunc(fn)

	ol := observableLogger{
		Logger: zap.NewNop(),
		Fields: make([]zap.Field, 1),
	}

	handler := CustomContextLoggerHandler(wrapped, func() (contexthelper.ILogger, error) { return &ol, nil })

	req := http.Request{}
	handler.ServeHTTP(nil, &req)

	if !ol.SyncCalled {
		t.Fail()
	}
}
