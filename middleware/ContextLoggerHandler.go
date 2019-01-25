package middleware

import (
	"net/http"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/contexthelper"
)

// LoggerFactory Factory method definition to allow custom loggers to be used per request
type LoggerFactory func() (contexthelper.ILogger, error)

// CustomContextLoggerHandler Creates an ILogger using the factory method, adds a request ID (UUID) to it,
// then adds it to the context of the request. This middleware is designed to be the top middleware as other
// middlewares in this package will panic if they try to use a logger from the context and fail to get it.
// Panics (with the intent to crash, i.e. don't recover this) if unable to create a logger
func CustomContextLoggerHandler(next http.Handler, logFactory LoggerFactory) http.Handler {
	fn := func(rsp http.ResponseWriter, req *http.Request) {
		logger, err := logFactory()
		if err != nil {
			panic("Unable to create logger!")
		}
		defer logger.Sync()

		// This request ID is used to tie all logs together
		reqID := uuid.New()

		logger = logger.With(zap.String("reqId", reqID.String()))

		ctx := contexthelper.AddLoggertoContext(req.Context(), logger)
		ctx = contexthelper.AddRequestIDToContext(ctx, reqID)

		newReq := req.WithContext(ctx)

		next.ServeHTTP(rsp, newReq)
	}

	return http.HandlerFunc(fn)
}

// DefaultContextLoggerHandler Creates an ILogger, adds a request ID (UUID) to it, then adds it to the context of the request.
// This middleware is designed to be the top middleware as other middlewares in this package will panic if they try
// to use a logger from the context and fail to get it.
// Panics (with the intent to crash, i.e. don't recover this) if unable to create a logger
func DefaultContextLoggerHandler(next http.Handler) http.Handler {
	return CustomContextLoggerHandler(next, func() (contexthelper.ILogger, error) { return zap.NewProduction() })
}
