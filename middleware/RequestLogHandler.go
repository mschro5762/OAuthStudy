package middleware

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/contexthelper"
)

type readableResponseWriter struct {
	http.ResponseWriter
	StatusCode int
}

func (rsp *readableResponseWriter) WriteHeader(statusCode int) {
	rsp.StatusCode = statusCode
	rsp.ResponseWriter.WriteHeader(statusCode)
}

// RequestLogHandler Gets the logger from the request context, and logs the request string
// Panics if no logger is set on the context.
// This middleware is designed to be used after ContextLoggerHandler
func RequestLogHandler(next http.Handler) http.Handler {
	fn := func(rsp http.ResponseWriter, req *http.Request) {
		logger := contexthelper.LoggerFromContext(req.Context())

		logger.Info("Recieved HTTP request",
			zap.String(logFieldHTTPMethod, req.Method),
			zap.String(logFieldReqPath, req.URL.Path))

		readableRsp := &readableResponseWriter{
			ResponseWriter: rsp,
			// I would have preferred an error default, but calling WriteHeader
			// is optional and casues a 200 response if not called.
			StatusCode: http.StatusOK,
		}

		startTime := time.Now()
		next.ServeHTTP(readableRsp, req)
		endTime := time.Now()

		logger.Info("Request ended",
			zap.Int("responseCode", readableRsp.StatusCode),
			zap.Duration("duration", endTime.Sub(startTime)))
	}

	return http.HandlerFunc(fn)
}
