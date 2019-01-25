package middleware

import (
	"fmt"
	"net/http"

	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/contexthelper"
)

// PanicHandler Recovers from any panic caused by a request (i.e. not middleware) and returns a 500 response.
func PanicHandler(next http.Handler) http.Handler {
	fn := func(rsp http.ResponseWriter, req *http.Request) {
		logger := contexthelper.LoggerFromContext(req.Context())

		defer func() {
			if err := recover(); err != nil {
				logger.Warn("Unhandled panic in request",
					zap.String("panic", fmt.Sprintf("%v", err)))
				http.Error(rsp, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(rsp, req)
	}

	return http.HandlerFunc(fn)
}
