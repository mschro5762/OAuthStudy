package middleware

import "net/http"

// CommonHandlers Returns a chain of ContextLoggerHandler->RequestLogHandler->PanicHandler->next
func CommonHandlers(next http.Handler) http.Handler {
	return DefaultContextLoggerHandler(RequestLogHandler(PanicHandler(next)))
}
