package contexthelper

import (
	"context"

	"github.com/google/uuid"

	"go.uber.org/zap"
)

// ILogger Interface that zap.Logger satisfies
type ILogger interface {
	With(fields ...zap.Field) *zap.Logger
	Debug(msg string, fields ...zap.Field)
	Info(msg string, fields ...zap.Field)
	Warn(msg string, fields ...zap.Field)
	Error(msg string, fields ...zap.Field)
	DPanic(msg string, fields ...zap.Field)
	Panic(msg string, fields ...zap.Field)
	Fatal(msg string, fields ...zap.Field)
	Sync() error
}

// Context keys
type contextKey int

const (
	contextKeyLogger contextKey = iota
	contextKeyRequestID
)

// NewContextWithLogger Creates a new context with the given logger
func NewContextWithLogger(logger ILogger) context.Context {
	newCtx := context.WithValue(context.Background(), contextKeyLogger, logger)
	return newCtx
}

// AddLoggertoContext Adds a logger to the given context
func AddLoggertoContext(ctx context.Context, logger ILogger) context.Context {
	newCtx := context.WithValue(ctx, contextKeyLogger, logger)
	return newCtx
}

// LoggerFromContext Gets the logger from the context
func LoggerFromContext(ctx context.Context) ILogger {
	ctxLogger, ok := ctx.Value(contextKeyLogger).(ILogger)

	if !ok {
		logger, _ := zap.NewProduction()
		defer logger.Sync()
		logger.Panic("Logger not added to context")
	}

	return ctxLogger
}

// AddRequestIDToContext Adds a request ID to the given context
func AddRequestIDToContext(ctx context.Context, requestID uuid.UUID) context.Context {
	newCtx := context.WithValue(ctx, contextKeyRequestID, requestID)
	return newCtx
}

// RequestIDFromContext Gets the request ID from a given context
func RequestIDFromContext(ctx context.Context) uuid.UUID {
	reqID, ok := ctx.Value(contextKeyRequestID).(uuid.UUID)

	if !ok {
		logger := LoggerFromContext(ctx)
		logger.Panic("ContextID not added to context")
	}

	return reqID
}
