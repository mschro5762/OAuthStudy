package oauth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/crypto"
)

// Implements the workflows in:
// https://tools.ietf.org/html/rfc6749

// The only Authorization Grant (RFC 6749 1.3) supported is Authorization Code (RFC 6749 1.3.1).
// Client Credentials (RFC 6749 1.3.4) may be considered at a future time.

// Constants for Authorization and Token scopes
const (
	ScopeFullAuthorization = "authz"
)

// AuthTokenServiceConfig Configuration for the Authorization Service
type AuthTokenServiceConfig struct {
	AuthzCodeCrypto crypto.EncrypterConfig `json:"authzCodeCrypto"`
	// AuthzCodeTTL A time.Duration string
	AuthzCodeTTLString string `json:"authzCodeTtl"`
	authzCodeTTL       time.Duration
}

// IAuthTokenService Authorization token service interface
type IAuthTokenService interface {
	CreateAuthorizationCode(ctx context.Context, userID uuid.UUID, clientID uuid.UUID) ([]byte, error)
	ValidateAuthorizationCode(ctx context.Context, clientID uuid.UUID, authzCode []byte) (bool, error)
}

// AuthTokenService Authorization token service
type AuthTokenService struct {
	config    AuthTokenServiceConfig
	encrypter crypto.IEncrypter
}

// NewAuthTokenService Constructs a new AuthTokenService instance
func NewAuthTokenService(ctx context.Context, config AuthTokenServiceConfig, encrypter crypto.IEncrypter) *AuthTokenService {
	logger := contexthelper.LoggerFromContext(ctx)

	if config == (AuthTokenServiceConfig{}) {
		panic("Empty config passed!")
	}
	if encrypter == nil {
		panic("Nil Argument: encrypter")
	}

	authCodeTTL, err := time.ParseDuration(config.AuthzCodeTTLString)
	if err != nil {
		logger.Panic("Unable to parse Authorization Code TTL config",
			zap.Error(err))
	}
	config.authzCodeTTL = authCodeTTL

	newSvc := AuthTokenService{
		config:    config,
		encrypter: encrypter,
	}

	return &newSvc
}
