package oauth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/clients"
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
	IssuerURI            string        `json:"issuerUri"`
	AuthzCodeCrypto      crypto.Config `json:"authzCodeCrypto"`
	AuthzCodeSigning     crypto.Config `json:"authzCodeSigning"`
	AuthzCodeTTLString   string        `json:"authzCodeTtl"` // A time.Duration string
	AccessTokenCrypto    crypto.Config `json:"accessTokenCrypto"`
	AccessTokenSigning   crypto.Config `json:"accessTokenSigning"`
	AccessTokenTTLString string        `json:"accessTokenTtl"` // A time.Duration string
	authzCodeTTL         time.Duration
	accessTokenTTL       time.Duration
}

// IAuthTokenService Authorization token service interface
type IAuthTokenService interface {
	CreateAuthorizationCode(ctx context.Context, userID uuid.UUID, clientID uuid.UUID, redirectURISent bool) ([]byte, error)
	ValidateAuthorizationCode(ctx context.Context, client clients.Client, authzCode []byte, redirectURI string) (bool, error)
}

// AuthTokenService Authorization token service
type AuthTokenService struct {
	config    AuthTokenServiceConfig
	encrypter crypto.IEncrypter
}

// NewAuthTokenService Constructs a new AuthTokenService instance
func NewAuthTokenService(ctx context.Context, config AuthTokenServiceConfig, encrypter crypto.IEncrypter) *AuthTokenService {
	if config == (AuthTokenServiceConfig{}) {
		panic("Empty config passed!")
	}
	if encrypter == nil {
		panic("Nil Argument: encrypter")
	}

	config = buildConfig(ctx, config)

	newSvc := AuthTokenService{
		config:    config,
		encrypter: encrypter,
	}

	return &newSvc
}

func buildConfig(ctx context.Context, proto AuthTokenServiceConfig) AuthTokenServiceConfig {
	logger := contexthelper.LoggerFromContext(ctx)

	authCodeTTL, err := time.ParseDuration(proto.AuthzCodeTTLString)
	if err != nil {
		logger.Panic("Unable to parse Authorization Code TTL config",
			zap.Error(err))
	}
	proto.authzCodeTTL = authCodeTTL

	accessTokenTTL, err := time.ParseDuration(proto.AccessTokenTTLString)
	if err != nil {
		logger.Panic("Unable to parse Access Token TTL config",
			zap.Error(err))
	}
	proto.accessTokenTTL = accessTokenTTL

	return proto

}
