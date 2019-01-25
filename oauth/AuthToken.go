package oauth

import (
	"time"

	"github.com/google/uuid"
)

// Authorization scopes
const (
	AuthroizationScopeAuthenticate = "auth"
)

// userAuthToken Information about a user's authorization.
// An authorization token is a self descriptive set of information that an
// IAuthTokenService can use to determine if the bearer is authorized.
// The information contained in this type should never leave the package unencrypted.
type userAuthToken struct {
	UserID    uuid.UUID
	ClientID  uuid.UUID
	IssuedAt  time.Time
	ExpiresAt time.Time
}
