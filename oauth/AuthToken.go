package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/crypto"
)

// Authorization scopes
const (
	AuthroizationScopeAuthenticate = "auth"
)

// userAuthToken Information about a user's authorization.
// An authorization token is a self descriptive set of information that an
// IAuthTokenService can use to determine if the bearer is authorized.
// The information contained in this type should never leave the package unencrypted.
type userAccessToken struct {
	Issuer    string
	UserID    uuid.UUID
	Audience  []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Only used for custom JSON serialization of userAccessToken,
// which we need for unix format time values
type userAccessTokenJSON struct {
	Issuer    string    `json:"iss"`
	UserID    uuid.UUID `json:"sub"`
	Audience  []string  `json:"aud"`
	IssuedAt  int64     `json:"iat"`
	ExpiresAt int64     `json:"exp"`
}

func (token userAccessToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(&userAccessTokenJSON{
		Issuer:    token.Issuer,
		UserID:    token.UserID,
		Audience:  token.Audience,
		IssuedAt:  token.IssuedAt.Unix(),
		ExpiresAt: token.ExpiresAt.Unix(),
	})
}

func (token *userAccessToken) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	if string(text) == "" {
		return nil
	}

	var jtoken userAccessTokenJSON
	err := json.Unmarshal(data, &jtoken)
	if err != nil {
		return err
	}

	iat := time.Unix(jtoken.IssuedAt, 0).UTC()
	exp := time.Unix(jtoken.ExpiresAt, 0).UTC()

	token.Issuer = jtoken.Issuer
	token.UserID = jtoken.UserID
	token.Audience = jtoken.Audience
	token.IssuedAt = iat
	token.ExpiresAt = exp

	return nil
}

// BuildAccessToken Builds a new Access token
func (authSvc *AuthTokenService) BuildAccessToken(ctx context.Context, userID uuid.UUID, clientID uuid.UUID) ([]byte, time.Time, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	iat := time.Now().UTC()
	exp := iat.Add(authSvc.config.accessTokenTTL)

	token := userAccessToken{
		Issuer: authSvc.config.IssuerURI,
		UserID: userID,
		Audience: []string{
			clientID.String(),
			authSvc.config.IssuerURI + "/userinfo",
		},
		IssuedAt:  iat,
		ExpiresAt: exp,
	}

	jws, err := authSvc.buildAccessTokenJws(ctx, token)
	if err != nil {
		logger.Error("Unable to build access token JWS",
			zap.Error(err))
		return nil, time.Time{}, err
	}

	return jws, exp, nil
}

func (authSvc *AuthTokenService) buildAccessTokenJws(ctx context.Context, token userAccessToken) ([]byte, error) {
	header := buildJose(ctx, authSvc.accessTokenSigner, false)

	jose, err := json.Marshal(header)
	if err != nil {
		return make([]byte, 0), err
	}

	jwt, err := json.Marshal(token)
	if err != nil {
		return make([]byte, 0), err
	}

	encodedJose := base64.URLEncoding.EncodeToString(jose)
	encodedJwt := base64.URLEncoding.EncodeToString(jwt)

	signingPayload := make([]byte, 0, len(encodedJose)+len(encodedJwt)+1)
	signingPayload = append(signingPayload, encodedJose...)
	signingPayload = append(signingPayload, '.')
	signingPayload = append(signingPayload, encodedJwt...)

	encodedPayload := base64.URLEncoding.EncodeToString(signingPayload)

	signature, err := authSvc.accessTokenSigner.BuildSignature(ctx, []byte(encodedPayload))
	if err != nil {
		return make([]byte, 0), err
	}

	encodedSig := base64.URLEncoding.EncodeToString(signature)

	signingPayload = append(signingPayload, '.')
	signingPayload = append(signingPayload, encodedSig...)

	return []byte(signingPayload), nil
}

type jsonObjectSigningAndEncryptionHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

func buildJose(ctx context.Context, signer crypto.ISigner, encrypted bool) jsonObjectSigningAndEncryptionHeader {
	logger := contexthelper.LoggerFromContext(ctx)

	jose := jsonObjectSigningAndEncryptionHeader{}

	if encrypted {
		jose.Type = "JWE"
	} else {
		jose.Type = "JWS"
	}

	switch signer.Name() {
	case crypto.HMACSHA256SignerName:
		jose.Algorithm = "HS256"
	default:
		logger.Panic("Unrecognized JOSE Algorithm",
			zap.String("algorithm", signer.Name()))
	}

	return jose
}
