package oauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/clients"
	"github.com/mschro5762/OAuthStudy/contexthelper"
)

type EncrypterFake struct {
	EncryptFunc func(ctx context.Context, cleartext []byte) ([]byte, error)
	DecryptFunc func(ctx context.Context, ciphertext []byte) ([]byte, error)
}

func (fake *EncrypterFake) Encrypt(ctx context.Context, cleartext []byte) ([]byte, error) {
	if fake.EncryptFunc != nil {
		return fake.EncryptFunc(ctx, cleartext)
	}

	return cleartext, nil
}

// Decrypt Decrypts a cyphertext message
func (fake *EncrypterFake) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if fake.DecryptFunc != nil {
		return fake.DecryptFunc(ctx, ciphertext)
	}

	return ciphertext, nil
}

func TestAuthorizationCodeBinaryEncoding(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	expiryTime, _ := time.ParseDuration("5m")

	expectedAuthCode := authorizationCode{
		ClientID:  uuid.New(),
		UserID:    uuid.New(),
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(expiryTime),
	}

	data, _ := encodeAuthCode(ctx, expectedAuthCode)
	actualAuthCode, _ := decodeAuthCode(ctx, data)

	if actualAuthCode != expectedAuthCode {
		t.Fail()
	}
}

func TestAuthTokenService_CreateAuthorizationCode_NilContext_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	authSvc := AuthTokenService{}

	authSvc.CreateAuthorizationCode(nil, uuid.New(), uuid.New(), false)
}

func TestAuthTokenService_CreateAuthorizationCode_HappyPath_ReturnsResultFromEncrypter(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	clientID := uuid.New()
	userID := uuid.New()

	expectedCode := "expectation"

	encrypterFake := EncrypterFake{
		EncryptFunc: func(ctx context.Context, cleartext []byte) ([]byte, error) {
			return []byte(expectedCode), nil
		},
	}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	actualCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, clientID, false)

	if string(actualCode) != expectedCode {
		t.Fail()
	}
}

func TestAuthTokenService_CreateAuthorizationCode_HappyPath_ProducesWellformedCode(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	clientID := uuid.New()
	userID := uuid.New()
	redirectSent := false

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	iatFudge, _ := time.ParseDuration("5ms")
	now := time.Now().UTC()

	actualCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, clientID, redirectSent)

	code, err := decodeAuthCode(ctx, actualCode)

	if err != nil ||
		code.UserID != userID ||
		code.ClientID != clientID ||
		code.IssuedAt.Before(now) || code.IssuedAt.After(now.Add(iatFudge)) ||
		!code.ExpiresAt.Equal(code.IssuedAt.Add(codeTTL)) ||
		code.RedirectURISent != redirectSent {
		t.Fail()
	}
}

func TestAuthTokenService_CreateAuthorizationCode_RedirectSentTrue_SetsRedirectSent(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	clientID := uuid.New()
	userID := uuid.New()
	redirectSent := true

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	actualCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, clientID, redirectSent)

	code, err := decodeAuthCode(ctx, actualCode)

	if err != nil ||
		code.RedirectURISent != redirectSent {
		t.Fail()
	}
}

func TestAuthTokenService_CreateAuthorizationCode_HappyPath_TimeStampsAreUTC(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	clientID := uuid.New()
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	actualCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, clientID, false)

	code, err := decodeAuthCode(ctx, actualCode)

	if err != nil ||
		code.IssuedAt.Location() != time.UTC ||
		code.ExpiresAt.Location() != time.UTC {
		t.Fail()
	}
}

func TestAuthTokenService_CreateAuthorizationCode_EncryptionError_ReturnsError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	clientID := uuid.New()
	userID := uuid.New()

	encrypterFake := EncrypterFake{
		EncryptFunc: func(ctx context.Context, cleartext []byte) ([]byte, error) {
			return nil, errors.New("test error")
		},
	}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	_, err := authSvc.CreateAuthorizationCode(ctx, userID, clientID, false)

	if err == nil {
		t.Fail()
	}
}

func TestAuthTokenService_CreateAuthorizationCode_EncryptionError_ReturnsNilCode(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	clientID := uuid.New()
	userID := uuid.New()

	encrypterFake := EncrypterFake{
		EncryptFunc: func(ctx context.Context, cleartext []byte) ([]byte, error) {
			return nil, errors.New("test error")
		},
	}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	actualCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, clientID, false)

	if actualCode != nil {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_HappyPath_ReturnsTrue(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID: uuid.New(),
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, false)

	isValid, _ := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, "")

	if !isValid {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_HappyPath_ReturnsNilError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID: uuid.New(),
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, false)

	_, err := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, "")

	if err != nil {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_CodeExpired_ReturnsFalse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("1ms")
	client := clients.Client{
		ID: uuid.New(),
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, false)

	sleepDuration, _ := time.ParseDuration("5ms")
	time.Sleep(sleepDuration)

	isValid, _ := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, "")

	if isValid {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_CodeExpired_ReturnsNilError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("1ms")
	client := clients.Client{
		ID: uuid.New(),
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, false)

	sleepDuration, _ := time.ParseDuration("5ms")
	time.Sleep(sleepDuration)

	_, err := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, "")

	if err != nil {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_ClientMismatch_ReturnsFalse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID: uuid.New(),
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, false)

	badClient := clients.Client{
		ID: uuid.New(),
	}

	isValid, _ := authSvc.ValidateAuthorizationCode(ctx, badClient, authzCode, "")

	if isValid {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_ClientMismatch_ReturnsNilError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID: uuid.New(),
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, false)

	badClient := clients.Client{
		ID: uuid.New(),
	}

	_, err := authSvc.ValidateAuthorizationCode(ctx, badClient, authzCode, "")

	if err != nil {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_DecryptionError_ReturnsFalse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID: uuid.New(),
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{
		DecryptFunc: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return nil, errors.New("test error")
		},
	}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, false)

	isValid, _ := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, "")

	if isValid {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_DecryptionError_ReturnsError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID: uuid.New(),
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{
		DecryptFunc: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return nil, errors.New("test error")
		},
	}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, false)

	_, err := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, "")

	if err == nil {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_DeserializationError_ReturnsFalse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID: uuid.New(),
	}

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	isValid, _ := authSvc.ValidateAuthorizationCode(ctx, client, []byte("BadCode"), "")

	if isValid {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_DeserializationError_ReturnsError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID: uuid.New(),
	}

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	_, err := authSvc.ValidateAuthorizationCode(ctx, client, []byte("BadCode"), "")

	if err == nil {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_RedirectURISent_HappyPath_ReturnsTrue(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID:          uuid.New(),
		RedirectURI: "urn:testURI",
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, true)

	isValid, _ := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, client.RedirectURI)

	if !isValid {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_RedirectURISent_HappyPath_ReturnsNilError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID:          uuid.New(),
		RedirectURI: "urn:testURI",
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, true)

	_, err := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, client.RedirectURI)

	if err != nil {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_RedirectURINotSent_RedirectURIParamSent_ReturnsTrue(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID: uuid.New(),
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, false)

	isValid, _ := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, client.RedirectURI)

	if !isValid {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_RedirectURINotSent_RedirectURIParamSent_ReturnsNilError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID: uuid.New(),
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, false)

	_, err := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, "urn:testuri")

	if err != nil {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_RedirectURISent_URIMismatch_ReturnsFalse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID:          uuid.New(),
		RedirectURI: "urn:testURI",
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, true)

	isValid, _ := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, "bad URI")

	if isValid {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_RedirectURISent_URIMismatch_ReturnsNilError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID:          uuid.New(),
		RedirectURI: "urn:testURI",
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, true)

	_, err := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, "bad URI")

	if err != nil {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_RedirectURISent_EmptyURIParam_ReturnsFalse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID:          uuid.New(),
		RedirectURI: "urn:testURI",
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, true)

	isValid, _ := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, "")

	if isValid {
		t.Fail()
	}
}

func TestAuthtokenService_ValidateAuthorizationCode_RedirectURISent_EmptyURIParam_ReturnsNilError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	codeTTL, _ := time.ParseDuration("5m")
	client := clients.Client{
		ID:          uuid.New(),
		RedirectURI: "urn:testURI",
	}
	userID := uuid.New()

	encrypterFake := EncrypterFake{}

	authSvc := AuthTokenService{
		config: AuthTokenServiceConfig{
			authzCodeTTL: codeTTL,
		},
		encrypter: &encrypterFake,
	}

	authzCode, _ := authSvc.CreateAuthorizationCode(ctx, userID, client.ID, true)

	_, err := authSvc.ValidateAuthorizationCode(ctx, client, authzCode, "")

	if err != nil {
		t.Fail()
	}
}
