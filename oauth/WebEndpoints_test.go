package oauth

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/clients"
	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/users"
)

var testClient = clients.Client{
	ID:             uuid.New(),
	Name:           "test client",
	Secret:         []byte("secret"),
	IsConfidential: true,
	RedirectURI:    "https://foo.com/redirect",
}

type clientRegistryServiceFake struct {
	RegisterClientFunc          func(context.Context, string, bool, string) (clients.Client, string, error)
	GetClientFunc               func(context.Context, uuid.UUID) (clients.Client, error)
	DeleteClientFunc            func(context.Context, uuid.UUID) error
	GenerateNewClientSecretFunc func(context.Context, uuid.UUID) (string, error)
	VerifyClientSecretFunc      func(context.Context, clients.Client, string) (bool, error)
}

func (fake *clientRegistryServiceFake) RegisterClient(ctx context.Context, clientName string, isConfidential bool, redirectURI string) (clients.Client, string, error) {
	if fake.RegisterClientFunc != nil {
		return fake.RegisterClientFunc(ctx, clientName, isConfidential, redirectURI)
	}

	return clients.Client{}, "", nil
}

func (fake *clientRegistryServiceFake) GetClient(ctx context.Context, clientID uuid.UUID) (clients.Client, error) {
	if fake.GetClientFunc != nil {
		return fake.GetClientFunc(ctx, clientID)
	}

	return testClient, nil
}

func (fake *clientRegistryServiceFake) DeleteClient(ctx context.Context, clientID uuid.UUID) error {
	if fake.DeleteClientFunc != nil {
		return fake.DeleteClientFunc(ctx, clientID)
	}

	return nil
}

func (fake *clientRegistryServiceFake) GenerateNewClientSecret(ctx context.Context, clientID uuid.UUID) (string, error) {
	if fake.GenerateNewClientSecretFunc != nil {
		return fake.GenerateNewClientSecretFunc(ctx, clientID)
	}

	return string(testClient.Secret) + "2", nil
}

func (fake *clientRegistryServiceFake) VerifyClientSecret(ctx context.Context, client clients.Client, clientSecret string) (bool, error) {
	if fake.VerifyClientSecretFunc != nil {
		return fake.VerifyClientSecretFunc(ctx, client, clientSecret)
	}

	return bytes.Equal(client.Secret, []byte(clientSecret)), nil
}

var testUser = users.User{
	ID:       uuid.New(),
	Name:     "test user",
	Password: []byte("password"),
}

type userServiceFake struct {
	RegisterUserFunc     func(ctx context.Context, name string, passwordClearText []byte) (users.User, error)
	GetUserFunc          func(ctx context.Context, name string) (users.User, error)
	ValidatePasswordFunc func(ctx context.Context, user users.User, clearText []byte) (bool, error)
}

func (fake *userServiceFake) RegisterUser(ctx context.Context, name string, passwordClearText []byte) (users.User, error) {
	if fake.RegisterUserFunc != nil {
		return fake.RegisterUserFunc(ctx, name, passwordClearText)
	}

	user := users.User{
		ID:       uuid.New(),
		Name:     name,
		Password: passwordClearText,
	}

	return user, nil
}

func (fake *userServiceFake) GetUser(ctx context.Context, name string) (users.User, error) {
	if fake.GetUserFunc != nil {
		return fake.GetUserFunc(ctx, name)
	}

	return testUser, nil
}

func (fake *userServiceFake) ValidatePassword(ctx context.Context, user users.User, clearText []byte) (bool, error) {
	if fake.ValidatePasswordFunc != nil {
		return fake.ValidatePasswordFunc(ctx, user, clearText)
	}

	return bytes.Equal(user.Password, clearText), nil
}

const testAuthzCode = "testcode"
const testAccessToken = "testtoken"
const testAccessTokenExpiry = time.Duration(100000000000)

type authzServiceFake struct {
	CreateAuthorizationCodeFunc   func(ctx context.Context, userID uuid.UUID, clientID uuid.UUID, redirectURISent bool) ([]byte, error)
	ValidateAuthorizationCodeFunc func(ctx context.Context, client clients.Client, authzCode []byte, redirectURI string) (bool, uuid.UUID, error)
	BuildAccessTokenFunc          func(ctx context.Context, userID uuid.UUID, clientID uuid.UUID) ([]byte, time.Duration, error)
}

func (fake *authzServiceFake) CreateAuthorizationCode(ctx context.Context, userID uuid.UUID, clientID uuid.UUID, redirectURISent bool) ([]byte, error) {
	if fake.CreateAuthorizationCodeFunc != nil {
		return fake.CreateAuthorizationCodeFunc(ctx, userID, clientID, redirectURISent)
	}

	return []byte(testAuthzCode), nil
}

func (fake *authzServiceFake) ValidateAuthorizationCode(ctx context.Context, client clients.Client, authzCode []byte, redirectURI string) (bool, uuid.UUID, error) {
	if fake.ValidateAuthorizationCodeFunc != nil {
		return fake.ValidateAuthorizationCodeFunc(ctx, client, authzCode, redirectURI)
	}

	return true, testUser.ID, nil
}

func (fake *authzServiceFake) BuildAccessToken(ctx context.Context, userID uuid.UUID, clientID uuid.UUID) ([]byte, time.Duration, error) {
	if fake.BuildAccessTokenFunc != nil {
		return fake.BuildAccessTokenFunc(ctx, userID, clientID)
	}

	return []byte(testAccessToken), testAccessTokenExpiry, nil
}

func TestNewWebEndpoints_HappyPath_ReturnsEndpoints(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	if endpoints == nil {
		t.Fail()
	}
}

func TestNewWebEndpoints_AuthSvcNil_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, nil, &userSvc, &clientSvc)

	if endpoints == nil {
		t.Fail()
	}
}

func TestNewWebEndpoints_UserSvcNil_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, nil, &clientSvc)

	if endpoints == nil {
		t.Fail()
	}
}

func TestNewWebEndpoints_ClientSvcNil_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, nil)

	if endpoints == nil {
		t.Fail()
	}
}
