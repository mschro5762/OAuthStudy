package oauth

import (
	"bytes"
	"context"
	"testing"

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
	VerifyClientSecretFunc      func(context.Context, uuid.UUID, string) (bool, error)
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

func (fake *clientRegistryServiceFake) VerifyClientSecret(ctx context.Context, clientID uuid.UUID, clientSecret string) (bool, error) {
	if fake.VerifyClientSecretFunc != nil {
		return fake.VerifyClientSecretFunc(ctx, clientID, clientSecret)
	}

	return false, nil
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

var testAuthzCode = "testcode"

type authzServiceFake struct {
	CreateAuthorizationCodeFunc   func(ctx context.Context, userID uuid.UUID, clientID uuid.UUID) ([]byte, error)
	ValidateAuthorizationCodeFunc func(ctx context.Context, clientID uuid.UUID, authzCode []byte) (bool, error)
}

func (fake *authzServiceFake) CreateAuthorizationCode(ctx context.Context, userID uuid.UUID, clientID uuid.UUID) ([]byte, error) {
	if fake.CreateAuthorizationCodeFunc != nil {
		return fake.CreateAuthorizationCodeFunc(ctx, userID, clientID)
	}

	return []byte(testAuthzCode), nil
}

func (fake *authzServiceFake) ValidateAuthorizationCode(ctx context.Context, clientID uuid.UUID, authzCode []byte) (bool, error) {
	if fake.ValidateAuthorizationCodeFunc != nil {
		return fake.ValidateAuthorizationCodeFunc(ctx, clientID, authzCode)
	}

	return false, nil
}

func TestNewWebEndpoints_HappyPath_ReturnsEndpoints(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	endpoints := NewWebEndpoints(ctx, &authzSvc, &userSvc, &clientSvc)

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

	endpoints := NewWebEndpoints(ctx, nil, &userSvc, &clientSvc)

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

	endpoints := NewWebEndpoints(ctx, &authzSvc, nil, &clientSvc)

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

	endpoints := NewWebEndpoints(ctx, &authzSvc, &userSvc, nil)

	if endpoints == nil {
		t.Fail()
	}
}
