package clients

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/logging"
)

const clientSecretLen = 64

type ClientRepositoryFake struct {
	CreateFunc   func(context.Context, Client) error
	RetrieveFunc func(context.Context, uuid.UUID) (Client, error)
	UpdateFunc   func(context.Context, Client) error
	DeleteFunc   func(context.Context, uuid.UUID) error
}

func (repo *ClientRepositoryFake) Create(ctx context.Context, client Client) error {
	if repo.CreateFunc != nil {
		return repo.CreateFunc(ctx, client)
	}

	return nil
}

func (repo *ClientRepositoryFake) Retrieve(ctx context.Context, id uuid.UUID) (Client, error) {
	if repo.RetrieveFunc != nil {
		return repo.RetrieveFunc(ctx, id)
	}

	return Client{}, nil
}

func (repo *ClientRepositoryFake) Update(ctx context.Context, client Client) error {
	if repo.UpdateFunc != nil {
		return repo.UpdateFunc(ctx, client)
	}

	return nil
}

func (repo *ClientRepositoryFake) Delete(ctx context.Context, id uuid.UUID) error {
	if repo.DeleteFunc != nil {
		return repo.DeleteFunc(ctx, id)
	}

	return nil
}

type ClientRepositoryFakeError struct {
}

func (repo *ClientRepositoryFakeError) Create(ctx context.Context, client Client) error {
	return errors.New("Fake create error")
}

func (repo *ClientRepositoryFakeError) Retrieve(ctx context.Context, id uuid.UUID) (Client, error) {
	return Client{}, errors.New("Fake retrieve error")
}

func (repo *ClientRepositoryFakeError) Update(ctx context.Context, client Client) error {
	return errors.New("Fake update error")
}

func (repo *ClientRepositoryFakeError) Delete(ctx context.Context, id uuid.UUID) error {
	return errors.New("Fake delete error")
}

func TestClientRegistry_Ctor_HappyPath_ReturnsNewRegistry(t *testing.T) {
	repo := ClientRepositoryFake{}

	newRegistry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	if newRegistry == nil {
		t.Fail()
	}
}

func TestClientRegistry_Ctor_HappyPath_ErrNil(t *testing.T) {
	repo := ClientRepositoryFake{}

	_, err := NewRegistry(context.Background(), &repo, clientSecretLen)

	if err != nil {
		t.Fail()
	}
}

func TestClientRegistry_Ctor_RepoNil_ReturnsNilRegistry(t *testing.T) {
	var repo IClientRepository

	newRegistry, _ := NewRegistry(context.Background(), repo, clientSecretLen)

	if newRegistry != nil {
		t.Fail()
	}
}

func TestClientRegistry_Ctor_RepoNil_ErrNotNil(t *testing.T) {
	var repo IClientRepository

	_, err := NewRegistry(context.Background(), repo, clientSecretLen)

	if err == nil && err.Error() == "nil argument: repo" {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_HappyPath_ReturnsExpectedId(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "Foo Client"
	isConfidential := true
	redirectURI := "https://example.com"

	newClient, _, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	uuidZero := uuid.UUID{}
	if newClient.ID == uuidZero {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_HappyPath_ReturnsExpectedName(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "Foo Client"
	isConfidential := true
	redirectURI := "https://example.com"

	newClient, _, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if newClient.Name != clientName {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_HappyPath_ReturnsExpectedConfidentiality(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "Foo Client"
	isConfidential := true
	redirectURI := "https://example.com"

	newClient, _, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if newClient.IsConfidential != isConfidential {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_HappyPath_SecretCleartextCorrectLength(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "Foo Client"
	isConfidential := true
	redirectURI := "https://example.com"

	_, cleartext, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if len(cleartext) != registry.clientSecretLength {
		t.Fail()
	}
}

func TestClientRegistry_Registerclient_ContextNil_Panics(t *testing.T) {
	repo := ClientRepositoryFakeError{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	defer func() {
		if err := recover(); err == nil || err.(string) != logging.ErrMsgNilArgumentContext {
			t.Fail()
		}
	}()

	_, _, _ = registry.RegisterClient(nil, "", true, "https://example.com")
}

func TestClientRegistry_RegisterClient_RegisterTwoClients_ReturnsDifferentIds(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName1 := "Foo Client"
	clientName2 := "Bar Client"
	isConfidential := true
	redirectURI := "https://example.com"

	newClient1, _, _ := registry.RegisterClient(ctx, clientName1, isConfidential, redirectURI)
	newClient2, _, _ := registry.RegisterClient(ctx, clientName2, isConfidential, redirectURI)

	if newClient1.ID == newClient2.ID {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_RegisterTwoClients_ReturnsDifferentSecrets(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName1 := "Foo Client"
	clientName2 := "Bar Client"
	isConfidential := true
	redirectURI := "https://example.com"

	newClient1, _, _ := registry.RegisterClient(ctx, clientName1, isConfidential, redirectURI)
	newClient2, _, _ := registry.RegisterClient(ctx, clientName2, isConfidential, redirectURI)

	if bytes.Equal(newClient1.Secret, newClient2.Secret) {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_RegisterClientTwice_ReturnsDifferentSecrets(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "Foo Client"
	isConfidential := true
	redirectURI := "https://example.com"

	newClient1, _, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)
	newClient2, _, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if bytes.Equal(newClient1.Secret, newClient2.Secret) {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_HappyPath_ReturnsNilError(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "Foo Client"
	isConfidential := true
	redirectURI := "https://example.com"

	_, _, err := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if err != nil {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_DifferentSecretLengths_CreateCorrectSecretLengths(t *testing.T) {
	expectedLengths := []int{
		2,
		5,
		10,
		64,
	}

	repo := ClientRepositoryFake{}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "Foo Client"
	isConfidential := true
	redirectURI := "https://example.com"

	for _, i := range expectedLengths {
		registry, _ := NewRegistry(context.Background(), &repo, i)

		_, secretCleartext, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

		if len(secretCleartext) != i {
			t.Errorf("%d != %d", i, len(secretCleartext))
		}
	}
}

func TestClientRegistry_RegisterClient_NilContext_Panics(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	var ctx context.Context
	clientName := "Foo Client"
	isConfidential := true
	redirectURI := "https://example.com"

	defer func() {
		if r := recover(); r == nil {
			t.Error("paniced, but did not recover")
		}
	}()

	_, _, _ = registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)
	t.Error("did not panic")
}

func TestClientRegistry_RegisterClient_EmptyName_ReturnsZeroClient(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := ""
	isConfidential := true
	redirectURI := "https://example.com"

	newClient, _, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	zeroClient := Client{}
	if newClient.ID != zeroClient.ID {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_EmptyName_ReturnsError(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := ""
	isConfidential := true
	redirectURI := "https://example.com"

	_, _, err := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if err != nil && err.Error() != "Client name empty" {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_EmptyName_ReturnsEmptySecretCleartext(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := ""
	isConfidential := true
	redirectURI := "https://example.com"

	_, secretCleartext, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if secretCleartext != "" {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_WhitespaceName_ReturnsZeroClient(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "   "
	isConfidential := true
	redirectURI := "https://example.com"

	newClient, _, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	zeroClient := Client{}
	if !ClientsAreEqual(newClient, zeroClient) {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_WhitespaceName_ReturnsError(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "   "
	isConfidential := true
	redirectURI := "https://example.com"

	_, _, err := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if err != nil && err.Error() != "Client name empty" {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_WhitespaceName_ReturnsEmptySecretCleartext(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "   "
	isConfidential := true
	redirectURI := "https://example.com"

	_, secretCleartext, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if secretCleartext != "" {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_WhitespaceRedirectURI_ReturnsZeroClient(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "test"
	isConfidential := true
	redirectURI := " "

	newClient, _, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	zeroClient := Client{}
	if !ClientsAreEqual(newClient, zeroClient) {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_WhitespaceRedirectURI_ReturnsError(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "test"
	isConfidential := true
	redirectURI := " "

	_, _, err := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if err != nil && err.Error() != "Invalid redirect URI" {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_WhitespaceRedirectURI_ReturnsEmptySecretCleartext(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "test"
	isConfidential := true
	redirectURI := " "

	_, secretCleartext, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if secretCleartext != "" {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_RedirectURINotAURI_ReturnsZeroClient(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "test"
	isConfidential := true
	redirectURI := "notauri"

	newClient, _, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	zeroClient := Client{}
	if !ClientsAreEqual(newClient, zeroClient) {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_RedirectURINotAURI_ReturnsError(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "test"
	isConfidential := true
	redirectURI := "notauri"

	_, _, err := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if err != nil && err.Error() != "Invalid redirect URI" {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_RedirectURINotAURI_ReturnsEmptySecretCleartext(t *testing.T) {
	repo := ClientRepositoryFake{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "test"
	isConfidential := true
	redirectURI := "notauri"

	_, secretCleartext, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if secretCleartext != "" {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_RepositoryError_ReturnsZeroClient(t *testing.T) {
	repo := ClientRepositoryFake{
		CreateFunc: func(ctx context.Context, client Client) error {
			return errors.New("test error")
		},
	}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "test"
	isConfidential := true
	redirectURI := "https://example.com"

	newClient, _, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	zeroClient := Client{}
	if !ClientsAreEqual(newClient, zeroClient) {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_RepositoryError_ReturnsError(t *testing.T) {
	repo := ClientRepositoryFake{
		CreateFunc: func(ctx context.Context, client Client) error {
			return errors.New("test error")
		},
	}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "test"
	isConfidential := true
	redirectURI := "https://example.com"

	_, _, err := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if err == nil || err.Error() != "test error" {
		t.Fail()
	}
}

func TestClientRegistry_RegisterClient_RepositoryError_ReturnsEmptySecretCleartext(t *testing.T) {
	repo := ClientRepositoryFake{
		CreateFunc: func(ctx context.Context, client Client) error {
			return errors.New("test error")
		},
	}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	clientName := "test"
	isConfidential := true
	redirectURI := "https://example.com"

	_, secretCleartext, _ := registry.RegisterClient(ctx, clientName, isConfidential, redirectURI)

	if secretCleartext != "" {
		t.Fail()
	}
}

func TestClientRegistry_GetClient_HappyPath_ReturnsClient(t *testing.T) {
	expectedClient := Client{
		ID:             uuid.New(),
		Name:           "foo",
		IsConfidential: true,
		Secret:         []byte("bar"),
		RedirectURI:    "https://example.com",
	}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(context.Context, uuid.UUID) (Client, error) {
			return expectedClient, nil
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(ctx, &repo, clientSecretLen)

	actualClient, _ := registry.GetClient(ctx, expectedClient.ID)

	if actualClient.ID != expectedClient.ID {
		t.Fail()
	}
}

func TestClientRegistry_GetClient_HappyPath_ReturnsNilError(t *testing.T) {
	expectedClient := Client{
		ID:             uuid.New(),
		Name:           "foo",
		IsConfidential: true,
		Secret:         []byte("bar"),
		RedirectURI:    "https://example.com",
	}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(context.Context, uuid.UUID) (Client, error) {
			return expectedClient, nil
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(ctx, &repo, clientSecretLen)

	_, err := registry.GetClient(ctx, expectedClient.ID)

	if err != nil {
		t.Fail()
	}
}

func TestClientRegistry_GetClient_RepositoryError_ReturnsZeroClient(t *testing.T) {
	expectedClient := Client{}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(context.Context, uuid.UUID) (Client, error) {
			return Client{}, errors.New("test rror")
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(ctx, &repo, clientSecretLen)

	actualClient, _ := registry.GetClient(ctx, expectedClient.ID)

	if actualClient.ID != expectedClient.ID {
		t.Fail()
	}
}

func TestClientRegistry_GetClient_RepositoryError_ReturnsError(t *testing.T) {
	expectedClient := Client{}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(context.Context, uuid.UUID) (Client, error) {
			return Client{}, errors.New("test rror")
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(ctx, &repo, clientSecretLen)

	_, err := registry.GetClient(ctx, expectedClient.ID)

	if err == nil {
		t.Fail()
	}
}

func TestClientRegistry_Deleteclient_ContextNil_Panics(t *testing.T) {
	defer func() {
		if err := recover(); err == nil {
			t.Fail()
		}
	}()

	repo := ClientRepositoryFakeError{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	_ = registry.DeleteClient(nil, uuid.New())
}

func TestClientRegistry_DeleteClient_CallsRepoWithId(t *testing.T) {
	var actualID uuid.UUID
	repo := ClientRepositoryFake{
		DeleteFunc: func(ctx context.Context, clientID uuid.UUID) error {
			actualID = clientID
			return nil
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	expectedClientID := uuid.New()

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	_ = registry.DeleteClient(ctx, expectedClientID)

	if actualID != expectedClientID {
		t.Fail()
	}
}

func TestClientRegistry_GenerateNewClientSecret_ContextNil_Panics(t *testing.T) {
	repo := ClientRepositoryFakeError{}

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	defer func() {
		if err := recover(); err == nil || err.(string) != logging.ErrMsgNilArgumentContext {
			t.Fail()
		}
	}()

	_, _ = registry.GenerateNewClientSecret(nil, uuid.New())
}

func TestClientRegistry_GenerateNewClientSecret_CallsRepoGetWithId(t *testing.T) {
	secretPlainText := "abcd"
	hashedSecret, _ := hashSecret(secretPlainText)

	originalClient := Client{
		ID:             uuid.New(),
		Secret:         hashedSecret,
		Name:           "test client",
		IsConfidential: true,
	}

	var actualID uuid.UUID
	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			actualID = clientID
			// Returning by value, so the original shouldn't be mutated
			return originalClient, nil
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	expectedClientID := uuid.New()

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	_, _ = registry.GenerateNewClientSecret(ctx, expectedClientID)

	if actualID != expectedClientID {
		t.Fail()
	}
}

func TestClientRegistry_GenerateNewClientSecret_UpdatesClientWithOnlySecretChanged(t *testing.T) {
	secretPlainText := "abcd"
	hashedSecret, _ := hashSecret(secretPlainText)

	originalClient := Client{
		ID:             uuid.New(),
		Secret:         hashedSecret,
		Name:           "test client",
		IsConfidential: true,
	}

	var actualClient Client
	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			// Returning by value, so the original shouldn't be mutated
			return originalClient, nil
		},
		UpdateFunc: func(ctx context.Context, client Client) error {
			actualClient = client
			return nil
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	_, _ = registry.GenerateNewClientSecret(ctx, originalClient.ID)

	if !ClientsAreEqual(originalClient, actualClient) {
		t.Fail()
	}
}

func TestClientRegistry_GenerateNewClientSecret_RepoRetrieveFails_ReturnsError(t *testing.T) {
	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			// Returning by value, so the original shouldn't be mutated
			return Client{}, errors.New("test error")
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	expectedClientID := uuid.New()

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	_, err := registry.GenerateNewClientSecret(ctx, expectedClientID)

	if err == nil || err.Error() != "Unable to find client" {
		t.Fail()
	}
}

func TestClientRegistry_GenerateNewClientSecret_RepoRetrieveFails_DoesNotReturnNewSecret(t *testing.T) {
	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			// Returning by value, so the original shouldn't be mutated
			return Client{}, errors.New("test error")
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	expectedClientID := uuid.New()

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	newSecret, _ := registry.GenerateNewClientSecret(ctx, expectedClientID)

	if newSecret != "" {
		t.Fail()
	}
}

func TestClientRegistry_GenerateNewClientSecret_RepoUpdateFails_ReturnsError(t *testing.T) {
	secretPlainText := "abcd"
	hashedSecret, _ := hashSecret(secretPlainText)

	originalClient := Client{
		ID:             uuid.New(),
		Secret:         hashedSecret,
		Name:           "test client",
		IsConfidential: true,
	}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			// Returning by value, so the original shouldn't be mutated
			return originalClient, nil
		},
		UpdateFunc: func(ctx context.Context, client Client) error {
			return errors.New("test error")
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	_, err := registry.GenerateNewClientSecret(ctx, originalClient.ID)

	if err == nil || err.Error() != "Unable to save new client secret" {
		t.Fail()
	}
}

func TestClientRegistry_GenerateNewClientSecret_RepoUpdateFails_DoesNotReturnNewSecret(t *testing.T) {
	secretPlainText := "abcd"
	hashedSecret, _ := hashSecret(secretPlainText)

	originalClient := Client{
		ID:             uuid.New(),
		Secret:         hashedSecret,
		Name:           "test client",
		IsConfidential: true,
	}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			// Returning by value, so the original shouldn't be mutated
			return originalClient, nil
		},
		UpdateFunc: func(ctx context.Context, client Client) error {
			return errors.New("test error")
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	newSecret, _ := registry.GenerateNewClientSecret(ctx, originalClient.ID)

	if newSecret != "" {
		t.Fail()
	}
}

func TestClientRegistry_GenerateNewClientSecret_NewSecretIsCorrectLength(t *testing.T) {
	secretPlainText := "abcd"
	hashedSecret, _ := hashSecret(secretPlainText)

	originalClient := Client{
		ID:             uuid.New(),
		Secret:         hashedSecret,
		Name:           "test client",
		IsConfidential: true,
	}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			// Returning by value, so the original shouldn't be mutated
			return originalClient, nil
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	newSecretPlainText, _ := registry.GenerateNewClientSecret(ctx, originalClient.ID)

	if len(newSecretPlainText) != clientSecretLen {
		t.Fail()
	}
}

func TestClientRegistry_VerifyClientSecret_SecretMatches_ReturnsTrue(t *testing.T) {
	secretPlainText := "abcd"
	hashedSecret, _ := hashSecret(secretPlainText)

	client := Client{
		ID:             uuid.New(),
		Secret:         hashedSecret,
		Name:           "test client",
		IsConfidential: true,
	}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			// Returning by value, so the original shouldn't be mutated
			return client, nil
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	isValid, _ := registry.VerifyClientSecret(ctx, client.ID, secretPlainText)

	if !isValid {
		t.Fail()
	}
}

func TestClientRegistry_VerifyClientSecret_SecretMatches_ReturnsNilError(t *testing.T) {
	secretPlainText := "abcd"
	hashedSecret, _ := hashSecret(secretPlainText)

	client := Client{
		ID:             uuid.New(),
		Secret:         hashedSecret,
		Name:           "test client",
		IsConfidential: true,
	}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			// Returning by value, so the original shouldn't be mutated
			return client, nil
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	_, err := registry.VerifyClientSecret(ctx, client.ID, secretPlainText)

	if err != nil {
		t.Fail()
	}
}

func TestClientRegistry_VerifyClientSecret_SecretDoesNotMatch_ReturnsFalse(t *testing.T) {
	secretPlainText := "abcd"
	hashedSecret, _ := hashSecret(secretPlainText)

	client := Client{
		ID:             uuid.New(),
		Secret:         hashedSecret,
		Name:           "test client",
		IsConfidential: true,
	}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			// Returning by value, so the original shouldn't be mutated
			return client, nil
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	isValid, _ := registry.VerifyClientSecret(ctx, client.ID, "badcleartext")

	if isValid {
		t.Fail()
	}
}

func TestClientRegistry_VerifyClientSecret_SecretDoesNotMatch_ReturnsNilError(t *testing.T) {
	secretPlainText := "abcd"
	hashedSecret, _ := hashSecret(secretPlainText)

	client := Client{
		ID:             uuid.New(),
		Secret:         hashedSecret,
		Name:           "test client",
		IsConfidential: true,
	}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			// Returning by value, so the original shouldn't be mutated
			return client, nil
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	_, err := registry.VerifyClientSecret(ctx, client.ID, "badcleartext")

	if err != nil {
		t.Fail()
	}
}

func TestClientRegistry_VerifyClientSecret_RepoRetrieveError_ReturnsFalse(t *testing.T) {
	secretPlainText := "abcd"
	hashedSecret, _ := hashSecret(secretPlainText)

	client := Client{
		ID:             uuid.New(),
		Secret:         hashedSecret,
		Name:           "test client",
		IsConfidential: true,
	}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			// Returning by value, so the original shouldn't be mutated
			return Client{}, errors.New("test error")
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	isValid, _ := registry.VerifyClientSecret(ctx, client.ID, "badcleartext")

	if isValid {
		t.Fail()
	}
}

func TestClientRegistry_VerifyClientSecret_RepoRetrieveError_ReturnsError(t *testing.T) {
	secretPlainText := "abcd"
	hashedSecret, _ := hashSecret(secretPlainText)

	client := Client{
		ID:             uuid.New(),
		Secret:         hashedSecret,
		Name:           "test client",
		IsConfidential: true,
	}

	repo := ClientRepositoryFake{
		RetrieveFunc: func(ctx context.Context, clientID uuid.UUID) (Client, error) {
			// Returning by value, so the original shouldn't be mutated
			return Client{}, errors.New("test error")
		},
	}

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	registry, _ := NewRegistry(context.Background(), &repo, clientSecretLen)

	_, err := registry.VerifyClientSecret(ctx, client.ID, "badcleartext")

	if err == nil {
		t.Fail()
	}
}

func ClientsAreEqual(c1 Client, c2 Client) bool {
	if c1.ID != c2.ID ||
		c1.Name != c2.Name ||
		c1.IsConfidential != c2.IsConfidential ||
		!bytes.Equal(c1.Secret, c1.Secret) {
		return false
	}

	return true
}
