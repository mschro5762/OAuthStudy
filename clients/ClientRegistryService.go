package clients

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/logging"
)

// IClientRegistryService Interface for a Client registry
type IClientRegistryService interface {
	RegisterClient(ctx context.Context, clientName string, isConfidential bool, redirectURI string) (Client, string, error)

	GetClient(ctx context.Context, clientID uuid.UUID) (Client, error)

	DeleteClient(ctx context.Context, clientID uuid.UUID) error

	GenerateNewClientSecret(ctx context.Context, clientID uuid.UUID) (string, error)

	VerifyClientSecret(ctx context.Context, client Client, secret string) (bool, error)
}

// ClientRegistryService Concrete type for a Client registry
type ClientRegistryService struct {
	clientSecretLength int
	repo               IClientRepository
}

// NewRegistry Create a new Client registry.
func NewRegistry(ctx context.Context, repo IClientRepository, clientSecretLength int) (*ClientRegistryService, error) {
	if repo == nil {
		return nil, errors.New("nil argument: repo")
	}

	newRegistry := ClientRegistryService{
		clientSecretLength: clientSecretLength,
		repo:               repo,
	}

	return &newRegistry, nil
}

// RegisterClient Creates and registers a new Client in the system
// Returns The Client and the plaintext of the Client's secret
func (registry *ClientRegistryService) RegisterClient(ctx context.Context, clientName string, isConfidential bool, redirectURI string) (Client, string, error) {
	if ctx == nil {
		panic(logging.ErrMsgNilArgumentContext)
	}

	logger := contexthelper.LoggerFromContext(ctx)

	trimmedName := strings.TrimSpace(clientName)

	if trimmedName == "" {
		logger.Warn("ClientRegistry.RegisterClient: Client name empty")
		return Client{}, "", errors.New("Client name empty")
	}

	trimmedURI := strings.TrimSpace(redirectURI)

	if trimmedURI == "" || !validateURI(ctx, trimmedURI) {
		logger.Warn("ClientRegistry.RegisterClient: Redirect URI invalid",
			zap.String("redirectUri", trimmedURI))
		return Client{}, "", errors.New("Invalid redirect URI")
	}

	newClient := Client{
		ID:             uuid.New(),
		Name:           clientName,
		IsConfidential: isConfidential,
		RedirectURI:    redirectURI,
	}

	logger = logger.With(zap.String(logging.FieldClientID, newClient.ID.String()))

	logger.Info("ClientRegistry.RegisterClient: Creating client",
		zap.String("name", newClient.Name))

	secretClearText := registry.generateSecret()
	secretHash, err := hashSecret(secretClearText)
	if err != nil {
		logger.Error("Error hashing secret",
			zap.Error(err))
		return Client{}, "", err
	}

	newClient.Secret = secretHash

	err = registry.repo.Create(ctx, newClient)
	if err != nil {
		logger.Error("ClientRegistry.RegisterClient: Error creating client",
			zap.Error(err))
		return Client{}, "", err
	}

	logger.Info("ClientRegistry.RegisterClient: Client created")

	return newClient, secretClearText, nil
}

// GetClient Gets a client
func (registry *ClientRegistryService) GetClient(ctx context.Context, clientID uuid.UUID) (Client, error) {
	logger := contexthelper.LoggerFromContext(ctx)
	logger = logger.With(zap.String(logging.FieldClientID, clientID.String()))

	logger.Info("Getting client")

	client, err := registry.repo.Retrieve(ctx, clientID)
	if err != nil {
		logger.Warn("Unable to find client",
			zap.Error(err))
		return Client{}, errors.New("Unable to find client")
	}

	return client, nil
}

// DeleteClient Deletes a client from the system
func (registry *ClientRegistryService) DeleteClient(ctx context.Context, clientID uuid.UUID) error {
	logger := contexthelper.LoggerFromContext(ctx)

	logger.Info("Deleting client",
		zap.String(logging.FieldClientID, clientID.String()))
	err := registry.repo.Delete(ctx, clientID)

	return err
}

// GenerateNewClientSecret Generates a new secret for the given client.
// The old secret is immediately replaced.
func (registry *ClientRegistryService) GenerateNewClientSecret(ctx context.Context, clientID uuid.UUID) (string, error) {
	if ctx == nil {
		panic(logging.ErrMsgNilArgumentContext)
	}
	logger := contexthelper.LoggerFromContext(ctx)
	logger = logger.With(zap.String(logging.FieldClientID, clientID.String()))

	logger.Info("Generating new client secret")

	client, err := registry.repo.Retrieve(ctx, clientID)
	if err != nil {
		logger.Warn("Unable to find client",
			zap.Error(err))
		return "", errors.New("Unable to find client")
	}

	secretClearText := registry.generateSecret()
	secretHash, err := hashSecret(secretClearText)
	if err != nil {
		logger.Error("Error hashing secret",
			zap.Error(err))
		return "", err
	}

	client.Secret = secretHash

	err = registry.repo.Update(ctx, client)
	if err != nil {
		logger.Warn("Unable to save client",
			zap.Error(err))
		return "", errors.New("Unable to save new client secret")
	}

	return secretClearText, nil
}

// VerifyClientSecret Validates a given secret is correct for the given client.
func (registry *ClientRegistryService) VerifyClientSecret(ctx context.Context, client Client, clientSecret string) (bool, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	logger.Info("Comparing secrets for client")

	err := bcrypt.CompareHashAndPassword(client.Secret, []byte(clientSecret))
	if err != nil {
		logger.Info("Password compare failure",
			zap.Error(err))
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}

		return false, err
	}

	logger.Info("Client secret compare success")

	return true, nil
}

const clientSecretRunes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+^*-.~"

func (registry *ClientRegistryService) generateSecret() string {
	// TODO: Make the algorithm configurable

	str := make([]byte, registry.clientSecretLength)

	for i := range str {
		var letterIndex int16
		err := binary.Read(rand.Reader, binary.LittleEndian, &letterIndex)
		if err != nil {
			panic(err)
		}

		letterIndex = letterIndex % int16(len(clientSecretRunes))
		if letterIndex < 0 {
			letterIndex = -letterIndex
		}

		str[i] = clientSecretRunes[letterIndex]
	}

	return string(str)
}

func hashSecret(clearText string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(clearText), 12)
	if err != nil {
		return nil, err
	}

	return hash, nil
}

// https://tip.golang.org/pkg/regexp/syntax/
// Note that Go does not support Regexr.com style flags, nor start/end '/' chars to mark the start/end of the regex.
// We must use them in a group, or as a separate group at the beginning
// BUG: make sure that there is no fragment component
const uriRegex = `(?i)(?:[a-z][a-z0-9+.-]*):\/\/(?:[a-z][a-z0-9+.-]*)(?:\/[a-z][a-z0-9+.-]*)*(?:\?[a-z][a-z0-9+.-]*=[a-z][a-z0-9+.-]*)?`

func validateURI(ctx context.Context, uri string) bool {
	matched, err := regexp.Match(uriRegex, []byte(uri))

	if err != nil {
		logger := contexthelper.LoggerFromContext(ctx)
		logger.Warn("clients.validateURI: Error with regex match",
			zap.String("uri", uri))
		return false
	}

	return matched
}
