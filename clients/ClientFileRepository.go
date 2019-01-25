package clients

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"

	"github.com/google/uuid"
)

// ClientFileRepository File repository for Client objects
type ClientFileRepository struct {
	filePath string
}

// NewFileRepository Creates a new ClientFileRepository
// Returns an error if the given path is empty
func NewFileRepository(filePath string) (*ClientFileRepository, error) {
	if strings.TrimSpace(filePath) == "" {
		return nil, errors.New("filePath empty")
	}

	newRepo := ClientFileRepository{
		filePath: filePath,
	}

	return &newRepo, nil
}

// Create Creates a Client in the repository.
// Returns an error if there is already a Client with the given ID.
func (repo *ClientFileRepository) Create(ctx context.Context, client Client) error {
	clients := repo.readFile(ctx)

	for _, c := range clients {
		if c.ID == client.ID {
			return errors.New("Unable to create existent client with ID " + client.ID.String())
		}
	}

	clients = append(clients, client)

	err := repo.saveFile(ctx, clients)
	if err != nil {
		return err
	}

	return nil
}

// Retrieve Retrieves a Client with the given ID from the repository.
// Returns an error if the given ID is not found.
func (repo *ClientFileRepository) Retrieve(ctx context.Context, id uuid.UUID) (Client, error) {
	clients := repo.readFile(ctx)

	for _, c := range clients {
		if c.ID == id {
			return c, nil
		}
	}

	return Client{}, errors.New(ClientNotFoundError + id.String())
}

// Update Updates a client in the repository.
// Returns an error if the client does not already exist.
func (repo *ClientFileRepository) Update(ctx context.Context, client Client) error {
	clients := repo.readFile(ctx)

	for i, c := range clients {
		if c.ID == client.ID {
			clients[i] = client
			err := repo.saveFile(ctx, clients)
			if err != nil {
				return err
			}
			return nil
		}
	}

	return errors.New("Unknown client ID" + client.ID.String())
}

// Delete Removes a client from the repository.
// Returns an error if the ID does not exist in the repository.
func (repo *ClientFileRepository) Delete(ctx context.Context, id uuid.UUID) error {
	clients := repo.readFile(ctx)

	for i, c := range clients {
		if c.ID == id {
			clients = append(clients[:i], clients[i+1:]...)
			err := repo.saveFile(ctx, clients)
			if err != nil {
				return err
			}
			return nil
		}
	}

	return errors.New("Unknown client ID" + id.String())
}

func (repo *ClientFileRepository) readFile(ctx context.Context) []Client {
	jsonBytes, err := ioutil.ReadFile(repo.filePath)
	if err != nil {
		return make([]Client, 0)
	}

	var clients []Client
	if json.Unmarshal(jsonBytes, &clients) != nil {
		return make([]Client, 0)
	}

	return clients
}

func (repo *ClientFileRepository) saveFile(ctx context.Context, clients []Client) error {
	b, err := json.Marshal(clients)
	if err != nil {
		return err
	}

	if ioutil.WriteFile(repo.filePath, b, 0644) != nil {
		return err
	}

	return nil
}
