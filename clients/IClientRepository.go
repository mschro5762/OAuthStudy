package clients

import (
	"context"

	"github.com/google/uuid"
)

// ClientNotFoundError The prefix of a client not found error text
const ClientNotFoundError = "Unknown client ID: "

// IClientRepository Interface for all client repositories
type IClientRepository interface {
	Create(ctx context.Context, client Client) error
	Retrieve(ctx context.Context, id uuid.UUID) (Client, error)
	Update(ctx context.Context, client Client) error
	Delete(ctx context.Context, id uuid.UUID) error
}
