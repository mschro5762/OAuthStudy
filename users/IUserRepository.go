package users

import (
	"context"

	"github.com/google/uuid"
)

// IUserRepository Interface for all user repositories
type IUserRepository interface {
	Create(ctx context.Context, user User) error
	Retrieve(ctx context.Context, id uuid.UUID) (User, error)
	RetrieveByName(ctx context.Context, name string) (User, error)
	Update(ctx context.Context, user User) error
	Delete(ctx context.Context, id uuid.UUID) error
}
