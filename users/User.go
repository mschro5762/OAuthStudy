package users

import (
	"github.com/google/uuid"
)

// User The representation of a User in the authorization service.
type User struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	Password []byte    `json:"password"`
}
