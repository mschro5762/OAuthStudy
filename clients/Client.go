package clients

import (
	"github.com/google/uuid"
)

// Client the structure of a client
type Client struct {
	ID             uuid.UUID `json:"id"`
	Secret         []byte    `json:"secret"`
	Name           string    `json:"name"`
	IsConfidential bool      `json:"isConfidential"`
	RedirectURI    string    `json:"redirectUri"`
}
