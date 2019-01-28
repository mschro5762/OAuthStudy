package crypto

import "context"

// IEncrypter Interface for encryption and decryption
type IEncrypter interface {
	Name() string

	Encrypt(ctx context.Context, cleartext []byte) ([]byte, error)

	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}
