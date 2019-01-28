package crypto

import "context"

// ISigner the interface for signers.
type ISigner interface {
	Name() string
	BuildSignature(ctx context.Context, payload []byte) ([]byte, error)
}
