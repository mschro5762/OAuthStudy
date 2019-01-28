package crypto

// ISigner the interface for signers.
type ISigner interface {
	Name() string
	BuildSignature(payload []byte) ([]byte, error)
}
