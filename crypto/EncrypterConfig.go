package crypto

// EncrypterConfig The config for an encrypter.  To be used with a factory method.
type EncrypterConfig struct {
	Name    string `json:"name"`
	KeyFile string `json:"keyFile"`
}
