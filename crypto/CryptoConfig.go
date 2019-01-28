package crypto

// CryptoConfig The config for an encrypter.  To be used with a factory method.
type CryptoConfig struct {
	Name    string `json:"name"`
	KeyFile string `json:"keyFile"`
}
