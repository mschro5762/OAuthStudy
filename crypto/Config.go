package crypto

// Config The config for an encrypter.  To be used with a factory method.
type Config struct {
	Name    string `json:"name"`
	KeyFile string `json:"keyFile"`
}
