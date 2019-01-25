package crypto

import (
	"context"
	"errors"
	"io/ioutil"
	"strings"

	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/contexthelper"
)

// NewEncrypter Factory method for encrypters.
func NewEncrypter(ctx context.Context, config EncrypterConfig) (IEncrypter, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	logger.Info("Building encrypter",
		zap.String("algoritm", config.Name),
		zap.String("keyFile", config.KeyFile))

	switch strings.ToLower(config.Name) {
	case "aes256-gcm":
		key, err := loadAesKeyFile(config.KeyFile)
		if err != nil {
			return nil, err
		}
		return NewAesEncrypter(ctx, key), nil
	default:
		return nil, errors.New("Unknown algorithm")
	}
}

func loadAesKeyFile(path string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}
