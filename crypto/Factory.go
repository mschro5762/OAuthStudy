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
func NewEncrypter(ctx context.Context, config Config) (IEncrypter, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	logger.Info("Building encrypter",
		zap.String("algoritm", config.Name),
		zap.String("keyFile", config.KeyFile))

	switch strings.ToLower(config.Name) {
	case strings.ToLower(AesEncrypterName):
		key, err := loadAesKeyFile(config.KeyFile)
		if err != nil {
			return nil, err
		}
		return NewAesEncrypter(ctx, key), nil
	default:
		return nil, errors.New("Unknown algorithm")
	}
}

// NewSigner Factory method for signers
func NewSigner(ctx context.Context, config Config) (ISigner, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	logger.Info("Building signer",
		zap.String("algoritm", config.Name),
		zap.String("keyFile", config.KeyFile))

	switch strings.ToLower(config.Name) {
	case strings.ToLower(HMACSHA256SignerName):
		key, err := loadAesKeyFile(config.KeyFile)
		if err != nil {
			return nil, err
		}
		return NewHMACSHA256Signer(ctx, key), nil
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
