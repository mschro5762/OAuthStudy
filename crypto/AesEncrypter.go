package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/mschro5762/OAuthStudy/contexthelper"

	"go.uber.org/zap"
)

// AesEncrypterName The name of the AES encrypter
const AesEncrypterName = "AES256-GCM"

// AesEncrypter Type that encapsulates AES encryption and decryption
type AesEncrypter struct {
	encryptionKey []byte
}

// NewAesEncrypter Constructs a new AesEncrypter object
func NewAesEncrypter(ctx context.Context, key []byte) *AesEncrypter {
	if ctx == nil {
		panic("Nil Argument: ctx")
	}

	if key == nil || len(key) < 1 {
		panic("Nil or empty key")
	}

	logger := contexthelper.LoggerFromContext(ctx)

	logger.Info("Creating AES encrypter")

	newEncrypter := AesEncrypter{
		encryptionKey: key,
	}

	return &newEncrypter
}

// Name The name of the encrypter
func (encrypter *AesEncrypter) Name() string {
	return AesEncrypterName
}

// Encrypt Encrypts a cleartext message
func (encrypter *AesEncrypter) Encrypt(ctx context.Context, cleartext []byte) ([]byte, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	gcm, err := encrypter.buildAesGcm(ctx)
	if err != nil {
		// logging handled in helper method
		return nil, err
	}

	// "iv" = Initialization Vector
	iv := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		logger.Error("Error reading random bytes into initialization vector",
			zap.Error(err))
		return nil, err
	}

	ciphertext := gcm.Seal(iv, iv, cleartext, nil)

	return ciphertext, nil
}

// Decrypt Decrypts a cyphertext message
func (encrypter *AesEncrypter) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	gcm, err := encrypter.buildAesGcm(ctx)
	if err != nil {
		// logging handled in helper method
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	ciphertextLen := len(ciphertext)

	if ciphertextLen < nonceSize {
		logger.Warn("AesEncrypter: ciphertext length less than nonce size",
			zap.Int("nonceSize", nonceSize),
			zap.Int("ciphertextLen", ciphertextLen))
		return nil, errors.New("ciphertext length less than nonce size")
	}

	iv, cipherData := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, iv, cipherData, nil)
	if err != nil {
		logger.Error("Error decrypting data",
			zap.Error(err),
			zap.ByteString("keyFirstFour", encrypter.encryptionKey[:4]))
		return nil, err
	}

	return plaintext, nil
}

func (encrypter *AesEncrypter) buildAesGcm(ctx context.Context) (cipher.AEAD, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	aesCipher, err := aes.NewCipher(encrypter.encryptionKey)
	if err != nil {
		logger.Error("Error creating AES cypher object",
			zap.Error(err),
			zap.ByteString("keyFirstFour", encrypter.encryptionKey[:4]))
		return nil, err
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		logger.Error("Error creating Galois Counter Mode object",
			zap.Error(err))
		return nil, err
	}

	return gcm, nil
}
