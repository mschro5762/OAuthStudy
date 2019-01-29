package oauth

import (
	"context"
	"testing"

	"github.com/mschro5762/OAuthStudy/contexthelper"

	"go.uber.org/zap"
)

type EncrypterFake struct {
	NameFunc    func() string
	EncryptFunc func(ctx context.Context, cleartext []byte) ([]byte, error)
	DecryptFunc func(ctx context.Context, ciphertext []byte) ([]byte, error)
}

func (fake *EncrypterFake) Name() string {
	if fake.NameFunc != nil {
		return fake.NameFunc()
	}

	return "Fake"
}

func (fake *EncrypterFake) Encrypt(ctx context.Context, cleartext []byte) ([]byte, error) {
	if fake.EncryptFunc != nil {
		return fake.EncryptFunc(ctx, cleartext)
	}

	return cleartext, nil
}

// Decrypt Decrypts a cyphertext message
func (fake *EncrypterFake) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if fake.DecryptFunc != nil {
		return fake.DecryptFunc(ctx, ciphertext)
	}

	return ciphertext, nil
}

type SignerFake struct {
	NameFunc           func() string
	BuildSignatureFunc func(ctx context.Context, payload []byte) ([]byte, error)
}

func (fake *SignerFake) Name() string {
	if fake.NameFunc != nil {
		return fake.NameFunc()
	}

	return "Fake"
}

func (fake *SignerFake) BuildSignature(ctx context.Context, payload []byte) ([]byte, error) {
	if fake.BuildSignatureFunc != nil {
		return fake.BuildSignatureFunc(ctx, payload)
	}

	return make([]byte, 0), nil
}

func TestAuthTokenService_Ctor_HappyPath_ReturnsService(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	config := buildDefaultAuthConfig()

	encrypterFake := EncrypterFake{}

	signerFake := SignerFake{}

	svc := NewAuthTokenService(ctx, config, &encrypterFake, &signerFake)

	if svc == nil {
		t.Fail()
	}
}

func TestAuthTokenService_Ctor_ConfigZero_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	config := AuthTokenServiceConfig{}

	encrypterFake := EncrypterFake{}

	signerFake := SignerFake{}

	_ = NewAuthTokenService(ctx, config, &encrypterFake, &signerFake)
}

func TestAuthTokenService_Ctor_EncrypterNil_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	config := buildDefaultAuthConfig()

	signerFake := SignerFake{}

	_ = NewAuthTokenService(ctx, config, nil, &signerFake)
}

func TestAuthTokenService_Ctor_TTLNotParsable_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	config := AuthTokenServiceConfig{
		AuthzCodeTTLString: "foo",
	}

	encrypterFake := EncrypterFake{}

	signerFake := SignerFake{}

	_ = NewAuthTokenService(ctx, config, &encrypterFake, &signerFake)
}

func buildDefaultAuthConfig() AuthTokenServiceConfig {
	newConfig := AuthTokenServiceConfig{
		AuthzCodeTTLString:   "15m",
		AccessTokenTTLString: "15m",
	}

	return newConfig
}
