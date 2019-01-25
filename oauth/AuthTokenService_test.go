package oauth

import (
	"testing"

	"github.com/mschro5762/OAuthStudy/contexthelper"

	"go.uber.org/zap"
)

func TestAuthTokenService_Ctor_HappyPath_ReturnsService(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	config := AuthTokenServiceConfig{
		AuthzCodeTTLString: "15m",
	}

	encrypterFake := EncrypterFake{}

	svc := NewAuthTokenService(ctx, config, &encrypterFake)

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

	_ = NewAuthTokenService(ctx, config, &encrypterFake)
}

func TestAuthTokenService_Ctor_EncrypterNil_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	config := AuthTokenServiceConfig{
		AuthzCodeTTLString: "15m",
	}

	_ = NewAuthTokenService(ctx, config, nil)
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

	_ = NewAuthTokenService(ctx, config, &encrypterFake)
}
