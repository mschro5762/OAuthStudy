package crypto

import (
	"testing"

	"github.com/mschro5762/OAuthStudy/contexthelper"

	"go.uber.org/zap"
)

const testAesKey = "thisisatestkeythisisatestkey===="

func TestAesEncrypter_Ctor_ReturnsEncrypter(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	encrypter := NewAesEncrypter(ctx, []byte(testAesKey))

	if encrypter == nil {
		t.Fail()
	}
}

func TestAesEncrypter_Ctor_SetsKey(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	encrypter := NewAesEncrypter(ctx, []byte(testAesKey))

	if string(encrypter.encryptionKey) != testAesKey {
		t.Fail()
	}
}

func TestAesEncrypter_Ctor_NilKey_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	NewAesEncrypter(ctx, nil)
}

func TestAesEncrypter_Ctor_CtxNil_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	NewAesEncrypter(nil, []byte(testAesKey))
}

func TestAesEncrypter_Ctor_EmptyKey_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	NewAesEncrypter(ctx, make([]byte, 0))
}

func TestAesEncrypter_Name_ReturnsName(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	encrypter := NewAesEncrypter(ctx, []byte(testAesKey))

	expectedName := AesEncrypterName
	actualName := encrypter.Name()

	if actualName != expectedName {
		t.Fail()
	}
}

func TestAesEncrypter_EncryptionRoundTrip_ProducesExpectedCleartext(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	expectedCleartext := "expected clear text!"

	encrypter := NewAesEncrypter(ctx, []byte(testAesKey))

	cyphertext, _ := encrypter.Encrypt(ctx, []byte(expectedCleartext))

	actualCleartext, _ := encrypter.Decrypt(ctx, cyphertext)

	if string(actualCleartext) != expectedCleartext {
		t.Fail()
	}
}

func TestAesEncrypter_Encrypt_HappyPath_ReturnsNilError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	cleartext := "clear text"

	encrypter := NewAesEncrypter(ctx, []byte(testAesKey))

	_, err := encrypter.Encrypt(ctx, []byte(cleartext))

	if err != nil {
		t.Fail()
	}
}

func TestAesEncrypter_Decrypt_HappyPath_ReturnsNilError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	cleartext := "clear text"

	encrypter := NewAesEncrypter(ctx, []byte(testAesKey))

	cyphertext, _ := encrypter.Encrypt(ctx, []byte(cleartext))

	_, err := encrypter.Decrypt(ctx, cyphertext)

	if err != nil {
		t.Fail()
	}
}

func TestAesEncrypter_Encrypt_BadKey_ReturnsError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	cleartext := "clear text"

	encrypter := NewAesEncrypter(ctx, []byte("badkey"))

	_, err := encrypter.Encrypt(ctx, []byte(cleartext))

	if err == nil {
		t.Fail()
	}
}

func TestAesEncrypter_Encrypt_BadKey_ReturnsNilCyphertext(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	cleartext := "clear text"

	encrypter := NewAesEncrypter(ctx, []byte("badkey"))

	cyphertext, _ := encrypter.Encrypt(ctx, []byte(cleartext))

	if cyphertext != nil {
		t.Fail()
	}
}

func TestAesEncrypter_Decrypt_BadKey_ReturnsError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	cleartext := "clear text"

	encrypter := NewAesEncrypter(ctx, []byte("badkey"))

	_, err := encrypter.Decrypt(ctx, []byte(cleartext))

	if err == nil {
		t.Fail()
	}
}

func TestAesEncrypter_Decrypt_BadKey_ReturnsNilCleartext(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	cleartext := "clear text"

	encrypter := NewAesEncrypter(ctx, []byte("badkey"))

	cyphertext, _ := encrypter.Decrypt(ctx, []byte(cleartext))

	if cyphertext != nil {
		t.Fail()
	}
}

func TestAesEncrypter_Decrypt_BadNonce_ReturnsError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	cleartext := "badnonce"

	encrypter := NewAesEncrypter(ctx, []byte(testAesKey))

	_, err := encrypter.Decrypt(ctx, []byte(cleartext))

	if err == nil {
		t.Fail()
	}
}

func TestAesEncrypter_Decrypt_BadNonce_ReturnsNilCleartext(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())
	cleartext := "badnonce"

	encrypter := NewAesEncrypter(ctx, []byte(testAesKey))

	cyphertext, _ := encrypter.Decrypt(ctx, []byte(cleartext))

	if cyphertext != nil {
		t.Fail()
	}
}
