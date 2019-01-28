package crypto

import (
	"bytes"
	"testing"

	"github.com/mschro5762/OAuthStudy/contexthelper"
	"go.uber.org/zap"
)

const testHMACKey = "thisisatestkeythisisatestkey"

func TestHMACSHA256Signer_Name_ReturnsName(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	signer := NewHMACSHA256Signer(ctx, []byte(testHMACKey))

	expectedName := HMACSHA256SignerName
	actualname := signer.Name()

	if actualname != expectedName {
		t.Fail()
	}
}

func TestHMACSHA256Signer_Ctor_HappyPath_AssignsKey(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	expectedKey := testHMACKey

	signer := NewHMACSHA256Signer(ctx, []byte(expectedKey))

	if string(signer.signingKey) != expectedKey {
		t.Fail()
	}
}

func TestHMACSHA256Signer_Ctor_KeyNil_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	NewHMACSHA256Signer(ctx, nil)
}

func TestHMACSHA256Signer_Ctor_KeyEmpty_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	NewHMACSHA256Signer(ctx, []byte(""))
}

func TestHMACSHA256Signer_BuildSignature_HappyPath_ReturnsSigature(t *testing.T) {
	payload := "foo"

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	signer := NewHMACSHA256Signer(ctx, []byte(testHMACKey))

	signature, _ := signer.BuildSignature([]byte(payload))

	if signature == nil {
		t.Fail()
	}
}

func TestHMACSHA256Signer_BuildSignature_HappyPath_ReturnsConsistantSigature(t *testing.T) {
	payload := "foo"

	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	signer := NewHMACSHA256Signer(ctx, []byte(testHMACKey))

	signature1, _ := signer.BuildSignature([]byte(payload))
	signature2, _ := signer.BuildSignature([]byte(payload))

	if !bytes.Equal(signature1, signature2) {
		t.Fail()
	}
}

// We need to keep the error check on h.Write because implementation of the sha256 implementation
// could change between comilations, but there is currently no way to make it error, or elegantly
// mock it away.
