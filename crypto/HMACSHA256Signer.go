package crypto

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"strings"
)

// HMACSHA256SignerName The name of the HMACSHA256Signer signer
const HMACSHA256SignerName = "HMAC+SHA256"

// HMACSHA256Signer The signer for producing HMAC+SHA256 signatures
type HMACSHA256Signer struct {
	signingKey []byte
}

// NewHMACSHA256Signer Creates a new NewHMACSHA256Signer
func NewHMACSHA256Signer(ctx context.Context, signingKey []byte) *HMACSHA256Signer {
	if signingKey == nil || strings.TrimSpace(string(signingKey)) == "" {
		panic("Nil argument: signing key")
	}

	newSigner := HMACSHA256Signer{
		signingKey: signingKey,
	}

	return &newSigner
}

// Name The name of the signer
func (signer *HMACSHA256Signer) Name() string {
	return HMACSHA256SignerName
}

// BuildSignature Creates a signature for a payload
func (signer *HMACSHA256Signer) BuildSignature(payload []byte) ([]byte, error) {
	h := hmac.New(sha256.New, signer.signingKey)

	_, err := h.Write(payload)
	if err != nil {
		return nil, err
	}

	signature := h.Sum(nil)

	return signature, nil
}
