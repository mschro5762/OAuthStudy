package oauth

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/logging"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// authorizationCode is a self decriptive structure of what Client a User
// is authorizing an AuthToken for.  It should never leave this package
// unencrypted.
type authorizationCode struct {
	ClientID  uuid.UUID
	UserID    uuid.UUID
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// CreateAuthorizationCode Creates an authorization code
func (tokenSvc *AuthTokenService) CreateAuthorizationCode(ctx context.Context, userID uuid.UUID, clientID uuid.UUID) ([]byte, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	iat := time.Now().UTC()
	exp := iat.Add(tokenSvc.config.authzCodeTTL)

	code := authorizationCode{
		ClientID:  clientID,
		UserID:    userID,
		IssuedAt:  iat,
		ExpiresAt: exp,
	}

	logger.Info("Creating authorization code",
		zap.String(logging.FieldClientID, code.ClientID.String()),
		zap.String(logging.FieldUserID, code.UserID.String()),
		zap.Time("iat", code.IssuedAt),
		zap.Time("exp", code.ExpiresAt))

	encodedCode, err := encodeAuthCode(ctx, code)
	if err != nil {
		// logging handled by helper method
		return nil, err
	}

	encryptedCode, err := tokenSvc.encrypter.Encrypt(ctx, encodedCode)
	if err != nil {
		// logging handled by helper method
		return nil, err
	}

	return encryptedCode, nil
}

// ValidateAuthorizationCode Validates that a given authorization code is valid.
// Tests that the code is within it's lifetime, and that it was requested for the given client.
func (tokenSvc *AuthTokenService) ValidateAuthorizationCode(ctx context.Context, clientID uuid.UUID, authzCode []byte) (bool, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	now := time.Now().UTC()

	encodedCode, err := tokenSvc.encrypter.Decrypt(ctx, authzCode)
	if err != nil {
		// logging handled by helper method
		return false, err
	}

	code, err := decodeAuthCode(ctx, encodedCode)
	if err != nil {
		// logging handled by helper method
		return false, err
	}

	logger = logger.With(
		zap.String(logging.FieldClientID, code.ClientID.String()),
		zap.String(logging.FieldUserID, code.UserID.String()),
		zap.Time("iat", code.IssuedAt),
		zap.Time("exp", code.ExpiresAt))

	logger.Info("Checking Authorization code")

	if code.ExpiresAt.Before(now) || code.IssuedAt.After(now) {
		logger.Warn("Expired Authorization Code")
		return false, nil
	}

	if code.ClientID != clientID {
		logger.Warn("Authoriztion code not for requesting Client")
		return false, nil
	}

	logger.Info("Authorization code valid")
	return true, nil
}

func encodeAuthCode(ctx context.Context, authCode authorizationCode) ([]byte, error) {
	var buf bytes.Buffer

	err := binary.Write(&buf, binary.BigEndian, authCode.ClientID)
	if err != nil {
		logger := contexthelper.LoggerFromContext(ctx)
		logger.Error("Error binary encoding authorization code",
			zap.Error(err))
		return nil, err
	}

	err = binary.Write(&buf, binary.BigEndian, authCode.UserID)
	if err != nil {
		logger := contexthelper.LoggerFromContext(ctx)
		logger.Error("Error binary encoding authorization code",
			zap.Error(err))
		return nil, err
	}

	err = serializeTime(ctx, &buf, authCode.IssuedAt)
	if err != nil {
		logger := contexthelper.LoggerFromContext(ctx)
		logger.Error("Error binary encoding authorization code",
			zap.Error(err))
		return nil, err
	}

	err = serializeTime(ctx, &buf, authCode.ExpiresAt)
	if err != nil {
		logger := contexthelper.LoggerFromContext(ctx)
		logger.Error("Error binary encoding authorization code",
			zap.Error(err))
		return nil, err
	}

	return buf.Bytes(), nil
}

func decodeAuthCode(ctx context.Context, data []byte) (authorizationCode, error) {
	buf := bytes.NewBuffer(data)

	authCode := authorizationCode{}

	err := binary.Read(buf, binary.BigEndian, &(authCode.ClientID))
	if err != nil {
		logger := contexthelper.LoggerFromContext(ctx)
		logger.Error("Error binary decoding authorization code",
			zap.Error(err))
		return authorizationCode{}, err
	}

	err = binary.Read(buf, binary.BigEndian, &(authCode.UserID))
	if err != nil {
		logger := contexthelper.LoggerFromContext(ctx)
		logger.Error("Error binary decoding authorization code",
			zap.Error(err))
		return authorizationCode{}, err
	}

	authCode.IssuedAt, err = deserializeTime(ctx, buf)
	if err != nil {
		logger := contexthelper.LoggerFromContext(ctx)
		logger.Error("Error binary decoding authorization code",
			zap.Error(err))
		return authorizationCode{}, err
	}

	authCode.ExpiresAt, err = deserializeTime(ctx, buf)
	if err != nil {
		logger := contexthelper.LoggerFromContext(ctx)
		logger.Error("Error binary decoding authorization code",
			zap.Error(err))
		return authorizationCode{}, err
	}

	return authCode, nil
}

func serializeTime(ctx context.Context, buf io.Writer, t time.Time) error {
	timeBytes, err := t.MarshalBinary()
	timeBytesLen := int8(len(timeBytes))

	err = binary.Write(buf, binary.BigEndian, timeBytesLen)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.BigEndian, timeBytes)
	if err != nil {
		return err
	}

	return nil
}

func deserializeTime(ctx context.Context, buf io.Reader) (time.Time, error) {
	var timeBytesLen int8
	err := binary.Read(buf, binary.BigEndian, &timeBytesLen)
	if err != nil {
		return time.Time{}, err
	}

	timeBytes := make([]byte, timeBytesLen)

	nRead, err := buf.Read(timeBytes)
	if err != nil || nRead != int(timeBytesLen) {
		return time.Time{}, err
	}

	t := time.Time{}

	err = t.UnmarshalBinary(timeBytes)
	if err != nil {
		return time.Time{}, err
	}

	return t, nil
}
