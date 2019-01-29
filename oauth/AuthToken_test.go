package oauth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUserAccessToken_JSONMarshalingRoundTrip_CreatesWellFormedOutput(t *testing.T) {
	expDuration, _ := time.ParseDuration("30m")
	expectedToken := userAccessToken{
		Issuer: "https://foo.com",
		UserID: uuid.New(),
		Audience: []string{
			"https://authz.com/userinfo",
			"https://resource.com",
		},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(expDuration),
	}

	data, _ := json.Marshal(expectedToken)

	var actualToken userAccessToken
	_ = json.Unmarshal(data, &actualToken)

	// Asserting unix timestamps as that is what is marshaled
	if actualToken.Issuer != expectedToken.Issuer ||
		actualToken.UserID != expectedToken.UserID ||
		actualToken.IssuedAt.Unix() != expectedToken.IssuedAt.Unix() ||
		actualToken.ExpiresAt.Unix() != expectedToken.ExpiresAt.Unix() ||
		len(actualToken.Audience) != len(expectedToken.Audience) {
		t.Fail()
	}
}
