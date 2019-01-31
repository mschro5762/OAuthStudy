package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/clients"
	"github.com/mschro5762/OAuthStudy/contexthelper"
)

func TestTokenEndpoint_HappyPath_WritesAccess200(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusOK {
		t.Fail()
	}
}

func TestTokenEndpoint_HappyPath_WritesTokenResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var token tokenResponse
	_ = json.Unmarshal(jsonResponse, &token)

	if token.AccessToken != testAccessToken ||
		token.TokenType != "Bearer" ||
		token.ExpiresIn != int(testAccessTokenExpiry.Seconds()) ||
		token.Refreshtoken != "" ||
		token.Scope != "" {
		t.Fail()
	}
}

func TestTokenEndpoint_HappyPath_PublicClient_WritesAccess200(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return testPublicClient, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), testPublicClient.ID, uuid.UUID{}, nil, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusOK {
		t.Fail()
	}
}

func TestTokenEndpoint_HappyPath_PublicClient_WritesTokenResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return testPublicClient, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), testPublicClient.ID, uuid.UUID{}, nil, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var token tokenResponse
	_ = json.Unmarshal(jsonResponse, &token)

	if token.AccessToken != testAccessToken ||
		token.TokenType != "Bearer" ||
		token.ExpiresIn != int(testAccessTokenExpiry.Seconds()) ||
		token.Refreshtoken != "" ||
		token.Scope != "" {
		t.Fail()
	}
}

func TestTokenEndpoint_PublicClient_MissingClientID_Writes400(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return testPublicClient, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, uuid.UUID{}, nil, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusBadRequest {
		t.Fail()
	}
}

func TestTokenEndpoint_PublicClient_MissingClientID_WritesErrorResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return testPublicClient, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, uuid.UUID{}, nil, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var err tokenErrorResponse
	_ = json.Unmarshal(jsonResponse, &err)

	if err.Error != "invalid_client" {
		t.Fail()
	}
}

func TestTokenEndpoint_PublicClient_MissingClientID_DoesNotWriteAuthToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return testPublicClient, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, uuid.UUID{}, nil, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "access_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_PublicClient_MissingClientID_DoesNotWriteRefreshToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return testPublicClient, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, uuid.UUID{}, nil, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "refresh_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_ClientIDMismatch_Writes401(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return testPublicClient, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.New(), testClient.ID, testClient.Secret, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusUnauthorized {
		t.Fail()
	}
}

func TestTokenEndpoint_ClientIDMismatch_WritesErrorResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return testPublicClient, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.New(), testClient.ID, testClient.Secret, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var err tokenErrorResponse
	_ = json.Unmarshal(jsonResponse, &err)

	if err.Error != "invalid_client" {
		t.Fail()
	}
}

func TestTokenEndpoint_ClientIDMismatch_DoesNotWriteAuthToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return testPublicClient, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.New(), testClient.ID, testClient.Secret, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "access_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_ClientIDMismatch_DoesNotWriteRefreshToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return testPublicClient, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.New(), testClient.ID, testClient.Secret, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "refresh_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_ClientIsConfidential_NoClientAuth_Writes401(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), testClient.ID, uuid.UUID{}, nil, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusUnauthorized {
		t.Fail()
	}
}

func TestTokenEndpoint_ClientIsConfidential_NoClientAuth_WritesErrorResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), testClient.ID, uuid.UUID{}, nil, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var err tokenErrorResponse
	_ = json.Unmarshal(jsonResponse, &err)

	if err.Error != "invalid_client" {
		t.Fail()
	}
}

func TestTokenEndpoint_ClientIsConfidential_NoClientAuth_DoesNotWriteAuthToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), testClient.ID, uuid.UUID{}, nil, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var err tokenErrorResponse
	_ = json.Unmarshal(jsonResponse, &err)

	if strings.Contains(rsp.Body.String(), "access_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_ClientIsConfidential_NoClientAuth_DoesNotWriteRefreshToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), testClient.ID, uuid.UUID{}, nil, "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var err tokenErrorResponse
	_ = json.Unmarshal(jsonResponse, &err)

	if strings.Contains(rsp.Body.String(), "refresh_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_TwoClientIDParams_Writes400(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	form := buildAccessTokenRequestForm(ctx, make([]byte, 0), testClient.ID, "", "")
	form.Add("client_id", testClient.ID.String())

	req := buildAccessTokenRequestWithForm(ctx, form, testClient.ID, []byte(testClient.Secret))
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusBadRequest {
		t.Fail()
	}
}

func TestTokenEndpoint_TwoClientIDParams_WritesErrorResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	form := buildAccessTokenRequestForm(ctx, make([]byte, 0), testClient.ID, "", "")
	form.Add("client_id", testClient.ID.String())

	req := buildAccessTokenRequestWithForm(ctx, form, testClient.ID, []byte(testClient.Secret))
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var err tokenErrorResponse
	_ = json.Unmarshal(jsonResponse, &err)

	if err.Error != "invalid_client" {
		t.Fail()
	}
}

func TestTokenEndpoint_TwoClientIDParams_DoesNotWriteAuthToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	form := buildAccessTokenRequestForm(ctx, make([]byte, 0), testClient.ID, "", "")
	form.Add("client_id", testClient.ID.String())

	req := buildAccessTokenRequestWithForm(ctx, form, testClient.ID, []byte(testClient.Secret))
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "access_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_TwoClientIDParams_DoesNotWriteRefreshToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	form := buildAccessTokenRequestForm(ctx, make([]byte, 0), testClient.ID, "", "")
	form.Add("client_id", testClient.ID.String())

	req := buildAccessTokenRequestWithForm(ctx, form, testClient.ID, []byte(testClient.Secret))
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "refresh_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_MalformedClientIDParam_Writes400(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	form := buildAccessTokenRequestForm(ctx, make([]byte, 0), testClient.ID, "", "")
	form.Set("client_id", testClient.ID.String()[:4])

	req := buildAccessTokenRequestWithForm(ctx, form, uuid.UUID{}, nil)
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusBadRequest {
		t.Fail()
	}
}

func TestTokenEndpoint_MalformedClientIDParam_WritesErrorResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	form := buildAccessTokenRequestForm(ctx, make([]byte, 0), testClient.ID, "", "")
	form.Set("client_id", testClient.ID.String()[:4])

	req := buildAccessTokenRequestWithForm(ctx, form, uuid.UUID{}, nil)
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var err tokenErrorResponse
	_ = json.Unmarshal(jsonResponse, &err)

	if err.Error != "invalid_client" {
		t.Fail()
	}
}

func TestTokenEndpoint_MalformedClientIDParam_DoesNotWriteAuthToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	form := buildAccessTokenRequestForm(ctx, make([]byte, 0), testClient.ID, "", "")
	form.Set("client_id", testClient.ID.String()[:4])

	req := buildAccessTokenRequestWithForm(ctx, form, uuid.UUID{}, nil)
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "access_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_MalformedClientIDParam_DoesNotWriteRefreshToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	form := buildAccessTokenRequestForm(ctx, make([]byte, 0), testClient.ID, "", "")
	form.Set("client_id", testClient.ID.String()[:4])

	req := buildAccessTokenRequestWithForm(ctx, form, uuid.UUID{}, nil)
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "refresh_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_UnknownClientIDParam_Writes400(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{}, errors.New(clients.ClientNotFoundError)
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	form := buildAccessTokenRequestForm(ctx, make([]byte, 0), uuid.New(), "", "")

	req := buildAccessTokenRequestWithForm(ctx, form, uuid.UUID{}, nil)
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusBadRequest {
		t.Fail()
	}
}

func TestTokenEndpoint_UnknownClientIDParam_WritesErrorResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{}, errors.New(clients.ClientNotFoundError)
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	form := buildAccessTokenRequestForm(ctx, make([]byte, 0), uuid.New(), "", "")

	req := buildAccessTokenRequestWithForm(ctx, form, uuid.UUID{}, nil)
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var err tokenErrorResponse
	_ = json.Unmarshal(jsonResponse, &err)

	if err.Error != "invalid_client" {
		t.Fail()
	}
}

func TestTokenEndpoint_UnknownClientIDParam_DoesNotWriteAuthToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{}, errors.New(clients.ClientNotFoundError)
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	form := buildAccessTokenRequestForm(ctx, make([]byte, 0), uuid.New(), "", "")

	req := buildAccessTokenRequestWithForm(ctx, form, uuid.UUID{}, nil)
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "access_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_UnknownClientIDParam_DoesNotWriteRefreshToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{}, errors.New(clients.ClientNotFoundError)
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	form := buildAccessTokenRequestForm(ctx, make([]byte, 0), uuid.New(), "", "")

	req := buildAccessTokenRequestWithForm(ctx, form, uuid.UUID{}, nil)
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "refresh_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_MalformedClientIDAuth_Writes401(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	req.SetBasicAuth(testClient.ID.String()[:4], string(testClient.Secret))
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusBadRequest {
		t.Fail()
	}
}

func TestTokenEndpoint_MalformedClientIDAuth_WritesErrorResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	req.SetBasicAuth(testClient.ID.String()[:4], string(testClient.Secret))
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var err tokenErrorResponse
	_ = json.Unmarshal(jsonResponse, &err)

	if err.Error != "invalid_client" {
		t.Fail()
	}
}

func TestTokenEndpoint_MalformedClientIDAuth_DoesNotWriteAuthToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	req.SetBasicAuth(testClient.ID.String()[:4], string(testClient.Secret))
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "access_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_MalformedClientIDAuth_DoesNotWriteRefreshToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	req.SetBasicAuth(testClient.ID.String()[:4], string(testClient.Secret))
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "refresh_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_UnknownClientIDAuth_Writes401(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{}, errors.New(clients.ClientNotFoundError)
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusUnauthorized {
		t.Fail()
	}
}

func TestTokenEndpoint_UnknownClientIDAuth_WritesErrorResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{}, errors.New(clients.ClientNotFoundError)
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var err tokenErrorResponse
	_ = json.Unmarshal(jsonResponse, &err)

	if err.Error != "invalid_client" {
		t.Fail()
	}
}

func TestTokenEndpoint_UnknownClientIDAuth_DoesNotWriteAuthToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{}, errors.New(clients.ClientNotFoundError)
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "access_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_UnknownClientIDAuth_DoesNotWriteRefreshToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{}, errors.New(clients.ClientNotFoundError)
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "refresh_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_ClientRepositoryError_Writes500(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{}, errors.New("test error")
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusInternalServerError {
		t.Fail()
	}
}

func TestTokenEndpoint_ClientRepositoryError_DoesNotWriteAuthToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{}, errors.New("test error")
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "access_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_ClientRepositoryError_DoesNotWriteRefreshToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{}, errors.New("test error")
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "refresh_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_SecretValidationError_Writes500(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		VerifyClientSecretFunc: func(context.Context, clients.Client, string) (bool, error) {
			return false, errors.New("test error")
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusInternalServerError {
		t.Fail()
	}
}

func TestTokenEndpoint_SecretValidationError_DoesNotWriteAuthToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		VerifyClientSecretFunc: func(context.Context, clients.Client, string) (bool, error) {
			return false, errors.New("test error")
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "access_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_SecretValidationError_DoesNotWriteRefreshToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		VerifyClientSecretFunc: func(context.Context, clients.Client, string) (bool, error) {
			return false, errors.New("test error")
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte(testClient.Secret), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "refresh_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_BadClientSecret_Writes401(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		VerifyClientSecretFunc: func(context.Context, clients.Client, string) (bool, error) {
			return false, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte("bad secret"), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if rsp.Code != http.StatusUnauthorized {
		t.Fail()
	}
}

func TestTokenEndpoint_BadClientSecret_WritesErrorResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		VerifyClientSecretFunc: func(context.Context, clients.Client, string) (bool, error) {
			return false, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte("bad secret"), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	jsonResponse := rsp.Body.Bytes()
	var err tokenErrorResponse
	_ = json.Unmarshal(jsonResponse, &err)

	if err.Error != "invalid_client" {
		t.Fail()
	}
}

func TestTokenEndpoint_BadClientSecret_DoesNotWriteAuthToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		VerifyClientSecretFunc: func(context.Context, clients.Client, string) (bool, error) {
			return false, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte("bad secret"), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "access_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_BadClientSecret_DoesNotWriteRefreshToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		VerifyClientSecretFunc: func(context.Context, clients.Client, string) (bool, error) {
			return false, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAccessTokenRequest(ctx, make([]byte, 0), uuid.UUID{}, testClient.ID, []byte("bad secret"), "", "")
	rsp := httptest.NewRecorder()

	endpoints.TokenEndpoint(rsp, req)

	if strings.Contains(rsp.Body.String(), "refresh_token") {
		t.Fail()
	}
}

func TestTokenEndpoint_UnrecognizedGrantTypeParam_Writes400(t *testing.T) {

}

func TestTokenEndpoint_UnrecognizedGrantTypeParam_WritesErrorResponse(t *testing.T) {

}

func TestTokenEndpoint_UnrecognizedGrantTypeParam_DoesNotWriteAuthToken(t *testing.T) {

}

func TestTokenEndpoint_UnrecognizedGrantTypeParam_DoesNotWriteRefreshToken(t *testing.T) {

}

func TestTokenEndpoint_UnsupportedGrantTypeParam_Writes400(t *testing.T) {

}

func TestTokenEndpoint_UnsupportedGrantTypeParam_WritesErrorResponse(t *testing.T) {

}

func TestTokenEndpoint_UnsupportedGrantTypeParam_DoesNotWriteAuthToken(t *testing.T) {

}

func TestTokenEndpoint_UnsupportedGrantTypeParam_DoesNotWriteRefreshToken(t *testing.T) {

}

func TestTokenEndpoint_TwoGrantTypeParams_Writes400(t *testing.T) {

}

func TestTokenEndpoint_TwoGrantTypeParams_WritesErrorResponse(t *testing.T) {

}

func TestTokenEndpoint_TwoGrantTypeParams_DoesNotWriteAuthToken(t *testing.T) {

}

func TestTokenEndpoint_TwoGrantTypeParams_DoesNotWriteRefreshToken(t *testing.T) {

}

func TestTokenEndpoint_MissingGrantTypeParams_Writes400(t *testing.T) {

}

func TestTokenEndpoint_MissingGrantTypeParams_WritesErrorResponse(t *testing.T) {

}

func TestTokenEndpoint_MissingGrantTypeParams_DoesNotWriteAuthToken(t *testing.T) {

}

func TestTokenEndpoint_MissingGrantTypeParams_DoesNotWriteRefreshToken(t *testing.T) {

}

func TestTokenEndpoint_TwoRedirectURIParams_WritesErrorResponse(t *testing.T) {

}

func TestTokenEndpoint_TwoRedirectURIParams_DoesNotWriteAuthToken(t *testing.T) {

}

func TestTokenEndpoint_TwoRedirectURIParams_DoesNotWriteRefreshToken(t *testing.T) {

}

func TestTokenEndpoint_RedirectURIParamMismatchAuth_WritesErrorResponse(t *testing.T) {

}

func TestTokenEndpoint_RedirectURIParamMismatchAuth_DoesNotWriteAuthToken(t *testing.T) {

}

func TestTokenEndpoint_RedirectURIParamMismatchAuth_DoesNotWriteRefreshToken(t *testing.T) {

}

func TestTokenEndpoint_RedirectURIParamNotSent_WasSentInAuthzRequest_WritesErrorResponse(t *testing.T) {

}

func TestTokenEndpoint_RedirectURIParamNotSent_WasSentInAuthzRequest_DoesNotWriteAuthToken(t *testing.T) {

}

func TestTokenEndpoint_RedirectURIParamNotSent_WasSentInAuthzRequest_DoesNotWriteRefreshToken(t *testing.T) {

}

func buildAccessTokenRequestForm(ctx context.Context, authzCode []byte, clientIDParam uuid.UUID, redirectURI string, grantType string) *url.Values {
	form := url.Values{}

	if (clientIDParam != uuid.UUID{}) {
		form.Add("client_id", clientIDParam.String())
	}

	if grantType == "" {
		form.Add("grant_type", "authorization_code")
	} else {
		form.Add("grant_type", grantType)
	}

	form.Add("code", string(authzCode))

	if redirectURI == "" {
		form.Add("redirect_uri", "dummyaccesstoken")
	} else {
		form.Add("redirect_uri", redirectURI)
	}

	return &form
}

func buildAccessTokenRequestWithForm(ctx context.Context, form *url.Values, clientIDAuth uuid.UUID, clientSecret []byte) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "https://test.com/token", strings.NewReader(form.Encode()))

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if clientSecret != nil {
		req.SetBasicAuth(clientIDAuth.String(), string(testClient.Secret))
	}

	req = req.WithContext(ctx)

	return req
}

func buildAccessTokenRequest(ctx context.Context, authzCode []byte, clientIDParam uuid.UUID, clientIDAuth uuid.UUID, clientSecret []byte, redirectURI string, grantType string) *http.Request {
	form := buildAccessTokenRequestForm(ctx, authzCode, clientIDParam, redirectURI, grantType)

	req := buildAccessTokenRequestWithForm(ctx, form, clientIDAuth, clientSecret)

	return req
}
