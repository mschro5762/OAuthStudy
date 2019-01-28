package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/clients"
	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/users"
)

func TestAuthorizationEndpoint_BadUserCredentials_Writes401(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{
		GetUserFunc: func(ctx context.Context, name string) (users.User, error) {
			return users.User{}, errors.New("test error")
		},
	}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	redirectURI := "https://attacker.com"

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, redirectURI, "", "")
	rsp := httptest.NewRecorder()

	req.SetBasicAuth("foo", "bar")

	endpoints.AuthorizationEndpoint(rsp, req)

	if rsp.Code != http.StatusUnauthorized {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_NoUserCredentials_Writes401(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{
		GetUserFunc: func(ctx context.Context, name string) (users.User, error) {
			return users.User{}, errors.New("test error")
		},
	}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	redirectURI := "https://attacker.com"

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, redirectURI, "", "")
	rsp := httptest.NewRecorder()

	req.Header.Del("Authorization")

	endpoints.AuthorizationEndpoint(rsp, req)

	if rsp.Code != http.StatusUnauthorized {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_NoUserCredentials_DoesNotWriteLocationHeader(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{
		GetUserFunc: func(ctx context.Context, name string) (users.User, error) {
			return users.User{}, errors.New("test error")
		},
	}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	redirectURI := "https://attacker.com"

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, redirectURI, "", "")
	rsp := httptest.NewRecorder()

	req.Header.Del("Authorization")

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")

	if redirectLocation != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_HappyPath_WritesAuthzCode(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("code") != testAuthzCode {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_HappyPath_WritesOnlyOneAuthzCode(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if len(redirectQuery["code"]) != 1 {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_HappyPath_NoStateSent_DoesNotWriteState(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("state") != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_HappyPath_StateSent_WritesState(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	expectedState := "foostate"

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", expectedState, "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("state") != expectedState {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_HappyPath_StateSent_WritesOnlyOneState(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	expectedState := "foostate"

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", expectedState, "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if len(redirectQuery["state"]) != 1 {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_HappyPath_WritesNoCacheHeaders(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	cacheControlHeader := rsp.Header().Get("Cache-Control")
	pragmaHeader := rsp.Header().Get("Pragma")

	if cacheControlHeader != "no-store" || pragmaHeader != "no-cache" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_TwoStatesSent_WritesInvalidRequest(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams["state"] = []string{"state1", "state2"}
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("error") != authzCodeErrorInvalidRequest {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_TwoStatesSent_DoesNotWriteCode(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams["state"] = []string{"state1", "state2"}
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("code") != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_HappyPath_ClientsRedirectURISent_WritesCode(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	redirectURI := testClient.RedirectURI

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, redirectURI, "", "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("state") != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_BadRedirectURISent_Writes400(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	redirectURI := "https://attacker.com"

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, redirectURI, "", "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	if rsp.Code != http.StatusBadRequest {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_BadRedirectURISent_DoesNotWriteLocationHeader(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	redirectURI := "https://attacker.com"

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, redirectURI, "", "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")

	if redirectLocation != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_TwoRedirectURIsSent_Writes400(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams["redirect_uri"] = []string{"https://foo.com", "https://bar.com"}
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	if rsp.Code != http.StatusBadRequest {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_TwoRedirectURIsSent_DoesNotWriteLocationHeader(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams["redirect_uri"] = []string{"https://foo.com", "https://bar.com"}
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")

	if redirectLocation != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_HappyPath_ScopeSent_WritesAuthzCode(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", ScopeFullAuthorization)
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("code") != testAuthzCode {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_BadScopeSent_WritesInvalidScope(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "BadScope")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("error") != authzCodeErrorInvalidScope {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_BadScopeSent_DoesNotWriteCode(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "BadScope")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("code") != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_TwoScopesSent_WritesInvalidRequest(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams["scope"] = []string{ScopeFullAuthorization, ScopeFullAuthorization}
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("error") != authzCodeErrorInvalidRequest {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_TwoScopesSent_DoesNotWriteCode(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams["scope"] = []string{ScopeFullAuthorization, ScopeFullAuthorization}
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("code") != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_ImplicitResponseType_WritesErrorResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams.Set("response_type", "token")
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("error") != authzCodeErrorUnsupportedResponseType {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_ImplicitResponseType_DoesNotWriteCode(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams.Set("response_type", "token")
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("code") != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_ImplicitResponseType_DoesNotWriteToken(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams.Set("response_type", "token")
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("access_token") != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_TwoResposneTypesSent_WritesInvalidRequest(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams["response_type"] = []string{"code", "token"}
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("error") != authzCodeErrorInvalidRequest {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_TwoResposneTypesSent_DoesNotWriteCode(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams["response_type"] = []string{"code", "token"}
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("code") != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_UnknownClientID_Returns400(t *testing.T) {
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

	req := buildAuthzCodeRequest(ctx, uuid.New(), testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	if rsp.Code != http.StatusBadRequest {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_UnknownClientID_DoesNotWriteLocationHeader(t *testing.T) {
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

	req := buildAuthzCodeRequest(ctx, uuid.New(), testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")

	if redirectLocation != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_MalformedClientID_Returns400(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, uuid.New(), testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams.Set("client_id", "foo")
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	if rsp.Code != http.StatusBadRequest {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_MalformedClientID_DoesNotWriteLocationHeader(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, uuid.New(), testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams.Set("client_id", "foo")
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")

	if redirectLocation != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_ClientIDNotSent_Returns400(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, uuid.New(), testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams.Del("client_id")
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	if rsp.Code != http.StatusBadRequest {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_ClientIDNotSent_DoesNotWriteLocationHeader(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, uuid.New(), testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams.Del("client_id")
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")

	if redirectLocation != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_TwoClientIDs_Returns400(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, uuid.New(), testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams["client_id"] = []string{testClient.ID.String(), uuid.New().String()}
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	if rsp.Code != http.StatusBadRequest {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_TwoClientIDs_DoesNotWriteLocationHeader(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, uuid.New(), testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams["client_id"] = []string{testClient.ID.String(), uuid.New().String()}
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")

	if redirectLocation != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_MalformedRegisteredRedirectURI_Returns500(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{
				ID:          testClient.ID,
				RedirectURI: ":::baduri",
			}, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	if rsp.Code != http.StatusInternalServerError {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_MalformedRegisteredRedirectURI_DoesNotWriteLocationHeader(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{
		GetClientFunc: func(context.Context, uuid.UUID) (clients.Client, error) {
			return clients.Client{
				ID:          testClient.ID,
				RedirectURI: ":::baduri",
			}, nil
		},
	}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")

	if redirectLocation != "" {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_ErrorWritingCode_WritesErrorResponse(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{
		CreateAuthorizationCodeFunc: func(ctx context.Context, userID uuid.UUID, clientID uuid.UUID) ([]byte, error) {
			return nil, errors.New("test error")
		},
	}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("error") != authzCodeErrorServerError {
		t.Fail()
	}
}

func TestAuthorizationEndpoint_ErrorWritingCode_DoesNotWriteCode(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	clientSvc := clientRegistryServiceFake{}
	userSvc := userServiceFake{}
	authzSvc := authzServiceFake{
		CreateAuthorizationCodeFunc: func(ctx context.Context, userID uuid.UUID, clientID uuid.UUID) ([]byte, error) {
			return nil, errors.New("test error")
		},
	}

	config := buildDefaultAuthConfig()

	endpoints := NewWebEndpoints(ctx, config, &authzSvc, &userSvc, &clientSvc)

	req := buildAuthzCodeRequest(ctx, testClient.ID, testUser.Name, testUser.Password, "", "", "")
	rsp := httptest.NewRecorder()

	reqParams := req.URL.Query()
	reqParams.Set("response_type", "token")
	req.URL.RawQuery = reqParams.Encode()

	endpoints.AuthorizationEndpoint(rsp, req)

	redirectLocation := rsp.Header().Get("Location")
	redirectURL, _ := url.Parse(redirectLocation)

	redirectQuery := redirectURL.Query()

	if redirectQuery.Get("code") != "" {
		t.Fail()
	}
}

func buildAuthzCodeRequest(
	ctx context.Context,
	clientID uuid.UUID,
	userName string,
	userPassword []byte,
	redirectURI string,
	state string,
	scope string,
) *http.Request {
	reqURL, _ := url.Parse("https://test.com/authorize")

	query := reqURL.Query()

	query.Add("client_id", clientID.String())
	query.Add("response_type", "code")

	if redirectURI != "" {
		query.Add("redirect_uri", redirectURI)
	}

	if state != "" {
		query.Add("state", state)
	}

	if scope != "" {
		query.Add("scope", scope)
	}

	reqURL.RawQuery = query.Encode()

	req := &http.Request{
		Method: http.MethodPost,
		URL:    reqURL,
		Header: http.Header{},
	}

	req = req.WithContext(ctx)

	req.SetBasicAuth(userName, string(userPassword))

	return req
}
