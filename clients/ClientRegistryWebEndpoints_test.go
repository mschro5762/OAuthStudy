package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/contexthelper"
)

type ClientRegistryServiceFake struct {
	RegisterClientFunc          func(context.Context, string, bool, string) (Client, string, error)
	GetClientFunc               func(context.Context, uuid.UUID) (Client, error)
	DeleteClientFunc            func(context.Context, uuid.UUID) error
	GenerateNewClientSecretFunc func(context.Context, uuid.UUID) (string, error)
	VerifyClientSecretFunc      func(context.Context, uuid.UUID, string) (bool, error)
}

func (fake *ClientRegistryServiceFake) RegisterClient(ctx context.Context, clientName string, isConfidential bool, redirectURI string) (Client, string, error) {
	if fake.RegisterClientFunc != nil {
		return fake.RegisterClientFunc(ctx, clientName, isConfidential, redirectURI)
	}

	return Client{}, "", nil
}

func (fake *ClientRegistryServiceFake) GetClient(ctx context.Context, clientID uuid.UUID) (Client, error) {
	if fake.GetClientFunc != nil {
		return fake.GetClientFunc(ctx, clientID)
	}

	return Client{}, nil
}

func (fake *ClientRegistryServiceFake) DeleteClient(ctx context.Context, clientID uuid.UUID) error {
	if fake.DeleteClientFunc != nil {
		return fake.DeleteClientFunc(ctx, clientID)
	}

	return nil
}

func (fake *ClientRegistryServiceFake) GenerateNewClientSecret(ctx context.Context, clientID uuid.UUID) (string, error) {
	if fake.GenerateNewClientSecretFunc != nil {
		return fake.GenerateNewClientSecretFunc(ctx, clientID)
	}

	return "abcde", nil
}

func (fake *ClientRegistryServiceFake) VerifyClientSecret(ctx context.Context, clientID uuid.UUID, clientSecret string) (bool, error) {
	if fake.VerifyClientSecretFunc != nil {
		return fake.VerifyClientSecretFunc(ctx, clientID, clientSecret)
	}

	return false, nil
}

func TestClientRegistryWebEndpoints_RegisterClientEndpoint_HappyPath_WritesResponseObject(t *testing.T) {
	requestObj := registerClientRequest{
		Name:           "test client",
		IsConfidential: true,
	}

	expectedSecretCleartext := "expected secret"
	hashedExpectedSecret, _ := hashSecret(expectedSecretCleartext)
	expectedClientID := uuid.New()
	expectedName := "foo"

	expectedRspObj := registerClientResponse{
		ID:              expectedClientID.String(),
		Name:            expectedName,
		SecretCleartext: expectedSecretCleartext,
	}

	registry := ClientRegistryServiceFake{
		RegisterClientFunc: func(context.Context, string, bool, string) (Client, string, error) {
			return Client{
					ID:     expectedClientID,
					Name:   expectedName,
					Secret: hashedExpectedSecret,
				},
				expectedSecretCleartext,
				nil
		},
	}
	logger := zap.NewNop()
	ctx := contexthelper.NewContextWithLogger(logger)
	body, _ := json.Marshal(requestObj)

	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
		Body:   ioutil.NopCloser(bytes.NewReader(body)),
	}
	req = req.WithContext(ctx)
	rsp := httptest.NewRecorder()

	endpoints, _ := NewWebEndpoints(ctx, &registry)

	endpoints.RegisterClient(body, rsp, req)

	var actualRspObj registerClientResponse
	err := json.Unmarshal(rsp.Body.Bytes(), &actualRspObj)

	if err != nil ||
		actualRspObj != expectedRspObj {
		t.Fail()
	}
}

func TestClientRegistryWebEndpoints_RegisterClientEndpoint_CallsRegistryMethod(t *testing.T) {
	requestObj := registerClientRequest{
		Name:           "test client",
		IsConfidential: true,
	}

	fnCalledCount := 0
	registry := ClientRegistryServiceFake{
		RegisterClientFunc: func(context.Context, string, bool, string) (Client, string, error) {
			fnCalledCount++
			return Client{}, "", nil
		},
	}
	logger := zap.NewNop()
	ctx := contexthelper.NewContextWithLogger(logger)
	body, _ := json.Marshal(requestObj)

	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
		Body:   ioutil.NopCloser(bytes.NewReader(body)),
	}
	req = req.WithContext(ctx)
	rsp := httptest.NewRecorder()

	endpoints, _ := NewWebEndpoints(ctx, &registry)

	endpoints.RegisterClient(body, rsp, req)

	if fnCalledCount != 1 {
		t.Fail()
	}
}

func TestClientRegistryWebEndpoints_GenerateNewClientSecret_InvalidUUID_WritesNotFound(t *testing.T) {
	registry := ClientRegistryServiceFake{}
	logger := zap.NewNop()
	ctx := contexthelper.NewContextWithLogger(logger)

	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
	}
	req = req.WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{
		RouteParamClientID: "invalid UUID",
	})
	rsp := httptest.NewRecorder()

	endpoints, _ := NewWebEndpoints(ctx, &registry)

	endpoints.GenerateNewClientSecret(rsp, req)

	if rsp.Code != http.StatusNotFound {
		t.Fail()
	}
}

func TestClientRegistryWebEndpoints_GenerateNewClientSecret_InvalidUUID_Writes404Body(t *testing.T) {
	registry := ClientRegistryServiceFake{}
	logger := zap.NewNop()
	ctx := contexthelper.NewContextWithLogger(logger)

	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
	}
	req = req.WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{
		RouteParamClientID: "invalid UUID",
	})
	rsp := httptest.NewRecorder()

	endpoints, _ := NewWebEndpoints(ctx, &registry)

	endpoints.GenerateNewClientSecret(rsp, req)

	if string(rsp.Body.Bytes()) != "404 page not found\n" {
		t.Fail()
	}
}

func TestClientRegistryWebEndpoints_GenerateNewClientSecret_RegistryReturnsError_WritesInternalServerErrorHeader(t *testing.T) {
	registry := ClientRegistryServiceFake{
		GenerateNewClientSecretFunc: func(context.Context, uuid.UUID) (string, error) {
			return "", errors.New("foo error")
		},
	}
	logger := zap.NewNop()
	ctx := contexthelper.NewContextWithLogger(logger)

	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
	}
	req = req.WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{
		RouteParamClientID: uuid.New().String(),
	})
	rsp := httptest.NewRecorder()

	endpoints, _ := NewWebEndpoints(ctx, &registry)

	endpoints.GenerateNewClientSecret(rsp, req)

	if rsp.Code != http.StatusInternalServerError {
		t.Fail()
	}
}

func TestClientRegistryWebEndpoints_GenerateNewClientSecret_RegistryReturnsError_WritesErrorBody(t *testing.T) {
	registry := ClientRegistryServiceFake{
		GenerateNewClientSecretFunc: func(context.Context, uuid.UUID) (string, error) {
			return "", errors.New("foo error")
		},
	}
	logger := zap.NewNop()
	ctx := contexthelper.NewContextWithLogger(logger)

	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
	}
	req = req.WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{
		RouteParamClientID: uuid.New().String(),
	})
	rsp := httptest.NewRecorder()

	endpoints, _ := NewWebEndpoints(ctx, &registry)

	endpoints.GenerateNewClientSecret(rsp, req)

	bodyString := string(rsp.Body.Bytes())

	if bodyString != "Error creating new client secret\n" {
		t.Fail()
	}
}

func TestClientRegistryWebEndpoints_GenerateNewClientSecret_CallsRegistry_OnlyOnce(t *testing.T) {
	registryCalledCount := 0

	registry := ClientRegistryServiceFake{
		GenerateNewClientSecretFunc: func(context.Context, uuid.UUID) (string, error) {
			registryCalledCount++
			return "", nil
		},
	}
	logger := zap.NewNop()
	ctx := contexthelper.NewContextWithLogger(logger)

	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
	}
	req = req.WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{
		RouteParamClientID: uuid.New().String(),
	})
	rsp := httptest.NewRecorder()

	endpoints, _ := NewWebEndpoints(ctx, &registry)

	endpoints.GenerateNewClientSecret(rsp, req)

	if registryCalledCount != 1 {
		t.Fail()
	}
}

func TestClientRegistryWebEndpoints_GenerateNewClientSecret_DoesNotModifySecret(t *testing.T) {
	newSecret := uuid.New().String()

	registry := ClientRegistryServiceFake{
		GenerateNewClientSecretFunc: func(context.Context, uuid.UUID) (string, error) {
			return newSecret, nil
		},
	}
	logger := zap.NewNop()
	ctx := contexthelper.NewContextWithLogger(logger)

	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
	}
	req = req.WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{
		RouteParamClientID: uuid.New().String(),
	})
	rsp := httptest.NewRecorder()

	endpoints, _ := NewWebEndpoints(ctx, &registry)

	endpoints.GenerateNewClientSecret(rsp, req)

	if rsp.Body.String() != newSecret {
		t.Fail()
	}
}
