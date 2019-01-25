package users

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"github.com/mschro5762/OAuthStudy/contexthelper"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.uber.org/zap"
)

type userServiceFake struct {
	RegisterUserFunc     func(ctx context.Context, name string, passwordClearText []byte) (User, error)
	GetUserFunc          func(ctx context.Context, name string) (User, error)
	ValidatePasswordFunc func(ctx context.Context, user User, clearText []byte) (bool, error)
}

func (svc *userServiceFake) RegisterUser(ctx context.Context, name string, passwordClearText []byte) (User, error) {
	if svc.RegisterUserFunc != nil {
		return svc.RegisterUserFunc(ctx, name, passwordClearText)
	}

	return User{}, nil
}

func (svc *userServiceFake) GetUser(ctx context.Context, name string) (User, error) {
	if svc.GetUserFunc != nil {
		return svc.GetUserFunc(ctx, name)
	}

	return User{}, nil
}

func (svc *userServiceFake) ValidatePassword(ctx context.Context, user User, clearText []byte) (bool, error) {
	if svc.ValidatePasswordFunc != nil {
		return svc.ValidatePasswordFunc(ctx, user, clearText)
	}

	return false, nil
}

func TestUserWebEndpoints_Ctor_ContextNil_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	userSvc := &userServiceFake{}

	_, _ = NewUserEndpoints(nil, userSvc)
}

func TestUserWebEndpoints_Ctor_UserServiceNil_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fail()
		}
	}()

	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	_, _ = NewUserEndpoints(ctx, nil)
}

func TestUserWebEndpoints_Ctor_HappyPath_ReturnsNilError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	userSvc := &userServiceFake{}

	_, err := NewUserEndpoints(ctx, userSvc)

	if err != nil {
		t.Fail()
	}
}

func TestUserWebEndpoints_Ctor_HappyPath_SetsUserService(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	expectedUserSvc := &userServiceFake{}

	endpoints, _ := NewUserEndpoints(ctx, expectedUserSvc)

	if endpoints.userSvc != expectedUserSvc {
		t.Fail()
	}
}

func TestUserWebEndpoints_RegisterUser_BodyEmpty_Writes422(t *testing.T) {
	body := make([]byte, 0)

	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	userSvc := &userServiceFake{}

	endpoints, _ := NewUserEndpoints(ctx, userSvc)

	rsp := httptest.NewRecorder()
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
		Body:   ioutil.NopCloser(bytes.NewReader(body)),
	}
	req = req.WithContext(ctx)

	endpoints.RegisterUser(body, rsp, req)

	if rsp.Code != http.StatusUnprocessableEntity {
		t.Fail()
	}
}

func TestUserWebEndpoints_RegisterUser_UserServiceReturnsError_Writes500(t *testing.T) {
	requestObj := registerUserRequest{
		Name:              "foo",
		PasswordClearText: "bar",
	}

	body, _ := json.Marshal(requestObj)

	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	userSvc := &userServiceFake{
		RegisterUserFunc: func(ctx context.Context, name string, passwordClearText []byte) (User, error) {
			return User{}, errors.New("test error")
		},
	}

	endpoints, _ := NewUserEndpoints(ctx, userSvc)

	rsp := httptest.NewRecorder()
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
		Body:   ioutil.NopCloser(bytes.NewReader(body)),
	}
	req = req.WithContext(ctx)

	endpoints.RegisterUser(body, rsp, req)

	if rsp.Code != http.StatusInternalServerError {
		t.Fail()
	}
}

func TestUserWebEndpoints_RegisterUser_HappyPath_Writes200(t *testing.T) {
	requestObj := registerUserRequest{
		Name:              "foo",
		PasswordClearText: "bar",
	}

	body, _ := json.Marshal(requestObj)

	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	userSvc := &userServiceFake{}

	endpoints, _ := NewUserEndpoints(ctx, userSvc)

	rsp := httptest.NewRecorder()
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
		Body:   ioutil.NopCloser(bytes.NewReader(body)),
	}
	req = req.WithContext(ctx)

	endpoints.RegisterUser(body, rsp, req)

	if rsp.Code != http.StatusOK {
		t.Fail()
	}
}
