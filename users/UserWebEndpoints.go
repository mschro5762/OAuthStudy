package users

import (
	"context"
	"encoding/json"
	"github.com/mschro5762/OAuthStudy/contexthelper"
	"net/http"

	"go.uber.org/zap"
)

// UserWebEndpoints Web handler endpoints for User interactions
type UserWebEndpoints struct {
	userSvc IUserService
}

type registerUserRequest struct {
	Name              string `json:"name"`
	PasswordClearText string `json:"password"`
}

// NewUserEndpoints Constructs a new UserWebEndpoints object
func NewUserEndpoints(ctx context.Context, userService IUserService) (UserWebEndpoints, error) {
	if ctx == nil {
		panic("Context not passed")
	}

	if userService == nil {
		panic("User service not passed")
	}

	logger := contexthelper.LoggerFromContext(ctx)

	logger.Debug("Creating new User endpoints object")

	newEndpoints := UserWebEndpoints{
		userSvc: userService,
	}

	return newEndpoints, nil
}

// RegisterUser Handles a request to register a user
func (userHandler *UserWebEndpoints) RegisterUser(body []byte, rsp http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := contexthelper.LoggerFromContext(ctx)

	var reqObj registerUserRequest
	err := json.Unmarshal(body, &reqObj)
	if err != nil {
		logger.Warn("RegisterUserEndpoint: Unable to unmarshal request JSON",
			zap.Error(err))
		rsp.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	_, err = userHandler.userSvc.RegisterUser(ctx, reqObj.Name, []byte(reqObj.PasswordClearText))
	if err != nil {
		logger.Error("Unable to register user",
			zap.Error(err))
		http.Error(rsp, "Error creating user", http.StatusInternalServerError)
	}

	rsp.WriteHeader(http.StatusOK)
}
