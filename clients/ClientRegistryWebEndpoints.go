package clients

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/logging"
)

// Constants for route parameters
const (
	RouteParamClientID string = "clientID"
)

// RegisterClientRequest The body of a Register Client HTTP request
type registerClientRequest struct {
	Name           string `json:"name"`
	IsConfidential bool   `json:"isConfidential"`
	RedirectURI    string `json:"redirectURI"`
}

type registerClientResponse struct {
	ID              string `json:"clientId"`
	Name            string `json:"name"`
	SecretCleartext string `json:"secret"`
}

// ClientRegistryWebEndpoints Contains the logic to communicate between the web
// and an instance of IClientRegistryService
type ClientRegistryWebEndpoints struct {
	registry IClientRegistryService
}

// NewWebEndpoints Creates a new instance of a ClientRegistryWebEndpoints
func NewWebEndpoints(ctx context.Context, registry IClientRegistryService) (*ClientRegistryWebEndpoints, error) {
	if registry == nil {
		return nil, errors.New("Argument nil: registry")
	}

	newHandler := ClientRegistryWebEndpoints{
		registry: registry,
	}

	return &newHandler, nil
}

// RegisterClient Handles a request to register a client
func (webHandler *ClientRegistryWebEndpoints) RegisterClient(body []byte, rsp http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := contexthelper.LoggerFromContext(ctx)

	var reqObj registerClientRequest
	err := json.Unmarshal(body, &reqObj)
	if err != nil {
		logger.Warn("RegisterClientEndpoint: Unable to unmarshal request JSON",
			zap.Error(err))
		rsp.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	client, secretCleartext, err := webHandler.registry.RegisterClient(ctx, reqObj.Name, reqObj.IsConfidential, reqObj.RedirectURI)
	if err != nil {
		logger.Error("RegisterClientEndpoint: Error registering client",
			zap.Error(err))
		http.Error(rsp, "Error registering client", http.StatusInternalServerError)
		return
	}

	responseObj := registerClientResponse{
		ID:              client.ID.String(),
		Name:            client.Name,
		SecretCleartext: secretCleartext,
	}

	rsp.WriteHeader(http.StatusCreated)
	rsp.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(rsp).Encode(responseObj)
	if err != nil {
		logger.Error("RegisterClientEndpoint: Error encoding new clinet for HTTP response",
			zap.String(logging.FieldClientID, client.ID.String()),
			zap.Error(err))
		http.Error(rsp, "Request finished but error writing response", http.StatusInternalServerError)
	}
}

// GenerateNewClientSecret Handles a request to generate a new client secret
func (webHandler *ClientRegistryWebEndpoints) GenerateNewClientSecret(rsp http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := contexthelper.LoggerFromContext(ctx)

	vars := mux.Vars(req)
	idStr := vars[RouteParamClientID]
	clientID, err := uuid.Parse(idStr)
	if err != nil {
		logger.Info("Requestor sent invalid client ID",
			zap.String("invalidId", idStr))

		http.NotFound(rsp, req)
		return
	}

	newSecret, err := webHandler.registry.GenerateNewClientSecret(ctx, clientID)
	if err != nil {
		// Error logged by registry method
		http.Error(rsp, "Error creating new client secret", http.StatusInternalServerError)
		return
	}

	rsp.Write([]byte(newSecret))
}
