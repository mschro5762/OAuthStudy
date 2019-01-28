package oauth

import (
	"context"
	"net/http"
	"strings"

	"github.com/mschro5762/OAuthStudy/clients"
	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/logging"
	"github.com/mschro5762/OAuthStudy/users"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Implements the web communication requirements of RFC 6749 for the Authorization Endpoint (RFC 6749 3.1)

// All TLS requirements (RFC 6749 1.6) are handled by external TLS termination.  (e.g. Istio ingress in a
// Kubernetes environment), or by an consuming package. (e.g. http.ListenAndServeTLS in a "main" package)

// Brute force throttling (last para in RFC 6749 2.3.1) is handled elsewhere in infrastructure. (i.e.
// outside of this process)  There are other mechanisms we can implement, but are outside of scope right now.

// GET and POST handling (RFC 6749 3.1) are dealt with when registering the handler method with whatever
// http mux the consuming package author uses.

// The only supported Client authentication mechanism (RFC 6749 2.3.1) is HTTP basic auth

// The only supported Authorization Response Type (RFC 6749 3.1.1) is "code" (RFC 6749 4.1)

// The OAuth working group has an active draft of security topics named draft-ietf-oauth-security-topics
// (version as of 01-19-2019 https://tools.ietf.org/html/draft-ietf-oauth-security-topics-11)  This code
// will refer to it as "draft-security-topics"

// IWebEndpoints Interface for OAuth web endpoints.
type IWebEndpoints interface {
	AuthorizationEndpoint(body []byte, rsp http.ResponseWriter, req *http.Request)
}

// WebEndpoints Type containing the OAuth endpoints.
type WebEndpoints struct {
	authConfig   AuthTokenServiceConfig
	authTokenSvc IAuthTokenService
	userSvc      users.IUserService
	clientSvc    clients.IClientRegistryService
}

// NewWebEndpoints constructs a new WebEndpoints object
func NewWebEndpoints(ctx context.Context, authConfig AuthTokenServiceConfig, authSvc IAuthTokenService, userSvc users.IUserService, clientSvc clients.IClientRegistryService) *WebEndpoints {
	if authSvc == nil {
		panic("Nil authSvc")
	}

	if userSvc == nil {
		panic("Nil userSvc")
	}

	if clientSvc == nil {
		panic("Nil clientSvc")
	}

	authConfig = buildConfig(ctx, authConfig)

	newEndpoints := WebEndpoints{
		authConfig:   authConfig,
		authTokenSvc: authSvc,
		userSvc:      userSvc,
		clientSvc:    clientSvc,
	}

	return &newEndpoints
}

func (endpoints *WebEndpoints) getAndAuthenticateUserBasicAuth(ctx context.Context, rsp http.ResponseWriter, req *http.Request) (user users.User, canContinue bool) {
	logger := contexthelper.LoggerFromContext(ctx)

	// First of all, auth the user.  Don't hand out info about
	// clients or other parameters until we know who they are.
	userName, userPassword, userAuthExists := req.BasicAuth()
	if !userAuthExists {
		rsp.WriteHeader(http.StatusUnauthorized)
		return users.User{}, false
	}

	user, err := endpoints.userSvc.GetUser(ctx, userName)
	if err != nil {
		// GetUser will have logged
		rsp.WriteHeader(http.StatusUnauthorized)
		return users.User{}, false
	}

	logger.Info("Authenticating user")

	passwordValid, err := endpoints.userSvc.ValidatePassword(ctx, user, []byte(userPassword))
	if !passwordValid || err != nil {
		// ValidatePassword will have logged the error
		logger.Warn("User authentication failure")
		return users.User{}, false
	}

	logger.Info("User authentication success")

	return user, true
}

func (endpoints *WebEndpoints) getClient(ctx context.Context, rsp http.ResponseWriter, req *http.Request) (client clients.Client, canContinue bool) {
	logger := contexthelper.LoggerFromContext(ctx)

	clientIDParams, clientIDExists := req.URL.Query()["client_id"]
	if !clientIDExists || len(clientIDParams) != 1 {
		logger.Warn("Invalid number of client ID parameters")
		// Return 400 as we have no redirect URI to send error params to
		rsp.WriteHeader(http.StatusBadRequest)
		rsp.Write([]byte("Invalid cliend ID"))
		return clients.Client{}, false
	}

	clientIDParam := clientIDParams[0]

	clientID, err := uuid.Parse(clientIDParam)
	if err != nil {
		logger.Warn("Invalid client ID",
			zap.String(logging.FieldClientID, clientIDParam))
		// Return 400 as we have no redirect URI to send error params to
		rsp.WriteHeader(http.StatusBadRequest)
		rsp.Write([]byte("Invalid client ID"))
		return clients.Client{}, false
	}

	client, err = endpoints.clientSvc.GetClient(ctx, clientID)
	if err != nil {
		if strings.HasPrefix(err.Error(), clients.ClientNotFoundError) {
			logger.Warn("Client not found",
				zap.String(logging.FieldClientID, clientID.String()))
		} else {
			logger.Warn("Client retrieval error",
				zap.String(logging.FieldClientID, clientID.String()))
		}
		// Return 400 as we have no redirect URI to send error params to
		rsp.WriteHeader(http.StatusBadRequest)
		rsp.Write([]byte("Invalid client ID"))
		return clients.Client{}, false
	}

	return client, true
}
