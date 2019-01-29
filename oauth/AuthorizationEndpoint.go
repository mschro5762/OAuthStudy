package oauth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/clients"
	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/logging"
)

const authzResponseTypeCode = "code"

// Error strings for Authorization endpoint response
const (
	authzCodeErrorInvalidRequest          = "invalid_request"
	authzCodeErrorUnauthorizedClient      = "unauthorized_client"
	authzCodeErrorAccessDenied            = "access_denied"
	authzCodeErrorUnsupportedResponseType = "unsupported_response_type"
	authzCodeErrorInvalidScope            = "invalid_scope"
	authzCodeErrorServerError             = "server_error"
	authzCodeErrorTemporarilyUnavailable  = "temporarily_unavailable"
)

// AuthorizationEndpoint Endpoint for the OAuth Authorization Request (RFC 6749 3.1)
func (endpoints *WebEndpoints) AuthorizationEndpoint(rsp http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := contexthelper.LoggerFromContext(ctx)

	user, canContinue := endpoints.getAndAuthenticateUserBasicAuth(ctx, rsp, req)
	if !canContinue {
		// getAndAuthenticateUser will have logged and written to rsp
		return
	}

	client, canContinue := endpoints.getClient(ctx, rsp, req)
	if !canContinue {
		// getClient will have logged and written to rsp
		return
	}

	logger = logger.With(
		zap.String(logging.FieldUserID, user.ID.String()),
		zap.String(logging.FieldClientID, client.ID.String()))
	ctx = contexthelper.AddLoggertoContext(ctx, logger)
	req = req.WithContext(ctx)

	redirectURISent, canContinue := handleRedirectURIParam(ctx, rsp, req, client)
	if !canContinue {
		// handleRedirectURIParam will have logged and written to rsp
		return
	}

	state, canContinue := handleStateParam(ctx, rsp, req, client)
	if !canContinue {
		// handleStateParam will have logged and written to rsp
		return
	}

	canContinue = handleResponseTypeParam(ctx, rsp, req, client, state)
	if !canContinue {
		// handleResponseTypeParam will have logged and written to rsp
		return
	}

	_, canContinue = handleScopeParam(ctx, rsp, req, client, state)
	if !canContinue {
		// handleScopeParam will have logged and written to rsp
		return
	}

	code, err := endpoints.authTokenSvc.CreateAuthorizationCode(ctx, user.ID, client.ID, redirectURISent)
	if err != nil {
		// CreateAuthorizationCode will have logged
		err = writeAuthorizationErrorResponseRedirect(ctx, authzCodeErrorServerError, "", client, state, rsp)
		if err != nil {
			logger.Error("Error writing Authorization Code redirect response",
				zap.Error(err))
			http.Error(rsp, "Unexpected error", http.StatusInternalServerError)
		}
		return
	}

	err = writeAuthorizationCodeResponseRedirect(ctx, client, code, state, rsp)
	if err != nil {
		// CreateAuthorizationCode will have logged
		err = writeAuthorizationErrorResponseRedirect(ctx, authzCodeErrorServerError, "", client, state, rsp)
		if err != nil {
			logger.Error("Error writing Authorization Code redirect response",
				zap.Error(err))
			http.Error(rsp, "Unexpected error", http.StatusInternalServerError)
		}
		return
	}
}

func handleRedirectURIParam(ctx context.Context, rsp http.ResponseWriter, req *http.Request, client clients.Client) (redirectURISent, canContinue bool) {
	logger := contexthelper.LoggerFromContext(ctx)

	redirectURIs := req.URL.Query()["redirect_uri"]
	redirectURIsLen := len(redirectURIs)

	if redirectURIsLen != 0 {
		if redirectURIsLen != 1 {
			logger.Warn("Recieved invalid redirect_uri count",
				zap.Int("redirectUriCount", redirectURIsLen))
			// Error out, don't redirect, no information to attackers
			rsp.WriteHeader(http.StatusBadRequest)
			return true, false
		}

		redirectURI := redirectURIs[0]

		logger.Info("Recieved redirect_uri parameter",
			zap.String("redirectUriParam", redirectURI))

		// Only use exact matching of a redirect URI (draft-security-topics 3.1)
		if redirectURI != client.RedirectURI {
			logger.Warn("Redirect URI mismatch",
				zap.String("clientRedirectUri", client.RedirectURI),
				zap.String("redirectUriParam", redirectURI))
			// Error out, don't redirect, no information to attackers
			rsp.WriteHeader(http.StatusBadRequest)
			return true, false
		}

		logger.Info("Redirect URI match")
		return true, true
	}

	logger.Info("No redirect URI parameter")
	return false, true
}

func handleStateParam(ctx context.Context, rsp http.ResponseWriter, req *http.Request, client clients.Client) (state string, canContinue bool) {
	logger := contexthelper.LoggerFromContext(ctx)

	states := req.URL.Query()["state"]
	statesLen := len(states)

	if statesLen != 0 {
		if statesLen != 1 {
			logger.Warn("Recieved invalid state count",
				zap.Int("statesCount", statesLen))
			err := writeAuthorizationErrorResponseRedirect(ctx, authzCodeErrorInvalidRequest, "Invalid state count", client, "", rsp)
			if err != nil {
				logger.Error("Error writing Authorization Code redirect response",
					zap.Error(err))
				http.Error(rsp, "Unexpected error", http.StatusInternalServerError)
			}
			return "", false
		}

		state = states[0]

		logger.Info("Recieved state parameter")

	} else {
		state = ""
		logger.Info("No state parameter")
	}

	return state, true
}

func handleResponseTypeParam(ctx context.Context, rsp http.ResponseWriter, req *http.Request, client clients.Client, state string) (canContinue bool) {
	logger := contexthelper.LoggerFromContext(ctx)

	responseTypes, respTypesExists := req.URL.Query()["response_type"]
	if !respTypesExists || len(responseTypes) != 1 {
		logger.Warn("Invalid response type param count")
		err := writeAuthorizationErrorResponseRedirect(ctx, authzCodeErrorInvalidRequest, "Invalid response_type count", client, state, rsp)
		if err != nil {
			logger.Error("Error writing Authorization Code redirect response",
				zap.Error(err))
			http.Error(rsp, "Unexpected error", http.StatusInternalServerError)
		}
		return false
	}

	if responseTypes[0] != authzResponseTypeCode {
		logger.Warn("Invalid response type",
			zap.String("responseType", responseTypes[0]))
		err := writeAuthorizationErrorResponseRedirect(ctx, authzCodeErrorUnsupportedResponseType, "", client, state, rsp)
		if err != nil {
			logger.Error("Error writing Authorization Code redirect response",
				zap.Error(err))
			http.Error(rsp, "Unexpected error", http.StatusInternalServerError)
		}
		return false
	}

	return true
}

func handleScopeParam(ctx context.Context, rsp http.ResponseWriter, req *http.Request, client clients.Client, state string) (scopes []string, canContinue bool) {
	logger := contexthelper.LoggerFromContext(ctx)

	scopeParam := req.URL.Query()["scope"]
	scopesParamLen := len(scopeParam)

	if scopesParamLen == 0 {
		logger.Info("No scope parameter")
		return []string{ScopeFullAuthorization}, true
	}

	if scopesParamLen != 1 {
		logger.Warn("Recieved invalid scope param count",
			zap.Int("scopeParamCount", scopesParamLen))
		writeAuthorizationErrorResponseRedirect(ctx, authzCodeErrorInvalidRequest, "Invalid scope count", client, state, rsp)
		return nil, false
	}

	scopesString := scopeParam[0]
	scopes = strings.Split(scopesString, " ")

	invalidScopes := make([]string, 0)

	for _, s := range scopes {
		switch s {
		case ScopeFullAuthorization:
			continue
		default:
			invalidScopes = append(invalidScopes, s)
		}
	}

	if len(invalidScopes) > 0 {
		logger.Warn("Recieved invalid scope(s)",
			zap.String("invalidScopes", strings.Join(invalidScopes, " ")))
		writeAuthorizationErrorResponseRedirect(ctx, authzCodeErrorInvalidScope, "", client, state, rsp)
		return nil, false
	}

	return scopes, true
}

func writeAuthorizationErrorResponseRedirect(ctx context.Context, er string, errorDescription string, client clients.Client, state string, rsp http.ResponseWriter) error {
	redirectURI, err := url.Parse(client.RedirectURI)
	if err != nil {
		return err
	}

	query := redirectURI.Query()
	query.Add("error", er)

	if errorDescription != "" {
		query.Add("error_description", errorDescription)
	}

	redirectURI.RawQuery = query.Encode()

	writeClientRedirect(ctx, redirectURI, state, rsp)

	return nil
}

func writeAuthorizationCodeResponseRedirect(ctx context.Context, client clients.Client, authorizationCode []byte, state string, rsp http.ResponseWriter) error {
	redirectURI, err := url.Parse(client.RedirectURI)
	if err != nil {
		return err
	}

	encodedCode := base64.URLEncoding.EncodeToString(authorizationCode)

	query := redirectURI.Query()
	query.Add("code", string(encodedCode))
	redirectURI.RawQuery = query.Encode()

	writeClientRedirect(ctx, redirectURI, state, rsp)

	return nil
}

func writeClientRedirect(ctx context.Context, redirectURI *url.URL, state string, rsp http.ResponseWriter) {
	if state != "" {
		query := redirectURI.Query()
		query.Add("state", state)
		redirectURI.RawQuery = query.Encode()
	}

	logger := contexthelper.LoggerFromContext(ctx)
	logger.Info("Redirecting to client redirect endpoint",
		// Probably should extract or mask out the authorization code and state, but
		// since it's such a short lived item, and a nonce at that, it should be fine.
		zap.String("clientRedirectUri", redirectURI.String()))

	rsp.Header().Add("Location", redirectURI.String())
	rsp.Header().Add("Cache-Control", "no-store")
	rsp.Header().Add("Pragma", "no-cache")

	rsp.WriteHeader(http.StatusFound)
}
