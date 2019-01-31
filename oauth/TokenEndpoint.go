package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/mschro5762/OAuthStudy/clients"
	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/logging"
	"go.uber.org/zap"
)

// Token request paramter names
const (
	tokenParamClientID    = "client_id"
	tokenParamGrantType   = "grant_type"
	tokenParamCode        = "code"
	tokenParamRedirectURI = "redirect_uri"
)

const (
	tokenGrantTypeAuthzCode                = "authorization_code"
	tokenGrantTypeClientCredentials        = "client_credentials"
	tokenGrantTypeResourceOwnerCredentials = "password"
)

// Error strings for Token endpoint response
const (
	tokenErrorInvalidRequest       = "invalid_request"
	tokenErrorInvalidClient        = "invalid_client"
	tokenErrorInvalidGrant         = "invalid_grant"
	tokenErrorUnauthorizedClient   = "unauthorized_client"
	tokenErrorUnsupportedGrantType = "unsupported_Grant_type"
	tokenErrorInvalidScope         = "invalid_scope"
)

// TokenEndpoint The endpoint for Endpoint for the OAuth Token Request (RFC 6749 3.2)
func (endpoints *WebEndpoints) TokenEndpoint(rsp http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := contexthelper.LoggerFromContext(ctx)

	req.ParseForm()

	client, canContinue := endpoints.getAndAuthenticateClient(ctx, rsp, req)
	if !canContinue {
		// getAndAuthenticateUser will have logged and written to rsp
		return
	}

	logger = logger.With(
		zap.String(logging.FieldClientID, client.ID.String()))
	ctx = contexthelper.AddLoggertoContext(ctx, logger)
	req = req.WithContext(ctx)

	// Returned grant type is currently not used, only authorization_code supported
	_, canContinue = endpoints.validateGrantTypeParameter(ctx, rsp, req)
	if !canContinue {
		// validateGrantTypeParameter will have logged and written to rsp
		return
	}

	redirectURIParam, canContinue := endpoints.validateRedirectURIParameter(ctx, rsp, req)
	if !canContinue {
		// validateRedirectURIParameter will have logged and written to rsp
		return
	}

	authzCode, canContinue := endpoints.validateAuthzCodeParam(ctx, rsp, req)
	if !canContinue {
		// validateRedirectURIParameter will have logged and written to rsp
		return
	}

	decodedCode, err := base64.URLEncoding.DecodeString(string(authzCode))
	if err != nil {
		logger.Warn("Unable to validate authorization code",
			zap.Error(err))
		rsp.WriteHeader(http.StatusInternalServerError)
		return
	}

	codeIsValid, userID, err := endpoints.authTokenSvc.ValidateAuthorizationCode(ctx, client, decodedCode, redirectURIParam)
	if err != nil {
		logger.Warn("Unable to validate authorization code",
			zap.Error(err))
		rsp.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !codeIsValid {
		logger.Warn("Invalid authorization code")
		endpoints.writeTokenBadRequestErrorResponse(ctx, tokenErrorInvalidRequest, "", rsp)
		return
	}

	// TODO: generate token
	jws, exp, err := endpoints.authTokenSvc.BuildAccessToken(ctx, userID, client.ID)
	if err != nil {
		logger.Warn("Unable to build access token",
			zap.Error(err))
		rsp.WriteHeader(http.StatusInternalServerError)
		return
	}

	endpoints.writeTokenResponse(ctx, jws, exp, nil, "", rsp)
}

func (endpoints *WebEndpoints) getAndAuthenticateClient(ctx context.Context, rsp http.ResponseWriter, req *http.Request) (clients.Client, bool) {
	// This is going to be complicated due to the interaction between the auth header and the client_id paramter
	// If basic auth is used, then ANY non-processing error must be a 401, otherwise, its a 400 or 500
	// If both are used, then make sure they're the same
	// As usual, paramters can only appear once

	logger := contexthelper.LoggerFromContext(ctx)

	clientAuthIDString, clientSecret, basicAuthExists := req.BasicAuth()

	clientIDParams, clientIDParamExists := req.Form[tokenParamClientID]
	if clientIDParamExists && len(clientIDParams) != 1 {
		logger.Warn("Invalid number of client ID parameters")
		endpoints.writeTokenBadRequestErrorResponse(ctx, tokenErrorInvalidClient, "Invalid client_id parameter count", rsp)
		return clients.Client{}, false
	}

	if basicAuthExists && clientIDParamExists && clientAuthIDString != clientIDParams[0] {
		logger.Warn("Clinet ID mismatch between query and auth header",
			zap.String("authClientID", clientAuthIDString),
			zap.String("paramClientID", clientIDParams[0]))
		endpoints.writeTokenAuthErrorResponse(ctx, tokenErrorInvalidClient, "Client ID mismatch between query and authentication header", rsp)
		return clients.Client{}, false
	}

	var clientIDString string
	if basicAuthExists {
		clientIDString = clientAuthIDString
	} else if clientIDParamExists {
		clientIDString = clientIDParams[0]
	} else {
		logger.Warn("No Client ID sent")
		endpoints.writeTokenBadRequestErrorResponse(ctx, tokenErrorInvalidClient, "No client ID", rsp)
		return clients.Client{}, false
	}

	clientID, err := uuid.Parse(clientIDString)
	if err != nil {
		logger.Warn("Invalid client ID",
			zap.String(logging.FieldClientID, clientIDString))
		endpoints.writeTokenBadRequestErrorResponse(ctx, tokenErrorInvalidClient, "Invalid client ID", rsp)
		return clients.Client{}, false
	}

	client, err := endpoints.clientSvc.GetClient(ctx, clientID)
	if err != nil {
		// GetClient will have logged
		// Return 400 as we have no redirect URI to send error params to
		if strings.HasPrefix(err.Error(), clients.ClientNotFoundError) {
			if basicAuthExists {
				endpoints.writeTokenAuthErrorResponse(ctx, tokenErrorInvalidClient, "Invalid client ID", rsp)
			} else {
				endpoints.writeTokenBadRequestErrorResponse(ctx, tokenErrorInvalidClient, "Invalid client ID", rsp)
			}
		} else {
			rsp.WriteHeader(http.StatusInternalServerError)
		}
		return clients.Client{}, false
	}

	if client.IsConfidential {
		if !basicAuthExists {
			logger.Warn("Client is confidential but authentication was not provided",
				zap.String(logging.FieldClientID, clientAuthIDString))
			endpoints.writeTokenAuthErrorResponse(ctx, tokenErrorInvalidClient, "", rsp)
			return clients.Client{}, false
		}

		clientAuthed, err := endpoints.clientSvc.VerifyClientSecret(ctx, client, clientSecret)
		if err != nil {
			// VerifyClientSecret will have logged
			rsp.WriteHeader(http.StatusInternalServerError)
			return clients.Client{}, false
		}
		if !clientAuthed {
			// VerifyClientSecret will have logged
			endpoints.writeTokenAuthErrorResponse(ctx, tokenErrorInvalidClient, "", rsp)
			return clients.Client{}, false
		}
	}

	return client, true
}

func (endpoints *WebEndpoints) validateGrantTypeParameter(ctx context.Context, rsp http.ResponseWriter, req *http.Request) (string, bool) {
	logger := contexthelper.LoggerFromContext(ctx)

	grantTypeParams, grantTypeExists := req.Form[tokenParamGrantType]
	if !grantTypeExists || len(grantTypeParams) != 1 {
		logger.Warn("Invalid grant_type count",
			zap.Int("grantTypeCount", len(grantTypeParams)))
		endpoints.writeTokenBadRequestErrorResponse(ctx, tokenErrorInvalidGrant, "Invalid grant_type count", rsp)
		return "", false
	}

	grantTypeParam := grantTypeParams[0]

	switch grantTypeParam {
	case tokenGrantTypeAuthzCode:
		break // Good grant type
	case tokenGrantTypeClientCredentials:
		fallthrough
	case tokenGrantTypeResourceOwnerCredentials:
		fallthrough
	default:
		logger.Warn("Unsupported grant_type",
			zap.String("grantType", grantTypeParam))
		endpoints.writeTokenBadRequestErrorResponse(ctx, tokenErrorInvalidGrant, "Unsupported grant_type", rsp)
		return "", false
	}

	return grantTypeParam, true
}

func (endpoints *WebEndpoints) validateRedirectURIParameter(ctx context.Context, rsp http.ResponseWriter, req *http.Request) (string, bool) {
	logger := contexthelper.LoggerFromContext(ctx)

	redirectURIParams, redirectURIExists := req.Form[tokenParamRedirectURI]

	if !redirectURIExists {
		return "", true
	}

	if len(redirectURIParams) != 1 {
		logger.Warn("Invalid redirect_uri count",
			zap.Int("redirectUriCount", len(redirectURIParams)))
		endpoints.writeTokenBadRequestErrorResponse(ctx, tokenErrorInvalidRequest, "Invalid redirect_uri count", rsp)
		return "", false
	}

	redirectURIParam := redirectURIParams[0]

	return redirectURIParam, true
}

func (endpoints *WebEndpoints) validateAuthzCodeParam(ctx context.Context, rsp http.ResponseWriter, req *http.Request) ([]byte, bool) {
	logger := contexthelper.LoggerFromContext(ctx)

	authzCodeParams, authzCodeExists := req.Form[tokenParamCode]

	if !authzCodeExists || len(authzCodeParams) != 1 {
		logger.Warn("Invalid code count",
			zap.Int("authzCodeCount", len(authzCodeParams)))
		endpoints.writeTokenBadRequestErrorResponse(ctx, tokenErrorInvalidRequest, "Invalid code count", rsp)
		return make([]byte, 0), false
	}

	authzCodeParam := authzCodeParams[0]

	return []byte(authzCodeParam), true
}

type tokenErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func (endpoints *WebEndpoints) writeTokenAuthErrorResponse(ctx context.Context, er string, description string, rsp http.ResponseWriter) {
	rsp.Header().Add("WWW-Authenticate", "Basic")
	endpoints.writeTokenErrorResponse(ctx, er, description, http.StatusUnauthorized, rsp)
}

func (endpoints *WebEndpoints) writeTokenBadRequestErrorResponse(ctx context.Context, er string, description string, rsp http.ResponseWriter) {
	endpoints.writeTokenErrorResponse(ctx, er, description, http.StatusBadRequest, rsp)
}

func (endpoints *WebEndpoints) writeTokenErrorResponse(ctx context.Context, er string, description string, statusCode int, rsp http.ResponseWriter) {
	logger := contexthelper.LoggerFromContext(ctx)

	errObj := tokenErrorResponse{
		Error:       er,
		Description: description,
	}

	rsp.Header().Add("Content-Type", "application/json;charset=UTF-8")
	cacheAge := strconv.FormatFloat(endpoints.authConfig.accessTokenTTL.Seconds(), 'f', 0, 64)
	rsp.Header().Add("Cache-Control", "max-age="+cacheAge)

	rsp.WriteHeader(statusCode)

	jsonBytes, err := json.Marshal(errObj)
	if err != nil {
		logger.Error("Error serializing Token error response JSON",
			zap.Error(err))
		rsp.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = rsp.Write(jsonBytes)
	if err != nil {
		logger.Error("Error writing Token error response body",
			zap.Error(err))
		rsp.WriteHeader(http.StatusInternalServerError)
		return
	}
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Refreshtoken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (endpoints *WebEndpoints) writeTokenResponse(ctx context.Context, accessToken []byte, accessExpiry time.Duration, refreshToken []byte, scope string, rsp http.ResponseWriter) {
	logger := contexthelper.LoggerFromContext(ctx)
	logger.Debug(string(accessToken))

	responseObj := tokenResponse{
		AccessToken:  string(accessToken),
		TokenType:    "Bearer",
		ExpiresIn:    int(accessExpiry.Seconds()),
		Refreshtoken: string(refreshToken),
		Scope:        scope,
	}

	rsp.Header().Set("Content-Type", "application/json;charset=UTF-8")

	rsp.WriteHeader(http.StatusOK)

	responseJSON, err := json.Marshal(responseObj)
	if err != nil {
		rsp.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = rsp.Write(responseJSON)
	if err != nil {
		rsp.WriteHeader(http.StatusInternalServerError)
		return
	}
}
