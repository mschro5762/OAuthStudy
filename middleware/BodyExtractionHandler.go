package middleware

import (
	"io"
	"io/ioutil"
	"net/http"

	"github.com/mschro5762/OAuthStudy/contexthelper"

	"go.uber.org/zap"
)

// HTTPHandlerWithBodyFunc An HTTP method type that takes a body
type HTTPHandlerWithBodyFunc func([]byte, http.ResponseWriter, *http.Request)

// BodyExtractionHandler Middleware that extracts a request body in a consistent and safe manner.
// As this necessarily breaks the http.Handler idiom, it must be the last middleware in the chain.
func BodyExtractionHandler(bodyHandler HTTPHandlerWithBodyFunc) http.Handler {
	fn := func(rsp http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		logger := contexthelper.LoggerFromContext(ctx)

		if bodyHandler == nil {
			panic("Nil argument bodyHandler")
		}

		body, err := extractBody(req)
		if err != nil {
			logger.Error("RegisterClientEndpoint: Error reading request body",
				zap.Error(err))
			rsp.WriteHeader(http.StatusUnprocessableEntity)
			return
		}

		bodyHandler(body, rsp, req)
	}

	return http.HandlerFunc(fn)
}

func extractBody(req *http.Request) ([]byte, error) {
	// Read the body with an acceptable size limit
	body, err := ioutil.ReadAll(io.LimitReader(req.Body, 1048576))
	if err != nil {
		return nil, err
	}
	if err := req.Body.Close(); err != nil {
		return nil, err
	}

	return body, nil
}
