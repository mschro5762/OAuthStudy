package middleware

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/contexthelper"
)

func TestBodyExtractionHandler_PassesBody(t *testing.T) {
	expectedBody := []byte{0x23, 0x95, 0x01, 0x00}
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
		Body:   ioutil.NopCloser(bytes.NewReader(expectedBody)),
	}
	logger := zap.NewNop()
	req = req.WithContext(contexthelper.NewContextWithLogger(logger))
	rsp := httptest.NewRecorder()

	var actualBody []byte
	fn := func(body []byte, rsp http.ResponseWriter, req *http.Request) {
		actualBody = body
	}

	handler := BodyExtractionHandler(fn)

	handler.ServeHTTP(rsp, req)

	if len(actualBody) != len(expectedBody) {
		t.Fail()
	}
	for i := range expectedBody {
		if expectedBody[i] != actualBody[i] {
			t.Fail()
		}
	}
}

func TestBodyExtractionHandler_PassesResposne(t *testing.T) {
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
		Body:   http.NoBody,
	}
	logger := zap.NewNop()
	req = req.WithContext(contexthelper.NewContextWithLogger(logger))
	expectedRsp := httptest.NewRecorder()

	var actualRsp http.ResponseWriter
	fn := func(body []byte, rsp http.ResponseWriter, req *http.Request) {
		actualRsp = rsp
	}

	handler := BodyExtractionHandler(fn)

	handler.ServeHTTP(expectedRsp, req)

	if expectedRsp != actualRsp {
		t.Fail()
	}
}

func TestBodyExtractionHandler_PassesRequest(t *testing.T) {
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/"},
		Body:   http.NoBody,
	}
	logger := zap.NewNop()
	expectedReq := req.WithContext(contexthelper.NewContextWithLogger(logger))
	rsp := httptest.NewRecorder()

	var actualReq *http.Request
	fn := func(body []byte, rsp http.ResponseWriter, req *http.Request) {
		actualReq = req
	}

	handler := BodyExtractionHandler(fn)

	handler.ServeHTTP(rsp, expectedReq)

	if expectedReq != actualReq {
		t.Fail()
	}
}

func TestMethodMuxHandler_ServeHTTP_BodyGTMax_Errors(t *testing.T) {
	maxBodySize := 1048576
	body := make([]byte, maxBodySize+1)
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Path: "/"},
		Body:   ioutil.NopCloser(bytes.NewReader(body)),
	}
	logger := zap.NewNop()
	req = req.WithContext(contexthelper.NewContextWithLogger(logger))
	rsp := httptest.NewRecorder()

	actualBodySize := 0
	fn := func(body []byte, rsp http.ResponseWriter, req *http.Request) {
		actualBodySize = len(body)
	}
	handler := BodyExtractionHandler(fn)

	handler.ServeHTTP(rsp, req)

	if maxBodySize != actualBodySize {
		t.Fail()
	}
}
