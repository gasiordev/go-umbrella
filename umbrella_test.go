package umbrella

import (
	"net/http"
	"testing"
)

func TestHTTPHandler(t *testing.T) {
	b := makeRequest(false, http.StatusOK, t)
	if string(b) != "cool" {
		t.Fatalf("Invalid output from HTTP request")
	}
}

func TestHTTPHandlerWrapper(t *testing.T) {
	b := makeRequest(true, http.StatusOK, t)
	if string(b) != "123" {
		t.Fatalf("Invalid output from HTTP request to wrapped endpoint")
	}
}
