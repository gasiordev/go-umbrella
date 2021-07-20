package umbrella

import (
	"log"
	"net/http"
	"testing"
)

func TestHTTPHandler(t *testing.T) {
	b := makeRequest(false, "login", http.StatusOK, t)
	log.Print(string(b))

	b = makeRequest(false, "register", http.StatusOK, t)
	log.Print(string(b))
}

func TestRegisterHTTPHandlerWithInvalidInput(t *testing.T) {
}

func TestRegisterHTTPHandlerWithInvalidPassword(t *testing.T) {
}

func TestRegisterHTTPHandlerWithNonExistingEmail(t *testing.T) {
}

func TestRegisterHTTPHandlerWithExistingEmail(t *testing.T) {
}

func TestConfirmHTTPHandlerWithInvalidInput(t *testing.T) {
}

func TestConfirmHTTPHandlerWithValidKey(t *testing.T) {
}

func TestConfirmHTTPHandlerWithInvalidKey(t *testing.T) {
}

func TestLoginHTTPHandlerWithInvalidInput(t *testing.T) {
}

func TestLoginHTTPHandlerWithValidEmailAndPassword(t *testing.T) {
}

func TestLoginHTTPHandlerWithNonExistingEmail(t *testing.T) {
}

func TestLoginHTTPHandlerWithInvalidPassword(t *testing.T) {
}

func TestCheckHTTPHandlerWithInvalidInput(t *testing.T) {
}

func TestCheckHTTPHandlerWithValidToken(t *testing.T) {
}

func TestCheckHTTPHandlerWithInvalidToken(t *testing.T) {
}

func TestLogoutHTTPHandlerWithInvalidInput(t *testing.T) {
}

func TestLogoutHTTPHandlerWithValidToken(t *testing.T) {
}

func TestLogoutHTTPHandlerWithInvalidToken(t *testing.T) {
}

func TestHTTPHandlerWrapper(t *testing.T) {
	b := makeRequest(true, "", http.StatusOK, t)
	if string(b) != "123" {
		t.Fatalf("Invalid output from HTTP request to wrapped endpoint")
	}
}
