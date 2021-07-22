package umbrella

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func TestRegisterHTTPHandlerWithInvalidInput(t *testing.T) {
	r := NewHTTPResponse(0, "")

	data := url.Values{}
	data.Set("invalidfield1", "somevalue")
	data.Set("invalidfield2", "somevalue2")
	b := makeRequest("POST", false, "register", data.Encode(), http.StatusBadRequest, t)
	err := json.Unmarshal(b, &r)
	if err != nil {
		t.Fatalf("POST method on register endpoint returned wrong json output, error marshaling: %s", err.Error())
	}
	if r.ErrText != "invalid_email" {
		t.Fatalf("POST method on register did not return invalid_email")
	}

	data = url.Values{}
	data.Set("email", "code@forthcoming.io")
	b = makeRequest("POST", false, "register", data.Encode(), http.StatusBadRequest, t)
	err = json.Unmarshal(b, &r)
	if err != nil {
		t.Fatalf("POST method on register endpoint returned wrong json output, error marshaling: %s", err.Error())
	}
	if r.ErrText != "invalid_or_weak_password" {
		t.Fatalf("POST method on register did not return invalid_or_weak_password")
	}

	data = url.Values{}
	data.Set("email", "code@forthcoming.io")
	data.Set("password", "weak")
	b = makeRequest("POST", false, "register", data.Encode(), http.StatusBadRequest, t)
	err = json.Unmarshal(b, &r)
	if err != nil {
		t.Fatalf("POST method on register endpoint returned wrong json output, error marshaling: %s", err.Error())
	}
	if r.ErrText != "invalid_or_weak_password" {
		t.Fatalf("POST method on register did not return invalid_or_weak_password")
	}
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
	b := makeRequest("GET", true, "", "", http.StatusOK, t)
	if string(b) != "123" {
		t.Fatalf("Invalid output from HTTP request to wrapped endpoint")
	}
}
