package umbrella

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"golang.org/x/crypto/bcrypt"
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
}

func TestRegisterHTTPHandlerWithInvalidPassword(t *testing.T) {
	r := NewHTTPResponse(0, "")

	data := url.Values{}
	data.Set("email", "code@forthcoming.io")
	data.Set("password", "weak")
	b := makeRequest("POST", false, "register", data.Encode(), http.StatusBadRequest, t)
	err := json.Unmarshal(b, &r)
	if err != nil {
		t.Fatalf("POST method on register endpoint returned wrong json output, error marshaling: %s", err.Error())
	}
	if r.ErrText != "invalid_or_weak_password" {
		t.Fatalf("POST method on register did not return invalid_or_weak_password")
	}
}

func TestRegisterHTTPHandlerWithNonExistingEmail(t *testing.T) {
	r := NewHTTPResponse(0, "")

	data := url.Values{}
	data.Set("email", "code@forthcoming.io")
	data.Set("password", "T0ugh3rPassw0rd444!")
	b := makeRequest("POST", false, "register", data.Encode(), http.StatusCreated, t)
	err := json.Unmarshal(b, &r)
	if err != nil {
		t.Fatalf("POST method on register endpoint returned wrong json output, error marshaling: %s", err.Error())
	}
	if r.ErrText != "" {
		t.Fatalf("POST method on register returned error text")
	}
	if r.OK != 1 {
		t.Fatalf("POST method on register did not return ok for valid input and non-existing email")
	}

	id, email, password, err := getEmailPasswordByEmail("code@forthcoming.io")
	if err != nil {
		t.Fatalf("POST method on register - failed to check if record added in the database")
	}
	if id == 0 || email != "code@forthcoming.io" {
		t.Fatalf("POST method on register failed to add record")
	}
	passwordInDBDecoded, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		t.Fatalf("POST method on register - failed to decode the password from the database")
	}
	err = bcrypt.CompareHashAndPassword(passwordInDBDecoded, []byte("T0ugh3rPassw0rd444!"))
	if err != nil {
		t.Fatalf("POST method on register failed to insert password to the database properly")
	}
}

func TestRegisterHTTPHandlerWithExistingEmail(t *testing.T) {
	r := NewHTTPResponse(0, "")

	data := url.Values{}
	data.Set("email", "code@forthcoming.io")
	data.Set("password", "T0ugh3rPassw0rd444!")
	b := makeRequest("POST", false, "register", data.Encode(), http.StatusOK, t)
	err := json.Unmarshal(b, &r)
	if err != nil {
		t.Fatalf("POST method on register endpoint returned wrong json output, error marshaling: %s", err.Error())
	}
	if r.ErrText != "email_registered" {
		t.Fatalf("POST method on register with existing email did not return email_registered error text")
	}
	if r.OK != 0 {
		t.Fatalf("POST method on register returned ok for valid input and existing email")
	}
}

func TestConfirmHTTPHandlerWithInvalidInput(t *testing.T) {
	r := NewHTTPResponse(0, "")

	data := url.Values{}
	data.Set("invalidfield1", "somevalue")
	data.Set("invalidfield2", "somevalue2")
	b := makeRequest("POST", false, "confirm", data.Encode(), http.StatusBadRequest, t)
	err := json.Unmarshal(b, &r)
	if err != nil {
		t.Fatalf("POST method on confirm endpoint returned wrong json output, error marshaling: %s", err.Error())
	}
	if r.ErrText != "invalid_key" {
		t.Fatalf("POST method on register did not return invalid_key")
	}

	data = url.Values{}
	data.Set("key", `%%%(((%%%))))`)
	b = makeRequest("POST", false, "confirm", data.Encode(), http.StatusBadRequest, t)
	err = json.Unmarshal(b, &r)
	if err != nil {
		t.Fatalf("POST method on confirm endpoint returned wrong json output, error marshaling: %s", err.Error())
	}
	if r.ErrText != "invalid_key" {
		t.Fatalf("POST method on register did not return invalid_key")
	}
}

func TestConfirmHTTPHandlerWithValidKey(t *testing.T) {
}

func TestConfirmHTTPHandlerWithInvalidKey(t *testing.T) {
	r := NewHTTPResponse(0, "")

	data := url.Values{}
	data.Set("key", "nonexistingkey")
	b := makeRequest("POST", false, "confirm", data.Encode(), http.StatusNotFound, t)
	err := json.Unmarshal(b, &r)
	if err != nil {
		t.Fatalf("POST method on confirm endpoint returned wrong json output, error marshaling: %s", err.Error())
	}
	if r.ErrText != "invalid_key" {
		t.Fatalf("POST method on register did not return invalid_key")
	}
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
