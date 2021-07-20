package umbrella

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gen64/go-crud"
)

type Umbrella struct {
	dbConn           *sql.DB
	dbTblPrefix      string
	goCRUDController *crud.Controller
}

type User struct {
	ID                 int    `json:"user_id"`
	Flags              int    `json:"flags"`
	Name               string `json:"name" crud:"req lenmin:2 lenmax:50"`
	Email              string `json:"email" crud:"req"`
	Password           string `json:"password"`
	EmailActivationKey string `json:"email_activation_key" crud:""`
	CreatedAt          int    `json:"created_at"`
	CreatedByUserID    int    `json:"created_by_user_id"`
}

type Session struct {
	ID        int    `json:"session_id"`
	Flags     int    `json:"flags"`
	Key       string `json:"key" crud:"uniq lenmin:32 lenmax:50"`
	ExpiresAt int    `json:"expires_at"`
	UserID    int    `json:"user_id" crud:"req"`
}

func NewUmbrella(dbConn *sql.DB, tblPrefix string) *Umbrella {
	u := &Umbrella{
		dbConn:           dbConn,
		dbTblPrefix:      tblPrefix,
		goCRUDController: crud.NewController(dbConn, tblPrefix),
	}
	return u
}

func (u Umbrella) CreateDBTables() *ErrUmbrella {
	user := &User{}
	session := &Session{}

	err := u.goCRUDController.CreateDBTables(user, session)
	if err != nil {
		return &ErrUmbrella{
			Op:  "CreateDBTables",
			Err: err,
		}
	}

	return nil
}

func (u Umbrella) GetHTTPHandler(uri string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uri := u.getURIFromRequest(r, uri)

		switch uri {
		case "register":
			u.handleRegister(w, r)
		case "confirm":
			u.handleConfirm(w, r)
		case "login":
			u.handleLogin(w, r)
		case "check":
			u.handleCheck(w, r)
		case "logout":
			u.handleLogout(w, r)
		default:
			u.writeErrText(w, http.StatusNotFound, "invalid_uri")
		}
	})
}

func (u Umbrella) GetHTTPHandlerWrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "UserID", int64(123))
		req := r.WithContext(ctx)
		next.ServeHTTP(w, req)
	})
}

func (u Umbrella) GetUserIDFromRequest(r *http.Request) int64 {
	v := r.Context().Value("UserID").(int64)
	return v
}

func (u Umbrella) getURIFromRequest(r *http.Request, uri string) string {
	uriPart := r.RequestURI[len(uri):]
	xs := strings.SplitN(uriPart, "?", 2)
	return xs[0]
}

func (u Umbrella) handleRegister(w http.ResponseWriter, r *http.Request) {
	u.writeOK(w, http.StatusOK, map[string]interface{}{
		"page": "register",
	})
}

func (u Umbrella) handleConfirm(w http.ResponseWriter, r *http.Request) {
	u.writeOK(w, http.StatusOK, map[string]interface{}{
		"page": "confirm",
	})
}

func (u Umbrella) handleLogin(w http.ResponseWriter, r *http.Request) {
	u.writeOK(w, http.StatusOK, map[string]interface{}{
		"page": "login",
	})
}

func (u Umbrella) handleCheck(w http.ResponseWriter, r *http.Request) {
	u.writeOK(w, http.StatusOK, map[string]interface{}{
		"page": "check",
	})
}

func (u Umbrella) handleLogout(w http.ResponseWriter, r *http.Request) {
	u.writeOK(w, http.StatusOK, map[string]interface{}{
		"page": "logout",
	})
}

func (u Umbrella) writeErrText(w http.ResponseWriter, status int, errText string) {
	r := NewHTTPResponse(0, errText)
	j, err := json.Marshal(r)
	w.WriteHeader(status)
	if err == nil {
		w.Write(j)
	}
}

func (u Umbrella) writeOK(w http.ResponseWriter, status int, data map[string]interface{}) {
	r := NewHTTPResponse(1, "")
	r.Data = data
	j, err := json.Marshal(r)
	w.WriteHeader(status)
	if err == nil {
		w.Write(j)
	}
}
