package umbrella

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gen64/go-crud"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const FlagUserActive = 1
const FlagUserEmailConfirmed = 2
const FlagUserAllowLogin = 4

const FlagSessionActive = 1
const FlagSessionLoggedOut = 2

type Umbrella struct {
	dbConn           *sql.DB
	dbTblPrefix      string
	goCRUDController *crud.Controller
	jwtConfig        *JWTConfig
}

type JWTConfig struct {
	Key               string
	ExpirationMinutes int
	Issuer            string
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
	Key       string `json:"key" crud:"uniq lenmin:32 lenmax:2000"`
	ExpiresAt int64  `json:"expires_at"`
	UserID    int    `json:"user_id" crud:"req"`
}

type customClaims struct {
	jwt.StandardClaims
	SID string
}

func NewUmbrella(dbConn *sql.DB, tblPrefix string, jwtConfig *JWTConfig) *Umbrella {
	u := &Umbrella{
		dbConn:           dbConn,
		dbTblPrefix:      tblPrefix,
		goCRUDController: crud.NewController(dbConn, tblPrefix),
		jwtConfig:        jwtConfig,
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
	if r.Method != http.MethodPost {
		u.writeErrText(w, http.StatusBadRequest, "invalid_request")
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	if !u.isValidEmail(email) {
		u.writeErrText(w, http.StatusBadRequest, "invalid_email")
		return
	}
	if !u.isValidPassword(password) {
		u.writeErrText(w, http.StatusBadRequest, "invalid_or_weak_password")
		return
	}

	ok, err := u.isEmailExists(email)
	if err != nil {
		u.writeErrText(w, http.StatusInternalServerError, "database_error")
		return
	}
	if ok {
		u.writeErrText(w, http.StatusOK, "email_registered")
		return
	}

	_, err2 := u.createUser(email, password)
	if err2 != nil {
		u.writeErrText(w, http.StatusInternalServerError, "create_error")
		return
	}

	u.writeOK(w, http.StatusCreated, map[string]interface{}{})
}

func (u Umbrella) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		u.writeErrText(w, http.StatusBadRequest, "invalid_request")
		return
	}
	key := r.FormValue("key")
	if !u.isValidActivationKey(key) {
		u.writeErrText(w, http.StatusBadRequest, "invalid_key")
		return
	}

	err2 := u.confirmEmail(key)
	if err2 != nil {
		var errUmb *ErrUmbrella
		if errors.As(err2, &errUmb) {
			if errUmb.Op == "NoRow" || errUmb.Op == "UserInactive" {
				u.writeErrText(w, http.StatusNotFound, "invalid_key")
			} else if errUmb.Op == "GetFromDB" {
				u.writeErrText(w, http.StatusInternalServerError, "database_error")
			} else {
				u.writeErrText(w, http.StatusInternalServerError, "confirm_error")
			}
		}
		return
	}

	u.writeOK(w, http.StatusOK, map[string]interface{}{})
}

func (u Umbrella) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		u.writeErrText(w, http.StatusBadRequest, "invalid_request")
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	if !u.isValidEmail(email) {
		u.writeErrText(w, http.StatusBadRequest, "invalid_credentials")
		return
	}
	if password == "" {
		u.writeErrText(w, http.StatusBadRequest, "invalid_credentials")
		return
	}

	token, expiresAt, err := u.login(email, password)
	if err != nil {
		var errUmb *ErrUmbrella
		if errors.As(err, &errUmb) {
			if errUmb.Op == "NoRow" || errUmb.Op == "UserInactive" || errUmb.Op == "InvalidPassword" {
				u.writeErrText(w, http.StatusNotFound, "invalid_credentials")
			} else if errUmb.Op == "GetFromDB" {
				u.writeErrText(w, http.StatusInternalServerError, "database_error")
			} else {
				u.writeErrText(w, http.StatusInternalServerError, "login_error")
			}
		}
		return
	}

	u.writeOK(w, http.StatusOK, map[string]interface{}{
		"token":      token,
		"expires_at": expiresAt,
	})
}

func (u Umbrella) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		u.writeErrText(w, http.StatusBadRequest, "invalid_request")
		return
	}

	token := r.FormValue("token")
	if !u.isValidToken(token) {
		u.writeErrText(w, http.StatusBadRequest, "invalid_token")
		return
	}

	refresh := false
	if r.FormValue("refresh") == "1" {
		refresh = true
	}

	token2, expiresAt, err := u.check(token, refresh)
	if err != nil {
		var errUmb *ErrUmbrella
		if errors.As(err, &errUmb) {
			if errUmb.Op == "InvalidToken" || errUmb.Op == "UserInactive" || errUmb.Op == "Expired" || errUmb.Op == "InvalidSession" || errUmb.Op == "InvalidUser" || errUmb.Op == "ParseToken" {
				u.writeErrText(w, http.StatusNotFound, "invalid_credentials")
			} else if errUmb.Op == "GetFromDB" {
				u.writeErrText(w, http.StatusInternalServerError, "database_error")
			} else {
				u.writeErrText(w, http.StatusInternalServerError, "check_error")
			}
		}
		return
	}

	u.writeOK(w, http.StatusOK, map[string]interface{}{
		"token":      token2,
		"expires_at": expiresAt,
		"refreshed":  refresh,
	})
}

func (u Umbrella) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		u.writeErrText(w, http.StatusBadRequest, "invalid_request")
		return
	}
	token := r.FormValue("token")
	if token == "" {
		u.writeErrText(w, http.StatusBadRequest, "invalid_token")
		return
	}

	err := u.logout(token)
	if err != nil {
		var errUmb *ErrUmbrella
		if errors.As(err, &errUmb) {
			if errUmb.Op == "InvalidToken" || errUmb.Op == "Expired" || errUmb.Op == "ParseToken" || errUmb.Op == "InvalidSession" {
				u.writeErrText(w, http.StatusNotFound, "invalid_credentials")
			} else if errUmb.Op == "GetFromDB" {
				u.writeErrText(w, http.StatusInternalServerError, "database_error")
			} else {
				u.writeErrText(w, http.StatusInternalServerError, "login_error")
			}
		}
		return
	}
	u.writeOK(w, http.StatusOK, map[string]interface{}{})
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

func (u Umbrella) createUser(email string, pass string) (string, *ErrUmbrella) {
	passEncrypted, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return "", &ErrUmbrella{
			Op:  "GeneratePassword",
			Err: err,
		}
	}

	key := uuid.New().String()

	user := &User{}
	user.Email = email
	user.Password = base64.StdEncoding.EncodeToString(passEncrypted)
	// TODO: We need to have name in the registration request
	user.Name = "Unknown"
	user.EmailActivationKey = key
	user.Flags = FlagUserActive

	errCrud := u.goCRUDController.SaveToDB(user)
	if errCrud != nil {
		return "", &ErrUmbrella{
			Op:  "SaveToDB",
			Err: err,
		}
	}

	return key, nil
}

func (u Umbrella) confirmEmail(key string) *ErrUmbrella {
	users, err := u.goCRUDController.GetFromDB(func() interface{} { return &User{} }, []string{"id", "asc"}, 1, 0, map[string]interface{}{
		"EmailActivationKey": key,
	})
	if err != nil {
		return &ErrUmbrella{
			Op:  "GetFromDB",
			Err: err,
		}
	}
	if len(users) == 0 {
		return &ErrUmbrella{
			Op:  "NoRow",
			Err: err,
		}
	}
	if users[0].(*User).Flags&FlagUserActive == 0 {
		return &ErrUmbrella{
			Op:  "UserInactive",
			Err: err,
		}
	}

	users[0].(*User).Flags = users[0].(*User).Flags | FlagUserEmailConfirmed | FlagUserAllowLogin
	users[0].(*User).EmailActivationKey = ""
	errCrud := u.goCRUDController.SaveToDB(users[0])
	if errCrud != nil {
		return &ErrUmbrella{
			Op:  "SaveToDB",
			Err: err,
		}
	}

	return nil
}

func (u Umbrella) login(email string, password string) (string, int64, *ErrUmbrella) {
	users, errCrud := u.goCRUDController.GetFromDB(func() interface{} { return &User{} }, []string{"id", "asc"}, 1, 0, map[string]interface{}{
		"Email": email,
	})
	if errCrud != nil {
		return "", 0, &ErrUmbrella{
			Op:  "GetFromDB",
			Err: errCrud,
		}
	}
	if len(users) == 0 {
		return "", 0, &ErrUmbrella{
			Op:  "NoRow",
			Err: errCrud,
		}
	}
	if users[0].(*User).Flags&FlagUserActive == 0 || users[0].(*User).Flags&FlagUserAllowLogin == 0 {
		return "", 0, &ErrUmbrella{
			Op:  "UserInactive",
			Err: errCrud,
		}
	}

	passwordInDBDecoded, err := base64.StdEncoding.DecodeString(users[0].(*User).Password)
	if err != nil {
		return "", 0, &ErrUmbrella{
			Op:  "InvalidPassword",
			Err: err,
		}
	}
	err = bcrypt.CompareHashAndPassword(passwordInDBDecoded, []byte(password))
	if err != nil {
		return "", 0, &ErrUmbrella{
			Op:  "InvalidPassword",
			Err: err,
		}
	}

	sUUID := uuid.New().String()
	token, expiresAt, err := u.createToken(sUUID)
	if err != nil {
		return "", 0, &ErrUmbrella{
			Op:  "CreateToken",
			Err: err,
		}
	}

	userID := users[0].(*User).ID
	sess := &Session{
		Key:       sUUID,
		ExpiresAt: expiresAt,
		UserID:    userID,
		Flags:     FlagSessionActive,
	}
	errCrud = u.goCRUDController.SaveToDB(sess)
	if errCrud != nil {
		return "", 0, &ErrUmbrella{
			Op:  "SaveToDB",
			Err: errCrud,
		}
	}

	return token, expiresAt, nil
}

func (u Umbrella) logout(token string) *ErrUmbrella {
	sID, errUmbrella := u.parseTokenWithCheck(token)
	if errUmbrella != nil {
		return errUmbrella
	}

	sessions, err := u.goCRUDController.GetFromDB(func() interface{} { return &Session{} }, []string{"id", "asc"}, 1, 0, map[string]interface{}{
		"Key": sID,
	})
	if err != nil {
		return &ErrUmbrella{
			Op:  "GetFromDB",
			Err: err,
		}
	}
	if len(sessions) == 0 {
		return &ErrUmbrella{
			Op:  "NoRow",
			Err: err,
		}
	}

	if sessions[0].(*Session).Flags&FlagSessionActive == 0 || sessions[0].(*Session).Flags&FlagSessionLoggedOut > 0 {
		return &ErrUmbrella{
			Op:  "InvalidSession",
			Err: err,
		}
	}

	sessions[0].(*Session).Flags = sessions[0].(*Session).Flags | FlagSessionLoggedOut
	if sessions[0].(*Session).Flags&FlagSessionActive > 0 {
		sessions[0].(*Session).Flags -= FlagSessionActive
	}
	errCrud := u.goCRUDController.SaveToDB(sessions[0])
	if errCrud != nil {
		return &ErrUmbrella{
			Op:  "SaveToDB",
			Err: err,
		}
	}

	return nil
}

func (u Umbrella) check(token string, refresh bool) (string, int64, *ErrUmbrella) {
	sID, errUmbrella := u.parseTokenWithCheck(token)
	if errUmbrella != nil {
		return "", 0, errUmbrella
	}
	sessions, err := u.goCRUDController.GetFromDB(func() interface{} { return &Session{} }, []string{"id", "asc"}, 1, 0, map[string]interface{}{
		"Key": sID,
	})
	if err != nil {
		return "", 0, &ErrUmbrella{
			Op:  "GetFromDB",
			Err: err,
		}
	}
	if len(sessions) == 0 {
		return "", 0, &ErrUmbrella{
			Op:  "InvalidSession",
			Err: err,
		}
	}
	if sessions[0].(*Session).Flags&FlagSessionActive == 0 || sessions[0].(*Session).Flags&FlagSessionLoggedOut > 0 {
		return "", 0, &ErrUmbrella{
			Op:  "InvalidSession",
			Err: err,
		}
	}

	user := &User{}
	errCrud := u.goCRUDController.SetFromDB(user, strconv.Itoa(sessions[0].(*Session).UserID))
	if errCrud != nil {
		return "", 0, &ErrUmbrella{
			Op:  "GetFromDB",
			Err: errCrud,
		}
	}
	if user.ID == 0 {
		return "", 0, &ErrUmbrella{
			Op:  "InvalidUser",
			Err: errCrud,
		}
	}
	if user.Flags&FlagUserActive == 0 || user.Flags&FlagUserAllowLogin == 0 {
		return "", 0, &ErrUmbrella{
			Op:  "UserInactive",
			Err: errCrud,
		}
	}

	if refresh {
		token2, expiresAt, err := u.createToken(sID)
		if err != nil {
			return "", 0, &ErrUmbrella{
				Op:  "CreateToken",
				Err: err,
			}
		}

		sessions[0].(*Session).ExpiresAt = expiresAt
		errCrud = u.goCRUDController.SaveToDB(sessions[0])
		if errCrud != nil {
			return "", 0, &ErrUmbrella{
				Op:  "SaveToDB",
				Err: err,
			}
		}
		return token2, expiresAt, nil
	}

	return token, 0, nil
}

func (u Umbrella) parseTokenWithCheck(token string) (string, *ErrUmbrella) {
	sID, expired, err := u.parseToken(token)
	if err != nil {
		return "", &ErrUmbrella{
			Op:  "ParseToken",
			Err: err,
		}
	}

	if expired {
		return "", &ErrUmbrella{
			Op:  "Expired",
			Err: err,
		}
	}

	if !u.isValidSessionID(sID) {
		return "", &ErrUmbrella{
			Op:  "InvalidSession",
			Err: err,
		}
	}

	return sID, nil
}

func (u Umbrella) createToken(sid string) (string, int64, error) {
	cc := customClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Duration(u.jwtConfig.ExpirationMinutes) * time.Minute).Unix(),
			Issuer:    u.jwtConfig.Issuer,
		},
		SID: sid,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cc)
	st, err := token.SignedString([]byte(u.jwtConfig.Key))
	if err != nil {
		return "", 0, fmt.Errorf("couldn't sign token in createToken %w", err)
	}
	return st, cc.StandardClaims.ExpiresAt, nil
}

func (u Umbrella) parseToken(st string) (string, bool, error) {
	token, err := jwt.ParseWithClaims(st, &customClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("parseWithClaims different algorithms used")
		}
		return []byte(u.jwtConfig.Key), nil
	})

	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorExpired != 0 {
			return token.Claims.(*customClaims).SID, true, nil
		}
	}

	if err != nil {
		return "", false, fmt.Errorf("couldn't ParseWithClaims in parseToken %w", err)
	}

	if token.Valid {
		return token.Claims.(*customClaims).SID, false, nil
	}

	return "", false, fmt.Errorf("token not valid in parseToken")
}

func (u Umbrella) isEmailExists(e string) (bool, *crud.ErrController) {
	users, err := u.goCRUDController.GetFromDB(func() interface{} { return &User{} }, []string{"id", "asc"}, 1, 0, map[string]interface{}{
		"Email": e,
	})
	if err != nil {
		return false, err
	}
	if len(users) > 0 {
		return true, nil
	}
	return false, nil
}

func (u Umbrella) isValidEmail(s string) bool {
	var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	return emailRegex.MatchString(s)
}

func (u Umbrella) isValidPassword(s string) bool {
	if len(s) < 12 {
		return false
	}
	return true
}

func (u Umbrella) isValidActivationKey(s string) bool {
	var keyRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,255}$`)
	return keyRegex.MatchString(s)
}

func (u Umbrella) isValidSessionID(s string) bool {
	var keyRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{1,255}$`)
	return keyRegex.MatchString(s)
}

func (u Umbrella) isValidToken(s string) bool {
	var keyRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\$]+$`)
	return keyRegex.MatchString(s)
}
