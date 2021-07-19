package umbrella

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/gen64/go-crud"
)

type Umbrella struct {
	dbConn           *sql.DB
	dbTblPrefix      string
	goCRUDController *crud.Controller
}

func NewUmbrella(dbConn *sql.DB, tblPrefix string) *Umbrella {
	u := &Umbrella{
		dbConn:      dbConn,
		dbTblPrefix: tblPrefix,
	}
	return u
}

func (u Umbrella) GetHTTPHandler(uri string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`cool`))
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
