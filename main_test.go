package umbrella

import (
	"context"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/ory/dockertest/v3"
)

// Global vars used across all the tests
var dbUser = "goumbrellatest"
var dbPass = "secret"
var dbName = "goumbrella"
var dbConn *sql.DB

var dockerPool *dockertest.Pool
var dockerResource *dockertest.Resource

var httpPort = "32777"
var httpCancelCtx context.CancelFunc
var httpURI = "/v1/umbrella/"
var httpURI2 = "/v1/restricted_stuff/"

var testEmail = "code@forthcoming.io"
var testPassword = "T0ugh3rPassw0rd444!"

var sessionToken = ""

var testUmbrella *Umbrella

func TestMain(m *testing.M) {
	createDocker()
	createUmbrella()
	createHTTPServer()

	code := m.Run()
	removeDocker()
	os.Exit(code)
}

func createDocker() {
	var err error
	dockerPool, err = dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}
	dockerResource, err = dockerPool.Run("postgres", "13", []string{"POSTGRES_PASSWORD=" + dbPass, "POSTGRES_USER=" + dbUser, "POSTGRES_DB=" + dbName})
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}
	if err = dockerPool.Retry(func() error {
		var err error
		dbConn, err = sql.Open("postgres", fmt.Sprintf("host=localhost user=%s password=%s port=%s dbname=%s sslmode=disable", dbUser, dbPass, dockerResource.GetPort("5432/tcp"), dbName))
		if err != nil {
			return err
		}
		return dbConn.Ping()
	}); err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}
}

func createUmbrella() {
	testUmbrella = NewUmbrella(dbConn, "gen64_", &JWTConfig{
		Key:               "someSecretKey--.",
		Issuer:            "forthcoming.io",
		ExpirationMinutes: 1,
	})
	err := testUmbrella.CreateDBTables()
	if err != nil {
		log.Fatalf("Failed to create DB tables")
	}
}

func getRestrictedStuffHTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := testUmbrella.GetUserIDFromRequest(r)
		if userID != 0 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
		w.Write([]byte(strconv.FormatInt(userID, 10)))
	})
}

func createHTTPServer() {
	var ctx context.Context
	ctx, httpCancelCtx = context.WithCancel(context.Background())
	go func(ctx context.Context) {
		go func() {
			http.Handle(httpURI, testUmbrella.GetHTTPHandler(httpURI))
			http.Handle(httpURI2, testUmbrella.GetHTTPHandlerWrapper(getRestrictedStuffHTTPHandler()))
			http.ListenAndServe(":"+httpPort, nil)
		}()
	}(ctx)
	time.Sleep(2 * time.Second)
}

func removeDocker() {
	dockerPool.Purge(dockerResource)
}

func makeRequest(method string, wrapped bool, additionalURI string, data string, status int, t *testing.T) []byte {
	uri := httpURI
	if wrapped {
		uri = httpURI2
	}

	req, err := http.NewRequest(method, "http://localhost:"+httpPort+uri+additionalURI, strings.NewReader(data))
	if err != nil {
		t.Fatalf("failed to make a request")
	}
	if method == "POST" {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	c := &http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("failed to make a request")
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body")
	}
	if resp.StatusCode != status {
		log.Print(string(b))
		t.Fatalf("request returned wrong status code, wanted %d, got %d", status, resp.StatusCode)
	}

	return b
}

func getUserByEmail(email string) (int64, string, string, string, int64, error) {
	var id, flags int64
	var email2, password, activationKey string
	err := dbConn.QueryRow(fmt.Sprintf("SELECT user_id, email, password, email_activation_key, user_flags FROM gen64_users WHERE email = '%s'", email)).Scan(&id, &email2, &password, &activationKey, &flags)
	return id, email2, password, activationKey, flags, err
}

func getSessionByID(id int64) (int64, string, int64, int64, error) {
	var flags, expiresAt, userID int64
	var key2 string
	err := dbConn.QueryRow(fmt.Sprintf("SELECT session_flags, key, expires_at, user_id FROM gen64_sessions WHERE session_id = %d", id)).Scan(&flags, &key2, &expiresAt, &userID)
	return flags, key2, expiresAt, userID, err
}
