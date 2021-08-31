package umbrella

import (
	"fmt"

	"github.com/gen64/go-crud"
)

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

// GoCRUDUser is default implementation of UserInterface using go-crud
type GoCRUDUser struct {
	goCRUDController *crud.Controller
	user             *User
}

func (g *GoCRUDUser) CreateDBTable() error {
	user := &User{}
	err := g.goCRUDController.CreateDBTables(user)
	if err != nil {
		return err
	}
	return nil
}
func (g *GoCRUDUser) GetID() int {
	return g.user.ID
}
func (g *GoCRUDUser) GetEmail() string {
	return g.user.Email
}
func (g *GoCRUDUser) GetPassword() string {
	return g.user.Password
}
func (g *GoCRUDUser) GetEmailActivationKey() string {
	return g.user.EmailActivationKey
}
func (g *GoCRUDUser) GetFlags() int {
	return g.user.Flags
}
func (g *GoCRUDUser) GetName() string {
	return g.user.Name
}
func (g *GoCRUDUser) SetEmail(e string) {
	g.user.Email = e
}
func (g *GoCRUDUser) SetPassword(p string) {
	g.user.Password = p
}
func (g *GoCRUDUser) SetEmailActivationKey(k string) {
	g.user.EmailActivationKey = k
}
func (g *GoCRUDUser) SetFlags(flags int) {
	g.user.Flags = flags
}
func (g *GoCRUDUser) SetName(n string) {
	g.user.Name = n
}
func (g *GoCRUDUser) Save() error {
	errCrud := g.goCRUDController.SaveToDB(g.user)
	if errCrud != nil {
		return fmt.Errorf("Error in crud.SaveToDB: %w", errCrud)
	}
	return nil
}
func (g *GoCRUDUser) GetByID(id int) (bool, error) {
	users, errCrud := g.goCRUDController.GetFromDB(func() interface{} { return &User{} }, []string{"id", "asc"}, 1, 0, map[string]interface{}{
		"ID": id,
	})
	if errCrud != nil {
		return false, fmt.Errorf("Error in crud.GetFromDB: %w", errCrud)
	}
	if len(users) == 0 {
		return false, nil
	}

	g.user = users[0].(*User)
	return true, nil
}
func (g *GoCRUDUser) GetByEmail(email string) (bool, error) {
	users, errCrud := g.goCRUDController.GetFromDB(func() interface{} { return &User{} }, []string{"id", "asc"}, 1, 0, map[string]interface{}{
		"Email": email,
	})
	if errCrud != nil {
		return false, fmt.Errorf("Error in crud.GetFromDB: %w", errCrud)
	}
	if len(users) == 0 {
		return false, nil
	}

	g.user = users[0].(*User)
	return true, nil
}
func (g *GoCRUDUser) GetByEmailActivationKey(key string) (bool, error) {
	users, errCrud := g.goCRUDController.GetFromDB(func() interface{} { return &User{} }, []string{"id", "asc"}, 1, 0, map[string]interface{}{
		"EmailActivationKey": key,
	})
	if errCrud != nil {
		return false, fmt.Errorf("Error in crud.GetFromDB: %w", errCrud)
	}
	if len(users) == 0 {
		return false, nil
	}

	g.user = users[0].(*User)
	return true, nil
}

// GoCRUDSession is default implementation of SessionInterface using go-crud
type GoCRUDSession struct {
	goCRUDController *crud.Controller
	session          *Session
}

func (g *GoCRUDSession) CreateDBTable() error {
	session := &Session{}
	err := g.goCRUDController.CreateDBTables(session)
	if err != nil {
		return err
	}
	return nil
}
func (g *GoCRUDSession) GetFlags() int {
	return g.session.Flags
}
func (g *GoCRUDSession) GetKey() string {
	return g.session.Key
}
func (g *GoCRUDSession) GetExpiresAt() int64 {
	return g.session.ExpiresAt
}
func (g *GoCRUDSession) GetUserID() int {
	return g.session.UserID
}
func (g *GoCRUDSession) SetFlags(flags int) {
	g.session.Flags = flags
}
func (g *GoCRUDSession) SetKey(k string) {
	g.session.Key = k
}
func (g *GoCRUDSession) SetExpiresAt(exp int64) {
	g.session.ExpiresAt = exp
}
func (g *GoCRUDSession) SetUserID(i int) {
	g.session.UserID = i
}
func (g *GoCRUDSession) Save() error {
	errCrud := g.goCRUDController.SaveToDB(g.session)
	if errCrud != nil {
		return fmt.Errorf("Error in crud.SaveToDB: %w", errCrud)
	}
	return nil
}
func (g *GoCRUDSession) GetByKey(key string) (bool, error) {
	sessions, errCrud := g.goCRUDController.GetFromDB(func() interface{} { return &Session{} }, []string{"id", "asc"}, 1, 0, map[string]interface{}{
		"Key": key,
	})

	if errCrud != nil {
		return false, fmt.Errorf("Error in crud.GetFromDB: %w", errCrud)
	}
	if len(sessions) == 0 {
		return false, nil
	}

	g.session = sessions[0].(*Session)
	return true, nil
}
