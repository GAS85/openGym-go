package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// ---------- db model ----------

type User struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Created      string `json:"created,omitempty"`
	Disabled     bool   `json:"disabled,omitempty"`
	Admin        bool   `json:"admin,omitempty"`
	InvitedBy    string `json:"invitedBy,omitempty"`
	SV           int    `json:"sv,omitempty"`
	LastReminder string `json:"lastReminder,omitempty"`
}

type Cred struct {
	ID         string   `json:"id"` // base64url credential ID
	UserID     string   `json:"userId"`
	PublicKey  string   `json:"publicKey"` // base64url
	Counter    uint32   `json:"counter"`
	Transports []string `json:"transports"`
}

type PushKeys struct {
	P256dh string `json:"p256dh"`
	Auth   string `json:"auth"`
}

type Sub struct {
	UserID   string   `json:"userId"`
	Endpoint string   `json:"endpoint"`
	Keys     PushKeys `json:"keys"`
	Created  string   `json:"created"`
}

type Invite struct {
	Code      string `json:"code"`
	Note      string `json:"note,omitempty"`
	CreatedBy string `json:"createdBy"`
	Created   string `json:"created"`
	UsedBy    string `json:"usedBy,omitempty"`
	UsedAt    string `json:"usedAt,omitempty"`
	Revoked   bool   `json:"revoked,omitempty"`
}

type DB struct {
	Users   []*User   `json:"users"`
	Creds   []*Cred   `json:"creds"`
	Subs    []*Sub    `json:"subs"`
	Invites []*Invite `json:"invites"`
}

// dbMu guards every read/write of db below. The original JS is single-threaded so it never
// needed this; Go handles requests concurrently, so all access to db must go through with(Read|Write)Lock helpers.
var (
	dbMu sync.RWMutex
	db   = &DB{}
)

func loadDB() {
	data, err := os.ReadFile(dbFile)
	if err != nil {
		return // fresh instance — db stays at zero value
	}
	_ = json.Unmarshal(data, db) // malformed db.json — start empty, same as the JS try/catch
}

func saveDBLocked() {
	data, _ := json.MarshalIndent(db, "", "  ")
	atomicWrite(dbFile, data)
}

func atomicWrite(file string, content []byte) {
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, file)
}

var stateFileSanitize = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

func stateFilePath(uid string) string {
	return filepath.Join(dataDir, "state-"+stateFileSanitize.ReplaceAllString(uid, "")+".json")
}

// readState loads a user's free-form workout state blob. It's client-defined JSON we mostly
// pass through untouched, so it's kept as a generic map rather than a fixed struct.
func readState(uid string) map[string]interface{} {
	data, err := os.ReadFile(stateFilePath(uid))
	if err != nil {
		return nil
	}
	var s map[string]interface{}
	if err := json.Unmarshal(data, &s); err != nil {
		return nil
	}
	return s
}

func isAdmin(u *User) bool {
	if u == nil {
		return false
	}
	if u.Admin {
		return true
	}
	for _, id := range adminUIDs {
		if id == u.ID {
			return true
		}
	}
	return false
}

func findUser(id string) *User {
	for _, u := range db.Users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

func findCredByID(id string) *Cred {
	for _, c := range db.Creds {
		if c.ID == id {
			return c
		}
	}
	return nil
}
