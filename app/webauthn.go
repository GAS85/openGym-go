package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// ---------- webauthn.User adapter ----------

// waUser adapts our own User/Cred rows to the go-webauthn User interface. It's built fresh for
// each ceremony rather than stored, since it only ever needs to carry the credentials relevant
// to that ceremony.
type waUser struct {
	id          []byte
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.id }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }
func (u *waUser) WebAuthnIcon() string                       { return "" }

func credToWebauthn(c *Cred) (webauthn.Credential, error) {
	pk, err := base64.RawURLEncoding.DecodeString(c.PublicKey)
	if err != nil {
		return webauthn.Credential{}, err
	}
	id, err := base64.RawURLEncoding.DecodeString(c.ID)
	if err != nil {
		return webauthn.Credential{}, err
	}
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:        id,
		PublicKey: pk,
		Transport: transports,
	}, nil
}

// ---------- challenge store (in-memory, 5 min TTL) ----------

type challengeEntry struct {
	session webauthn.SessionData
	name    string
	uid     string
	code    string
	exp     time.Time
}

var (
	chMu       sync.Mutex
	challenges = map[string]*challengeEntry{}
)

func putChallenge(e *challengeEntry) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	cid := base64.RawURLEncoding.EncodeToString(b)
	e.exp = time.Now().Add(5 * time.Minute)
	chMu.Lock()
	challenges[cid] = e
	chMu.Unlock()
	return cid
}

func takeChallenge(cid string) *challengeEntry {
	chMu.Lock()
	e, ok := challenges[cid]
	delete(challenges, cid)
	chMu.Unlock()
	if !ok || time.Now().After(e.exp) {
		return nil
	}
	return e
}

func startChallengeReaper() {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			chMu.Lock()
			for k, v := range challenges {
				if now.After(v.exp) {
					delete(challenges, k)
				}
			}
			chMu.Unlock()
		}
	}()
}

// ---------- handlers ----------

func hRegisterOptions(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Code string `json:"code"`
	}
	if err := readBody(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(body.Name)
	if len(name) > 40 {
		name = name[:40]
	}
	if name == "" {
		writeJSON(w, 400, map[string]any{"error": "name required"})
		return
	}
	code := strings.ToUpper(strings.TrimSpace(body.Code))
	if inviteOnly {
		dbMu.RLock()
		valid := false
		for _, i := range db.Invites {
			if i.Code == code && i.UsedBy == "" && !i.Revoked {
				valid = true
				break
			}
		}
		dbMu.RUnlock()
		if !valid {
			writeJSON(w, 403, map[string]any{"error": "a valid invite code is required"})
			return
		}
	}

	uidBytes := make([]byte, 12)
	_, _ = rand.Read(uidBytes)
	uid := base64.RawURLEncoding.EncodeToString(uidBytes)

	u := &waUser{id: []byte(uid), name: name, displayName: name}
	creation, session, err := wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		}),
		webauthn.WithExclusions(nil),
	)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	cid := putChallenge(&challengeEntry{session: *session, name: name, uid: uid, code: code})
	writeJSON(w, 200, map[string]any{"cid": cid, "options": creation})
}

func hRegisterVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Cid        string          `json:"cid"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := readBody(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	c := takeChallenge(body.Cid)
	if c == nil || c.uid == "" {
		writeJSON(w, 400, map[string]any{"error": "challenge expired — try again"})
		return
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body.Credential))
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "verification failed: " + err.Error()})
		return
	}
	u := &waUser{id: []byte(c.uid), name: c.name, displayName: c.name}
	cred, err := wa.CreateCredential(u, c.session, parsed)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "verification failed: " + err.Error()})
		return
	}

	credID := base64.RawURLEncoding.EncodeToString(cred.ID)

	dbMu.Lock()
	if findCredByID(credID) != nil {
		dbMu.Unlock()
		writeJSON(w, 409, map[string]any{"error": "credential already registered"})
		return
	}
	// Re-check the invite at the last moment (it may have been used/revoked since options), then burn it.
	var invite *Invite
	if inviteOnly {
		for _, i := range db.Invites {
			if i.Code == c.code && i.UsedBy == "" && !i.Revoked {
				invite = i
				break
			}
		}
		if invite == nil {
			dbMu.Unlock()
			writeJSON(w, 403, map[string]any{"error": "invite code is no longer valid — ask for a new one"})
			return
		}
	}
	user := &User{ID: c.uid, Name: c.name, Created: time.Now().UTC().Format(time.RFC3339)}
	if invite != nil {
		user.InvitedBy = invite.Code
		invite.UsedBy = user.ID
		invite.UsedAt = user.Created
	}
	db.Users = append(db.Users, user)

	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	db.Creds = append(db.Creds, &Cred{
		ID:         credID,
		UserID:     user.ID,
		PublicKey:  base64.RawURLEncoding.EncodeToString(cred.PublicKey),
		Counter:    cred.Authenticator.SignCount,
		Transports: transports,
	})
	saveDBLocked()
	dbMu.Unlock()

	w.Header().Set("Set-Cookie", sessionCookieHeader(user))
	writeJSON(w, 200, map[string]any{"user": publicUser(user)})
}

func hLoginOptions(w http.ResponseWriter, r *http.Request) {
	assertion, session, err := wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	cid := putChallenge(&challengeEntry{session: *session})
	writeJSON(w, 200, map[string]any{"cid": cid, "options": assertion})
}

func hLoginVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Cid        string          `json:"cid"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := readBody(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	c := takeChallenge(body.Cid)
	if c == nil {
		writeJSON(w, 400, map[string]any{"error": "challenge expired — try again"})
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body.Credential))
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "verification failed: " + err.Error()})
		return
	}

	credID := base64.RawURLEncoding.EncodeToString(parsed.RawID)

	dbMu.RLock()
	storedCred := findCredByID(credID)
	dbMu.RUnlock()
	if storedCred == nil {
		writeJSON(w, 404, map[string]any{"error": "unknown passkey — create a profile first"})
		return
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		wc, err := credToWebauthn(storedCred)
		if err != nil {
			return nil, err
		}
		return &waUser{id: userHandle, creds: []webauthn.Credential{wc}}, nil
	}

	updatedCred, err := wa.ValidateDiscoverableLogin(handler, c.session, parsed)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "verification failed: " + err.Error()})
		return
	}

	dbMu.Lock()
	storedCred.Counter = updatedCred.Authenticator.SignCount
	user := findUser(storedCred.UserID)
	saveDBLocked()
	dbMu.Unlock()

	if user == nil {
		writeJSON(w, 500, map[string]any{"error": "user missing"})
		return
	}
	if user.Disabled {
		writeJSON(w, 403, map[string]any{"error": "this account has been disabled"})
		return
	}
	w.Header().Set("Set-Cookie", sessionCookieHeader(user))
	writeJSON(w, 200, map[string]any{"user": publicUser(user)})
}