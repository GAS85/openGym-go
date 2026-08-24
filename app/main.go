// opengym-go — passkey (WebAuthn) auth + per-user state storage for openGym.
// Go port of the original Node.js single-file server: JSON-file storage, signed session cookies.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

const maxBody = 5 * 1024 * 1024

var (
	port        int
	dataDir     string
	rpID        string
	origin      string
	rpName      string
	adminUIDs   []string
	inviteOnly  bool
	allowGuest  bool
	sessionDays int
	secure      string // " Secure;" or ""

	secret []byte
	dbFile string

	wa *webauthn.WebAuthn
)

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var truthy = regexp.MustCompile(`(?i)^(1|true|yes|on)$`)
var falsy = regexp.MustCompile(`(?i)^(0|false|no|off)$`)

func loadConfig() {
	port = 3000
	if v := os.Getenv("PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			port = n
		}
	}
	dataDir = envDefault("DATA_DIR", "/data")
	rpID = envDefault("RP_ID", "localhost")
	origin = envDefault("ORIGIN", "http://localhost:8080")
	rpName = envDefault("RP_NAME", "openGym")

	// Admin dashboard: admins are matched by uid; INVITE_ONLY gates new signups behind a code
	// the admin generates. Both default off so a fresh self-hosted instance stays open.
	adminUIDs = nil
	for _, s := range strings.Split(os.Getenv("ADMIN_UIDS"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			adminUIDs = append(adminUIDs, s)
		}
	}
	inviteOnly = truthy.MatchString(os.Getenv("INVITE_ONLY"))
	// Guest mode ("Continue without account") keeps everything in the browser and never touches
	// this server — but on an instance meant for a known set of people, an entrance nobody can
	// walk back out of is still the wrong front door. Default ON so existing instances are
	// unchanged; the polarity is inverted from INVITE_ONLY because the safe default here is the
	// permissive one.
	allowGuest = !falsy.MatchString(os.Getenv("ALLOW_GUEST"))

	// 14 days keeps someone who trains a few times a week permanently signed in without a stolen
	// cookie staying good for a year. Only affects cookies minted from now on — the expiry is
	// baked into each cookie when it's issued, so lowering this never cuts an existing session
	// short.
	sessionDays = 14
	if v := os.Getenv("SESSION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			sessionDays = n
		}
	}
	if sessionDays < 1 {
		sessionDays = 1
	}

	// Secure cookies require HTTPS; over plain http://localhost the flag would drop the cookie.
	if regexp.MustCompile(`(?i)^https:`).MatchString(origin) {
		secure = " Secure;"
	} else {
		secure = ""
	}
}

func main() {
	loadConfig()

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("cannot create data dir %s: %v", dataDir, err)
	}

	loadSecret()
	dbFile = filepath.Join(dataDir, "db.json")
	loadDB()
	db.Subs = orEmptySubs(db.Subs)
	db.Invites = orEmptyInvites(db.Invites)

	loadVapid()

	var err error
	wa, err = webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpName,
		RPOrigins:     []string{origin},
	})
	if err != nil {
		log.Fatalf("webauthn config: %v", err)
	}

	startChallengeReaper()
	startPresenceReaper()
	startReminderLoop()

	mux := buildRoutes()

	addr := fmt.Sprintf(":%d", port)
	log.Printf("gym-api on %s (rpID=%s, origin=%s)", addr, rpID, origin)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func orEmptySubs(s []*Sub) []*Sub {
	if s == nil {
		return []*Sub{}
	}
	return s
}
func orEmptyInvites(i []*Invite) []*Invite {
	if i == nil {
		return []*Invite{}
	}
	return i
}

func loadSecret() {
	secretFile := filepath.Join(dataDir, "secret")
	if _, err := os.Stat(secretFile); os.IsNotExist(err) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		hexSecret := fmt.Sprintf("%x", b)
		if err := os.WriteFile(secretFile, []byte(hexSecret), 0o600); err != nil {
			log.Fatal(err)
		}
	}
	data, err := os.ReadFile(secretFile)
	if err != nil {
		log.Fatal(err)
	}
	secret = []byte(strings.TrimSpace(string(data)))
}

// ---------- routing ----------

func buildRoutes() http.Handler {
	routes := map[string]http.HandlerFunc{
		"GET /api/health":                  hHealth,
		"GET /api/config":                  hConfig,
		"GET /api/me":                      hMe,
		"POST /api/register/options":       hRegisterOptions,
		"POST /api/register/verify":        hRegisterVerify,
		"POST /api/login/options":          hLoginOptions,
		"POST /api/login/verify":           hLoginVerify,
		"POST /api/logout":                 hLogout,
		"POST /api/logout/all":             hLogoutAll,
		"GET /api/data":                    hGetData,
		"PUT /api/data":                    hPutData,
		"GET /api/push/public-key":         hPushPublicKey,
		"POST /api/push/subscribe":         hPushSubscribe,
		"POST /api/push/unsubscribe":       hPushUnsubscribe,
		"POST /api/push/test":              hPushTest,
		"POST /api/push/rest-timer":        hRestTimer,
		"POST /api/push/rest-timer/cancel": hRestTimerCancel,
		"POST /api/activity":               hActivity,
		"GET /api/admin/users":             hAdminUsers,
		"GET /api/admin/user":              hAdminUser,
		"POST /api/admin/user/disable":     hAdminUserDisable,
		"GET /api/admin/invites":           hAdminInvites,
		"POST /api/admin/invites/new":      hAdminInvitesNew,
		"POST /api/admin/invites/revoke":   hAdminInvitesRevoke,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		handler, ok := routes[key]
		if !ok {
			writeJSON(w, 404, map[string]any{"error": "not found"})
			return
		}
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("%s: %v", key, rec)
				writeJSON(w, 500, map[string]any{"error": "server error"})
			}
		}()
		handler(w, r)
	})
	return mux
}

// ---------- generic helpers ----------

func writeJSON(w http.ResponseWriter, code int, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(obj)
}

func readBody(r *http.Request, dst any) error {
	limited := io.LimitReader(r.Body, maxBody+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("body too large")
	}
	if int64(len(data)) > maxBody {
		return fmt.Errorf("body too large")
	}
	if len(data) == 0 {
		return nil // dst left as zero value, mirrors JS's `{}` default
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("bad json")
	}
	return nil
}

// ---------- sessions (signed cookie) ----------

func sign(payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifySig(token string) (string, bool) {
	i := strings.LastIndex(token, ".")
	if i < 0 {
		return "", false
	}
	payload, mac := token[:i], token[i+1:]
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(payload))
	expect := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	macB, err1 := base64.RawURLEncoding.DecodeString(mac)
	expectB, err2 := base64.RawURLEncoding.DecodeString(expect)
	if err1 != nil || err2 != nil || len(macB) != len(expectB) {
		return "", false
	}
	if subtle.ConstantTimeCompare(macB, expectB) != 1 {
		return "", false
	}
	return payload, true
}

// Session payload is `<uid>:<expiry>:<version>`, where the version is the user's SV counter.
// Bumping SV (POST /api/logout/all) makes every cookie ever handed out for that account stop
// verifying — the only revocation mechanism there is, short of deleting the secret file and
// signing out the whole instance. Cookies minted before SV existed have no third field and are
// read as version 0, matching a user who has never bumped — they stay valid until they expire.
func sessionVersion(u *User) int { return u.SV }

func makeSession(u *User) string {
	exp := time.Now().Add(time.Duration(sessionDays) * 24 * time.Hour).UnixMilli()
	return sign(fmt.Sprintf("%s:%d:%d", u.ID, exp, sessionVersion(u)))
}

func readSession(r *http.Request) *User {
	c, err := r.Cookie("gymsid")
	if err != nil || c.Value == "" {
		return nil
	}
	payload, ok := verifySig(c.Value)
	if !ok {
		return nil
	}
	parts := strings.SplitN(payload, ":", 3)
	if len(parts) < 2 {
		return nil
	}
	uid := parts[0]
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if uid == "" || err != nil || exp < time.Now().UnixMilli() {
		return nil
	}
	dbMu.RLock()
	user := findUser(uid)
	dbMu.RUnlock()
	if user == nil {
		return nil
	}
	if user.Disabled { // disabled accounts are locked out everywhere
		return nil
	}
	// Missing third field = pre-versioning cookie = version 0. Anything non-numeric is a
	// malformed payload (it still had to pass the HMAC, so this is belt-and-braces) and is
	// refused outright.
	claimed := 0
	if len(parts) == 3 {
		v, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil
		}
		claimed = v
	}
	if claimed != sessionVersion(user) {
		return nil
	}
	return user
}

// requireAdmin is the guard for /api/admin/*. It resolves the caller and writes 401/403 itself
// if they aren't an admin, returning nil in that case so callers can just `if u := requireAdmin(...); u == nil { return }`.
func requireAdmin(w http.ResponseWriter, r *http.Request) *User {
	user := readSession(r)
	if user == nil {
		writeJSON(w, 401, map[string]any{"error": "not signed in"})
		return nil
	}
	dbMu.RLock()
	admin := isAdmin(user)
	dbMu.RUnlock()
	if !admin {
		writeJSON(w, 403, map[string]any{"error": "forbidden"})
		return nil
	}
	return user
}

func sessionCookieHeader(u *User) string {
	return fmt.Sprintf("gymsid=%s; Path=/; Max-Age=%d; HttpOnly;%s SameSite=Lax",
		makeSession(u), sessionDays*86400, secure)
}

func clearCookieHeader() string {
	return fmt.Sprintf("gymsid=; Path=/; Max-Age=0; HttpOnly;%s SameSite=Lax", secure)
}

func publicUser(u *User) map[string]any {
	dbMu.RLock()
	admin := isAdmin(u)
	dbMu.RUnlock()
	return map[string]any{"id": u.ID, "name": u.Name, "admin": admin}
}
