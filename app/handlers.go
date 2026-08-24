package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

func hHealth(w http.ResponseWriter, r *http.Request) {
	dbMu.RLock()
	n := len(db.Users)
	dbMu.RUnlock()
	writeJSON(w, 200, map[string]any{"ok": true, "users": n})
}

// Public config the login screen needs before anyone is signed in.
func hConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"invite_only": inviteOnly, "allow_guest": allowGuest})
}

func hMe(w http.ResponseWriter, r *http.Request) {
	user := readSession(r)
	if user == nil {
		writeJSON(w, 401, map[string]any{"error": "not signed in"})
		return
	}
	writeJSON(w, 200, map[string]any{"user": publicUser(user)})
}

func hLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Set-Cookie", clearCookieHeader())
	writeJSON(w, 200, map[string]any{"ok": true})
}

// "Sign out everywhere" — bumps this user's session version, which invalidates every cookie ever
// issued for the account, on every device, including a copy someone else walked off with. The
// caller's own cookie is cleared here too, so the browser doing it doesn't sit on a token it no
// longer accepts. Passkeys are untouched: signing back in works immediately.
func hLogoutAll(w http.ResponseWriter, r *http.Request) {
	user := readSession(r)
	if user == nil {
		writeJSON(w, 401, map[string]any{"error": "not signed in"})
		return
	}
	dbMu.Lock()
	user.SV = sessionVersion(user) + 1
	saveDBLocked()
	dbMu.Unlock()
	log.Printf("logout/all: sessions invalidated for id=%s name=%q", user.ID, user.Name)
	w.Header().Set("Set-Cookie", clearCookieHeader())
	writeJSON(w, 200, map[string]any{"ok": true})
}

func hGetData(w http.ResponseWriter, r *http.Request) {
	user := readSession(r)
	if user == nil {
		writeJSON(w, 401, map[string]any{"error": "not signed in"})
		return
	}
	data, err := os.ReadFile(stateFilePath(user.ID))
	if err != nil {
		writeJSON(w, 200, map[string]any{"state": nil})
		return
	}
	var state json.RawMessage
	if err := json.Unmarshal(data, &state); err != nil {
		writeJSON(w, 200, map[string]any{"state": nil})
		return
	}
	writeJSON(w, 200, map[string]any{"state": state})
}

func hPutData(w http.ResponseWriter, r *http.Request) {
	user := readSession(r)
	if user == nil {
		writeJSON(w, 401, map[string]any{"error": "not signed in"})
		return
	}
	var body struct {
		State map[string]interface{} `json:"state"`
	}
	if err := readBody(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.State == nil {
		writeJSON(w, 400, map[string]any{"error": "state required"})
		return
	}
	delete(body.State, "active") // in-progress workouts stay device-local
	out, _ := json.Marshal(body.State)
	atomicWrite(stateFilePath(user.ID), out)
	var ts any
	if v, ok := body.State["_ts"]; ok {
		ts = v
	}
	writeJSON(w, 200, map[string]any{"ok": true, "ts": ts})
}

func hPushPublicKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"key": vapid.PublicKey})
}

func hPushSubscribe(w http.ResponseWriter, r *http.Request) {
	user := readSession(r)
	if user == nil {
		writeJSON(w, 401, map[string]any{"error": "not signed in"})
		return
	}
	var body struct {
		Subscription struct {
			Endpoint string   `json:"endpoint"`
			Keys     PushKeys `json:"keys"`
		} `json:"subscription"`
	}
	if err := readBody(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	sub := body.Subscription
	if sub.Endpoint == "" || sub.Keys.P256dh == "" || sub.Keys.Auth == "" {
		writeJSON(w, 400, map[string]any{"error": "invalid subscription"})
		return
	}
	dbMu.Lock()
	removeSub(sub.Endpoint)
	db.Subs = append(db.Subs, &Sub{
		UserID:   user.ID,
		Endpoint: sub.Endpoint,
		Keys:     sub.Keys,
		Created:  time.Now().UTC().Format(time.RFC3339),
	})
	saveDBLocked()
	dbMu.Unlock()
	log.Printf("push/subscribe: id=%s name=%q", user.ID, user.Name)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func hPushUnsubscribe(w http.ResponseWriter, r *http.Request) {
	user := readSession(r)
	if user == nil {
		writeJSON(w, 401, map[string]any{"error": "not signed in"})
		return
	}
	var body struct {
		Endpoint string `json:"endpoint"`
	}
	if err := readBody(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	dbMu.Lock()
	out := db.Subs[:0]
	for _, s := range db.Subs {
		if !(s.UserID == user.ID && s.Endpoint == body.Endpoint) {
			out = append(out, s)
		}
	}
	db.Subs = out
	saveDBLocked()
	dbMu.Unlock()
	log.Printf("push/unsubscribe: id=%s name=%q", user.ID, user.Name)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func hPushTest(w http.ResponseWriter, r *http.Request) {
	user := readSession(r)
	if user == nil {
		writeJSON(w, 401, map[string]any{"error": "not signed in"})
		return
	}
	sendPush(user.ID, map[string]any{"title": "openGym", "body": "Test notification ✅ — this is what alerts look like.", "tag": "test"})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func hRestTimer(w http.ResponseWriter, r *http.Request) {
	user := readSession(r)
	if user == nil {
		writeJSON(w, 401, map[string]any{"error": "not signed in"})
		return
	}
	var body struct {
		Seconds float64 `json:"seconds"`
	}
	if err := readBody(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	// Mirrors the JS clamp Math.max(1, Math.min(3600, Math.round(seconds||0))) — always yields
	// at least 1, so there's no "seconds required" case to reject here.
	sec := int(body.Seconds + 0.5)
	if sec > 3600 {
		sec = 3600
	}
	if sec < 1 {
		sec = 1
	}
	scheduleRestTimer(user.ID, sec)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func hRestTimerCancel(w http.ResponseWriter, r *http.Request) {
	user := readSession(r)
	if user == nil {
		writeJSON(w, 401, map[string]any{"error": "not signed in"})
		return
	}
	cancelRestTimer(user.ID)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// Live-workout heartbeat: client pings while a workout is on screen; { active:false } drops it.
func hActivity(w http.ResponseWriter, r *http.Request) {
	user := readSession(r)
	if user == nil {
		writeJSON(w, 401, map[string]any{"error": "not signed in"})
		return
	}
	var body struct {
		Active    bool    `json:"active"`
		Name      string  `json:"name"`
		ExIdx     float64 `json:"exIdx"`
		ExTotal   float64 `json:"exTotal"`
		SetsDone  float64 `json:"setsDone"`
		SetsTotal float64 `json:"setsTotal"`
		StartedAt float64 `json:"startedAt"`
	}
	if err := readBody(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.Active {
		name := body.Name
		if len(name) > 60 {
			name = name[:60]
		}
		startedAt := int64(body.StartedAt)
		if startedAt == 0 {
			startedAt = time.Now().UnixMilli()
		}
		setPresence(user.ID, &presenceEntry{
			Name:      name,
			ExIdx:     int(body.ExIdx),
			ExTotal:   int(body.ExTotal),
			SetsDone:  int(body.SetsDone),
			SetsTotal: int(body.SetsTotal),
			StartedAt: startedAt,
		})
	} else {
		dropPresence(user.ID)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}