package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// One row per user, cheap enough for a personal instance (reads each state file once).
func hAdminUsers(w http.ResponseWriter, r *http.Request) {
	if requireAdmin(w, r) == nil {
		return
	}
	dbMu.RLock()
	users := append([]*User{}, db.Users...)
	subsByUser := map[string]bool{}
	for _, s := range db.Subs {
		subsByUser[s.UserID] = true
	}
	dbMu.RUnlock()

	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		s := readState(u.ID)
		var workouts []interface{}
		if s != nil {
			workouts, _ = s["workouts"].([]interface{})
		}
		var lastWorkout any
		if len(workouts) > 0 {
			if wm, ok := workouts[len(workouts)-1].(map[string]interface{}); ok {
				lastWorkout = wm["d"]
			}
		}
		var lastSync any
		if s != nil {
			lastSync = s["_ts"]
		}
		dbMu.RLock()
		admin := isAdmin(u)
		dbMu.RUnlock()
		out = append(out, map[string]any{
			"id": u.ID, "name": u.Name, "created": orNull(u.Created),
			"disabled": u.Disabled, "admin": admin, "invitedBy": orNull(u.InvitedBy),
			"workouts":    len(workouts),
			"lastWorkout": lastWorkout,
			"lastSync":    lastSync,
			"hasPush":     subsByUser[u.ID],
			"live":        livePresence(u.ID),
		})
	}
	writeJSON(w, 200, map[string]any{"users": out, "invite_only": inviteOnly, "now": time.Now().UnixMilli()})
}

// Drill-down: full workout history + body-weight log for one user.
func hAdminUser(w http.ResponseWriter, r *http.Request) {
	if requireAdmin(w, r) == nil {
		return
	}
	id := r.URL.Query().Get("id")
	dbMu.RLock()
	u := findUser(id)
	var admin bool
	if u != nil {
		admin = isAdmin(u)
	}
	dbMu.RUnlock()
	if u == nil {
		writeJSON(w, 404, map[string]any{"error": "no such user"})
		return
	}
	s := readState(u.ID)
	if s == nil {
		s = map[string]interface{}{}
	}
	unit, _ := s["unit"].(string)
	if unit == "" {
		unit = "kg"
	}
	routinesOut := []map[string]any{}
	if routines, ok := s["routines"].([]interface{}); ok {
		for _, r := range routines {
			if rm, ok := r.(map[string]interface{}); ok {
				count := 0
				if ex, ok := rm["ex"].([]interface{}); ok {
					count = len(ex)
				}
				routinesOut = append(routinesOut, map[string]any{
					"id": rm["id"], "name": rm["name"], "emoji": rm["emoji"], "count": count,
				})
			}
		}
	}
	bodyweight := s["bodyweight"]
	if bodyweight == nil {
		bodyweight = []interface{}{}
	}
	var workouts []interface{}
	if w2, ok := s["workouts"].([]interface{}); ok {
		workouts = append(workouts, w2...)
		reverse(workouts) // newest first for display
	} else {
		workouts = []interface{}{}
	}

	writeJSON(w, 200, map[string]any{
		"user": map[string]any{
			"id": u.ID, "name": u.Name, "created": orNull(u.Created),
			"disabled": u.Disabled, "admin": admin, "invitedBy": orNull(u.InvitedBy),
		},
		"unit":       unit,
		"lastSync":   s["_ts"],
		"routines":   routinesOut,
		"bodyweight": bodyweight,
		"workouts":   workouts,
	})
}

func hAdminUserDisable(w http.ResponseWriter, r *http.Request) {
	admin := requireAdmin(w, r)
	if admin == nil {
		return
	}
	var body struct {
		ID       string `json:"id"`
		Disabled bool   `json:"disabled"`
	}
	if err := readBody(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	dbMu.Lock()
	u := findUser(body.ID)
	if u == nil {
		dbMu.Unlock()
		writeJSON(w, 404, map[string]any{"error": "no such user"})
		return
	}
	if isAdmin(u) {
		dbMu.Unlock()
		writeJSON(w, 400, map[string]any{"error": "cannot disable an admin"})
		return
	}
	u.Disabled = body.Disabled
	saveDBLocked()
	dbMu.Unlock()
	if u.Disabled {
		dropPresence(u.ID) // drop them off "training now" at once
	}
	log.Printf("admin/user/disable: id=%s name=%q disabled=%v by=%s", u.ID, u.Name, u.Disabled, admin.ID)
	writeJSON(w, 200, map[string]any{"ok": true, "id": u.ID, "disabled": u.Disabled})
}

func hAdminInvites(w http.ResponseWriter, r *http.Request) {
	if requireAdmin(w, r) == nil {
		return
	}
	dbMu.RLock()
	defer dbMu.RUnlock()
	out := make([]map[string]any, 0, len(db.Invites))
	for _, i := range db.Invites {
		var usedByName any
		if i.UsedBy != "" {
			if u := findUser(i.UsedBy); u != nil {
				usedByName = u.Name
			}
		}
		out = append(out, map[string]any{
			"code": i.Code, "note": i.Note, "createdBy": i.CreatedBy, "created": i.Created,
			"usedBy": orNull(i.UsedBy), "usedAt": orNull(i.UsedAt), "revoked": i.Revoked,
			"usedByName": usedByName,
		})
	}
	writeJSON(w, 200, map[string]any{"invites": out, "invite_only": inviteOnly})
}

func hAdminInvitesNew(w http.ResponseWriter, r *http.Request) {
	admin := requireAdmin(w, r)
	if admin == nil {
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	if err := readBody(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	note := body.Note
	if len(note) > 60 {
		note = note[:60]
	}

	dbMu.Lock()
	defer dbMu.Unlock()
	// 16 hex chars = 64 bits, up from 8 chars / 32 bits. The app has no rate limiting by design
	// (that's the reverse proxy's job) and /api/register/options tells a caller whether a code is
	// good, so the code itself has to be the thing that isn't worth guessing. Codes already in
	// db.json keep working — validation is an exact string compare, never a length or format check.
	var code string
	for {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		code = strings.ToUpper(fmt.Sprintf("%x", b))
		exists := false
		for _, i := range db.Invites {
			if i.Code == code {
				exists = true
				break
			}
		}
		if !exists {
			break
		}
	}
	invite := &Invite{Code: code, Note: note, CreatedBy: admin.ID, Created: time.Now().UTC().Format(time.RFC3339)}
	db.Invites = append(db.Invites, invite)
	saveDBLocked()
	log.Printf("admin/invites/new: code=%s note=%q by=%s", invite.Code, invite.Note, admin.ID)
	writeJSON(w, 200, map[string]any{"invite": invite})
}

func hAdminInvitesRevoke(w http.ResponseWriter, r *http.Request) {
	admin := requireAdmin(w, r)
	if admin == nil {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := readBody(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	code := strings.ToUpper(body.Code)

	dbMu.Lock()
	defer dbMu.Unlock()
	var inv *Invite
	for _, i := range db.Invites {
		if i.Code == code {
			inv = i
			break
		}
	}
	if inv == nil {
		writeJSON(w, 404, map[string]any{"error": "no such code"})
		return
	}
	if inv.UsedBy != "" {
		writeJSON(w, 400, map[string]any{"error": "already used — cannot revoke"})
		return
	}
	out := db.Invites[:0]
	for _, i := range db.Invites {
		if i.Code != inv.Code {
			out = append(out, i)
		}
	}
	db.Invites = out
	saveDBLocked()
	log.Printf("admin/invites/revoke: code=%s by=%s", inv.Code, admin.ID)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func orNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func reverse(s []interface{}) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}