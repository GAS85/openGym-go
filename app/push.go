package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ---------- VAPID key pair ----------

type vapidKeys struct {
	PublicKey  string `json:"publicKey"`  // base64url, uncompressed P-256 point (65 bytes)
	PrivateKey string `json:"privateKey"` // base64url, raw scalar D (32 bytes)
}

var (
	vapid        vapidKeys
	vapidPriv    *ecdsa.PrivateKey
	vapidSubject string
)

func loadVapid() {
	vapidFile := filepath.Join(dataDir, "vapid.json")
	data, err := os.ReadFile(vapidFile)
	if err == nil && json.Unmarshal(data, &vapid) == nil && vapid.PublicKey != "" {
		// fall through to reconstruct vapidPriv below
	} else {
		priv, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if genErr != nil {
			log.Fatal(genErr)
		}
		pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
		vapid = vapidKeys{
			PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
			PrivateKey: base64.RawURLEncoding.EncodeToString(leftPad32(priv.D.Bytes())),
		}
		out, _ := json.Marshal(vapid)
		if err := os.WriteFile(vapidFile, out, 0o600); err != nil {
			log.Fatal(err)
		}
	}

	dBytes, err := base64.RawURLEncoding.DecodeString(vapid.PrivateKey)
	if err != nil {
		log.Fatalf("bad vapid private key: %v", err)
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(vapid.PublicKey)
	if err != nil {
		log.Fatalf("bad vapid public key: %v", err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), pubBytes)
	if x == nil {
		log.Fatal("bad vapid public key point")
	}
	vapidPriv = &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		D:         new(big.Int).SetBytes(dBytes),
	}

	vapidSubject = os.Getenv("VAPID_SUBJECT")
	if vapidSubject == "" {
		if secure != "" {
			vapidSubject = origin
		} else {
			vapidSubject = "mailto:admin@localhost"
		}
	}
}

func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// ---------- VAPID JWT (ES256) ----------

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func vapidAuthHeader(endpoint string) (string, error) {
	u, err := urlOrigin(endpoint)
	if err != nil {
		return "", err
	}
	header := b64url([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claims, _ := json.Marshal(map[string]any{
		"aud": u,
		"exp": time.Now().Add(12 * time.Hour).Unix(),
		"sub": vapidSubject,
	})
	payload := header + "." + b64url(claims)

	hash := sha256.Sum256([]byte(payload))
	r, s, err := ecdsa.Sign(rand.Reader, vapidPriv, hash[:])
	if err != nil {
		return "", err
	}
	sig := append(leftPad32(r.Bytes()), leftPad32(s.Bytes())...)
	jwt := payload + "." + b64url(sig)
	return fmt.Sprintf("vapid t=%s, k=%s", jwt, vapid.PublicKey), nil
}

func urlOrigin(endpoint string) (string, error) {
	var scheme, hostport string
	i := indexOf(endpoint, "://")
	if i < 0 {
		return "", fmt.Errorf("bad endpoint url")
	}
	scheme = endpoint[:i]
	rest := endpoint[i+3:]
	j := indexOf(rest, "/")
	if j < 0 {
		hostport = rest
	} else {
		hostport = rest[:j]
	}
	return scheme + "://" + hostport, nil
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ---------- RFC 8291 message encryption (aes128gcm) ----------

func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}
func hkdfExpand(prk, info []byte, length int) []byte {
	m := hmac.New(sha256.New, prk)
	m.Write(info)
	m.Write([]byte{0x01})
	return m.Sum(nil)[:length]
}

// encryptPayload implements the Web Push "aes128gcm" content coding (RFC 8188 / RFC 8291) and
// returns the full request body to POST to the push service.
func encryptPayload(plaintext []byte, p256dhB64, authB64 string) ([]byte, error) {
	uaPub, err := decodeB64(p256dhB64)
	if err != nil {
		return nil, fmt.Errorf("bad p256dh: %w", err)
	}
	authSecret, err := decodeB64(authB64)
	if err != nil {
		return nil, fmt.Errorf("bad auth secret: %w", err)
	}

	curve := ecdh.P256()
	uaPubKey, err := curve.NewPublicKey(uaPub)
	if err != nil {
		return nil, fmt.Errorf("bad subscriber public key: %w", err)
	}
	asPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	asPub := asPriv.PublicKey().Bytes()

	ecdhSecret, err := asPriv.ECDH(uaPubKey)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// key_info = "WebPush: info" || 0x00 || ua_public || as_public
	keyInfo := append([]byte("WebPush: info\x00"), uaPub...)
	keyInfo = append(keyInfo, asPub...)
	ikm := hkdfExpand(hkdfExtract(authSecret, ecdhSecret), keyInfo, 32)

	prk := hkdfExtract(salt, ikm)
	cek := hkdfExpand(prk, []byte("Content-Encoding: aes128gcm\x00"), 16)
	nonce := hkdfExpand(prk, []byte("Content-Encoding: nonce\x00"), 12)

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// single-record message: plaintext padded with a 0x02 delimiter octet (no further padding)
	padded := append(append([]byte{}, plaintext...), 0x02)
	ciphertext := gcm.Seal(nil, nonce, padded, nil)

	var out bytes.Buffer
	out.Write(salt)
	rs := make([]byte, 4)
	binary.BigEndian.PutUint32(rs, 4096)
	out.Write(rs)
	out.WriteByte(byte(len(asPub)))
	out.Write(asPub)
	out.Write(ciphertext)
	return out.Bytes(), nil
}

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// ---------- sendPush ----------

var pushClient = &http.Client{Timeout: 15 * time.Second}

func sendPush(userID string, payload map[string]any) {
	dbMu.RLock()
	var subs []*Sub
	for _, s := range db.Subs {
		if s.UserID == userID {
			subs = append(subs, s)
		}
	}
	dbMu.RUnlock()
	if len(subs) == 0 {
		return
	}
	body, _ := json.Marshal(payload)

	var wg sync.WaitGroup
	var mu sync.Mutex
	dirty := false
	for _, sub := range subs {
		wg.Add(1)
		go func(sub *Sub) {
			defer wg.Done()
			status, err := postPush(sub, body)
			if err != nil {
				log.Printf("push send failed %s: %v", userID, err)
				return
			}
			if status == 404 || status == 410 {
				mu.Lock()
				removeSub(sub.Endpoint)
				dirty = true
				mu.Unlock()
			} else if status >= 400 {
				log.Printf("push send failed %s: status %d", userID, status)
			}
		}(sub)
	}
	wg.Wait()
	if dirty {
		dbMu.Lock()
		saveDBLocked()
		dbMu.Unlock()
	}
}

func removeSub(endpoint string) {
	out := db.Subs[:0]
	for _, s := range db.Subs {
		if s.Endpoint != endpoint {
			out = append(out, s)
		}
	}
	db.Subs = out
}

// postPush sends one encrypted push message with urgency 'high' — the one lever available over
// delivery speed, since iOS/Android throttle low-urgency background push more aggressively under
// battery-saving modes. TTL is left generous so a briefly-offline device still gets it once
// reconnected.
func postPush(sub *Sub, payload []byte) (int, error) {
	encrypted, err := encryptPayload(payload, sub.Keys.P256dh, sub.Keys.Auth)
	if err != nil {
		return 0, err
	}
	authHeader, err := vapidAuthHeader(sub.Endpoint)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest("POST", sub.Endpoint, bytes.NewReader(encrypted))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("TTL", "2419200") // 4 weeks, matches web-push library default
	req.Header.Set("Urgency", "high")
	req.Header.Set("Authorization", authHeader)

	resp, err := pushClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// ---------- rest-timer alerts ----------

// Client schedules on start/extend, cancels on skip or on-screen completion — this only fires
// when the tab was backgrounded/suspended and never got to cancel it itself.
var (
	restMu     sync.Mutex
	restTimers = map[string]*time.Timer{}
)

func scheduleRestTimer(userID string, sec int) {
	restMu.Lock()
	defer restMu.Unlock()
	if t, ok := restTimers[userID]; ok {
		t.Stop()
	}
	restTimers[userID] = time.AfterFunc(time.Duration(sec)*time.Second, func() {
		restMu.Lock()
		delete(restTimers, userID)
		restMu.Unlock()
		sendPush(userID, map[string]any{"title": "Rest over 💪", "body": "Time for your next set.", "tag": "rest-timer"})
	})
}

func cancelRestTimer(userID string) {
	restMu.Lock()
	defer restMu.Unlock()
	if t, ok := restTimers[userID]; ok {
		t.Stop()
		delete(restTimers, userID)
	}
}

// ---------- "workout planned today" reminder ----------

// effectiveRoutineId mirrors frontend/src/lib/history.js's helper of the same name — a tiny pure
// function, not worth sharing across the two runtimes.
func effectiveRoutineID(s map[string]interface{}, iso string) string {
	if dayPlan, ok := s["dayPlan"].(map[string]interface{}); ok {
		if ov, ok := dayPlan[iso].(string); ok {
			if ov == "rest" {
				return ""
			}
			if routines, ok := s["routines"].([]interface{}); ok {
				for _, r := range routines {
					if rm, ok := r.(map[string]interface{}); ok {
						if id, _ := rm["id"].(string); id == ov {
							return ov
						}
					}
				}
			}
		}
	}
	t, err := time.Parse("2006-01-02T15:04:05", iso+"T12:00:00")
	if err != nil {
		return ""
	}
	wd := int(t.Weekday())
	if week, ok := s["week"].([]interface{}); ok && wd < len(week) {
		if id, ok := week[wd].(string); ok {
			return id
		}
	}
	return ""
}

// userNow computes "now" in an arbitrary IANA zone (e.g. "Europe/Lisbon") instead of the server's
// own — each user's reminder fires by their own clock, wherever they and their phone actually are.
func userNow(tz string) (date, hhmm string, ok bool) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return "", "", false // unknown/invalid tz string — skip this user rather than guess
	}
	now := time.Now().In(loc)
	return now.Format("2006-01-02"), now.Format("15:04"), true
}

func startReminderLoop() {
	// Checked every 10s (not 60s) — ticks aren't aligned to the top of the minute, so a 60s
	// interval could sit on the target minute for up to 59s before noticing. 10s caps that at ~9s.
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			runReminderPass()
		}
	}()
}

func runReminderPass() {
	dbMu.RLock()
	users := append([]*User{}, db.Users...)
	subsByUser := map[string]bool{}
	for _, s := range db.Subs {
		subsByUser[s.UserID] = true
	}
	dbMu.RUnlock()

	for _, user := range users {
		if !subsByUser[user.ID] {
			continue
		}
		s := readState(user.ID)
		reminder, _ := s["reminder"].(map[string]interface{})
		if reminder == nil {
			continue
		}
		if on, _ := reminder["on"].(bool); !on {
			continue
		}
		tz, _ := reminder["tz"].(string)
		if tz == "" {
			tz = "UTC"
		}
		date, hhmm, ok := userNow(tz)
		if !ok {
			continue
		}
		wantTime, _ := reminder["time"].(string)
		if wantTime != hhmm {
			continue
		}
		if user.LastReminder == date {
			continue
		}
		already := false
		if workouts, ok := s["workouts"].([]interface{}); ok {
			for _, w := range workouts {
				if wm, ok := w.(map[string]interface{}); ok {
					if d, _ := wm["d"].(string); d == date {
						already = true
						break
					}
				}
			}
		}
		if already {
			continue
		}
		rid := effectiveRoutineID(s, date)
		if rid == "" {
			continue // rest day — nothing planned
		}
		var routine map[string]interface{}
		if routines, ok := s["routines"].([]interface{}); ok {
			for _, r := range routines {
				if rm, ok := r.(map[string]interface{}); ok {
					if id, _ := rm["id"].(string); id == rid {
						routine = rm
						break
					}
				}
			}
		}
		log.Printf("reminder firing %s %s", user.ID, rid)

		dbMu.Lock()
		user.LastReminder = date
		saveDBLocked()
		dbMu.Unlock()

		title := "Workout planned today"
		if routine != nil {
			emoji, _ := routine["emoji"].(string)
			if emoji == "" {
				emoji = "🏋️"
			}
			name, _ := routine["name"].(string)
			title = fmt.Sprintf("%s %s today", emoji, name)
		}
		sendPush(user.ID, map[string]any{
			"title": title,
			"body":  "It's on your plan — let's go 💪",
			"tag":   "day-reminder",
		})
	}
}
