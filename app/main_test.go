package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Setup test environment
func TestMain(m *testing.M) {
	// Set up test environment
	os.Setenv("DATA_DIR", "./test_data")
	os.Setenv("RP_ID", "localhost")
	os.Setenv("ORIGIN", "http://localhost:8080")
	os.Setenv("SESSION_DAYS", "1")

	// Initialize WebAuthn for tests
	initTestWebAuthn()

	// Clean up after tests
	code := m.Run()
	os.RemoveAll("./test_data")
	os.Exit(code)
}

func initTest() {
	// Reset global state
	dbMu.Lock()
	db = &DB{
		Users:   []*User{},
		Creds:   []*Cred{},
		Subs:    []*Sub{},
		Invites: []*Invite{},
	}
	dbMu.Unlock()

	// Clear challenges
	chMu.Lock()
	challenges = map[string]*challengeEntry{}
	chMu.Unlock()

	// Clear presence
	presenceMu.Lock()
	presence = map[string]*presenceEntry{}
	presenceMu.Unlock()

	// Clear rest timers
	restMu.Lock()
	restTimers = map[string]*time.Timer{}
	restMu.Unlock()

	// Reset config to defaults
	resetConfig()
}

func resetConfig() {
	port = 3000
	dataDir = "/data"
	rpID = "localhost"
	origin = "http://localhost:8080"
	rpName = "openGym"
	adminUIDs = nil
	inviteOnly = false
	allowGuest = true
	sessionDays = 14
	secure = ""
}

func initTestWebAuthn() {
	// Initialize WebAuthn for testing
	config := &webauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "openGym Test",
		RPOrigins:     []string{"http://localhost:8080"},
	}

	var err error
	wa, err = webauthn.New(config)
	if err != nil {
		panic("failed to initialize WebAuthn for tests: " + err.Error())
	}
}

func createTestUser(id, name string) *User {
	user := &User{
		ID:      id,
		Name:    name,
		Created: time.Now().UTC().Format(time.RFC3339),
	}
	dbMu.Lock()
	db.Users = append(db.Users, user)
	dbMu.Unlock()
	return user
}

func createTestCred(userID, credID string) *Cred {
	cred := &Cred{
		ID:        credID,
		UserID:    userID,
		PublicKey: base64.RawURLEncoding.EncodeToString([]byte("test-public-key")),
		Counter:   0,
	}
	dbMu.Lock()
	db.Creds = append(db.Creds, cred)
	dbMu.Unlock()
	return cred
}

func createTestInvite(code string) *Invite {
	invite := &Invite{
		Code:      code,
		CreatedBy: "admin",
		Created:   time.Now().UTC().Format(time.RFC3339),
	}
	dbMu.Lock()
	db.Invites = append(db.Invites, invite)
	dbMu.Unlock()
	return invite
}

// Test configuration loading
func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected map[string]interface{}
	}{
		{
			name:    "default config",
			envVars: map[string]string{},
			expected: map[string]interface{}{
				"port":        3000,
				"rpID":        "localhost",
				"origin":      "http://localhost:8080",
				"rpName":      "openGym",
				"sessionDays": 14,
				"inviteOnly":  false,
				"allowGuest":  true,
				"adminUIDs":   []string{},
			},
		},
		{
			name: "custom config",
			envVars: map[string]string{
				"PORT":         "8080",
				"RP_ID":        "gym.example.com",
				"ORIGIN":       "https://gym.example.com",
				"RP_NAME":      "Test Gym",
				"SESSION_DAYS": "30",
				"ADMIN_UIDS":   "admin1,admin2",
				"INVITE_ONLY":  "true",
				"ALLOW_GUEST":  "false",
			},
			expected: map[string]interface{}{
				"port":        8080,
				"rpID":        "gym.example.com",
				"origin":      "https://gym.example.com",
				"rpName":      "Test Gym",
				"sessionDays": 30,
				"adminUIDs":   []string{"admin1", "admin2"},
				"inviteOnly":  true,
				"allowGuest":  false,
				"secure":      " Secure;",
			},
		},
		{
			name: "truthy invite only",
			envVars: map[string]string{
				"INVITE_ONLY": "yes",
			},
			expected: map[string]interface{}{
				"inviteOnly": true,
			},
		},
		{
			name: "falsy allow guest",
			envVars: map[string]string{
				"ALLOW_GUEST": "off",
			},
			expected: map[string]interface{}{
				"allowGuest": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save current env and restore after test
			origEnv := os.Environ()
			defer func() {
				os.Clearenv()
				for _, e := range origEnv {
					// Parse key=value and set it back
					for i := 0; i < len(e); i++ {
						if e[i] == '=' {
							key := e[:i]
							value := e[i+1:]
							os.Setenv(key, value)
							break
						}
					}
				}
				resetConfig()
			}()

			// Clear env and reset config for this test
			os.Clearenv()
			resetConfig()

			// Set test env vars
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			// Load config
			loadConfig()

			// Check values
			if val, ok := tt.expected["port"]; ok && port != val {
				t.Errorf("expected port %v, got %v", val, port)
			}
			if val, ok := tt.expected["rpID"]; ok && rpID != val {
				t.Errorf("expected rpID %v, got %v", val, rpID)
			}
			if val, ok := tt.expected["origin"]; ok && origin != val {
				t.Errorf("expected origin %v, got %v", val, origin)
			}
			if val, ok := tt.expected["rpName"]; ok && rpName != val {
				t.Errorf("expected rpName %v, got %v", val, rpName)
			}
			if val, ok := tt.expected["sessionDays"]; ok && sessionDays != val {
				t.Errorf("expected sessionDays %v, got %v", val, sessionDays)
			}
			if val, ok := tt.expected["inviteOnly"]; ok && inviteOnly != val {
				t.Errorf("expected inviteOnly %v, got %v", val, inviteOnly)
			}
			if val, ok := tt.expected["allowGuest"]; ok && allowGuest != val {
				t.Errorf("expected allowGuest %v, got %v", val, allowGuest)
			}

			// Check admin UIDs
			if val, ok := tt.expected["adminUIDs"]; ok {
				expectedAdmins := val.([]string)
				if len(adminUIDs) != len(expectedAdmins) {
					t.Errorf("expected adminUIDs length %d, got %d", len(expectedAdmins), len(adminUIDs))
				}
				for i, id := range expectedAdmins {
					if i < len(adminUIDs) && adminUIDs[i] != id {
						t.Errorf("expected adminUID %s, got %s", id, adminUIDs[i])
					}
				}
			}

			// Check secure flag
			if val, ok := tt.expected["secure"].(string); ok {
				if secure != val {
					t.Errorf("expected secure %v, got %v", val, secure)
				}
			}
		})
	}
}

// Test health endpoint
func TestHealth(t *testing.T) {
	initTest()

	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	hHealth(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	if body["ok"] != true {
		t.Errorf("expected ok=true, got %v", body["ok"])
	}
}

// Test config endpoint
func TestConfig(t *testing.T) {
	initTest()

	inviteOnly = true
	allowGuest = false

	req := httptest.NewRequest("GET", "/api/config", nil)
	w := httptest.NewRecorder()
	hConfig(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	if body["invite_only"] != true {
		t.Errorf("expected invite_only=true, got %v", body["invite_only"])
	}
	if body["allow_guest"] != false {
		t.Errorf("expected allow_guest=false, got %v", body["allow_guest"])
	}
}

// Test session management
func TestSessionManagement(t *testing.T) {
	initTest()

	// Create test user
	user := createTestUser("test-user", "Test User")

	// Test makeSession
	session := makeSession(user)
	if session == "" {
		t.Error("session should not be empty")
	}

	// Test readSession with valid cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "gymsid", Value: session})

	readUser := readSession(req)
	if readUser == nil {
		t.Error("readSession should return user")
	}
	if readUser.ID != user.ID {
		t.Errorf("expected user ID %s, got %s", user.ID, readUser.ID)
	}

	// Test readSession with invalid cookie
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(&http.Cookie{Name: "gymsid", Value: "invalid"})

	readUser2 := readSession(req2)
	if readUser2 != nil {
		t.Error("readSession should return nil for invalid cookie")
	}

	// Test session version bump (logout all)
	oldVersion := sessionVersion(user)
	user.SV = oldVersion + 1
	newVersion := sessionVersion(user)

	if newVersion != oldVersion+1 {
		t.Errorf("expected version %d, got %d", oldVersion+1, newVersion)
	}

	// Old session should be invalid
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.AddCookie(&http.Cookie{Name: "gymsid", Value: session})

	readUser3 := readSession(req3)
	if readUser3 != nil {
		t.Error("old session should be invalid after version bump")
	}
}

// Test registration flow (simulated)
func TestRegistrationFlow(t *testing.T) {
	initTest()

	// Ensure WebAuthn is initialized
	if wa == nil {
		initTestWebAuthn()
	}

	// Test register options
	regBody := map[string]interface{}{
		"name": "Test User",
		"code": "",
	}
	regBodyJSON, _ := json.Marshal(regBody)

	req := httptest.NewRequest("POST", "/api/register/options", bytes.NewReader(regBodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	hRegisterOptions(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	cid, ok := body["cid"].(string)
	if !ok || cid == "" {
		t.Error("expected cid in response")
	}

	options, ok := body["options"].(map[string]interface{})
	if !ok {
		t.Error("expected options in response")
	}

	challenge, ok := options["challenge"].(string)
	if !ok || challenge == "" {
		t.Error("expected challenge in options")
	}

	// Test register verify with mock credential (will fail - expected)
	verifyBody := map[string]interface{}{
		"cid": cid,
		"credential": map[string]interface{}{
			"id": "test-credential-id",
			"response": map[string]interface{}{
				"transports": []string{"usb", "nfc"},
			},
		},
	}
	verifyBodyJSON, _ := json.Marshal(verifyBody)

	req2 := httptest.NewRequest("POST", "/api/register/verify", bytes.NewReader(verifyBodyJSON))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()

	hRegisterVerify(w2, req2)

	// It should fail because we're using a mock credential
	if w2.Code == http.StatusOK {
		t.Error("expected failure with mock credential")
	}
}

// Test login flow (simulated)
func TestLoginFlow(t *testing.T) {
	initTest()

	// Ensure WebAuthn is initialized
	if wa == nil {
		initTestWebAuthn()
	}

	// Create test user and credential
	createTestUser("test-user", "Test User")
	createTestCred("test-user", "test-cred-id")

	// Test login options
	req := httptest.NewRequest("POST", "/api/login/options", nil)
	w := httptest.NewRecorder()

	hLoginOptions(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	cid, ok := body["cid"].(string)
	if !ok || cid == "" {
		t.Error("expected cid in response")
	}

	options, ok := body["options"].(map[string]interface{})
	if !ok {
		t.Error("expected options in response")
	}

	challenge, ok := options["challenge"].(string)
	if !ok || challenge == "" {
		t.Error("expected challenge in options")
	}

	// Test login verify with mock credential (will fail - expected)
	verifyBody := map[string]interface{}{
		"cid": cid,
		"credential": map[string]interface{}{
			"id": "test-cred-id",
			"response": map[string]interface{}{
				"authenticatorData": "test-data",
				"signature":         "test-sig",
			},
		},
	}
	verifyBodyJSON, _ := json.Marshal(verifyBody)

	req2 := httptest.NewRequest("POST", "/api/login/verify", bytes.NewReader(verifyBodyJSON))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()

	hLoginVerify(w2, req2)

	// It should fail because we're using a mock credential
	if w2.Code == http.StatusOK {
		t.Error("expected failure with mock credential")
	}
}

// Test data operations
func TestDataOperations(t *testing.T) {
	// Create a unique test directory
	testDir := filepath.Join("./test_data", "data_ops_"+time.Now().Format("20060102150405"))

	// Clean up after test
	defer func() {
		if err := os.RemoveAll(testDir); err != nil {
			t.Logf("warning: failed to clean up test dir: %v", err)
		}
	}()

	// Now initTest will use the correct dataDir
	initTest()

	// Set dataDir to test directory BEFORE calling initTest
	dataDir = testDir
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("failed to create test data dir: %v", err)
	}

	// Reset dbFile for test environment
	dbFile = filepath.Join(dataDir, "db.json")

	user := createTestUser("test-user", "Test User")

	// Create session cookie
	session := makeSession(user)

	// Test get data (should return nil initially)
	req := httptest.NewRequest("GET", "/api/data", nil)
	req.AddCookie(&http.Cookie{Name: "gymsid", Value: session})
	w := httptest.NewRecorder()

	hGetData(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	if body["state"] != nil {
		t.Errorf("expected state nil, got %v", body["state"])
	}

	// Test put data
	testState := map[string]interface{}{
		"workouts": []interface{}{
			map[string]interface{}{
				"d":  "2024-01-01",
				"ex": []interface{}{},
			},
		},
		"_ts": time.Now().UnixMilli(),
	}

	putBody := map[string]interface{}{
		"state": testState,
	}
	putBodyJSON, _ := json.Marshal(putBody)

	req2 := httptest.NewRequest("PUT", "/api/data", bytes.NewReader(putBodyJSON))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "gymsid", Value: session})
	w2 := httptest.NewRecorder()

	hPutData(w2, req2)

	resp2 := w2.Result()
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp2.StatusCode)
	}

	var body2 map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&body2)

	if body2["ok"] != true {
		t.Errorf("expected ok=true, got %v", body2["ok"])
	}

	// Verify the state file was actually written
	statePath := stateFilePath(user.ID)
	t.Logf("State path: %s", statePath)

	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		// Check if the directory exists
		dir := filepath.Dir(statePath)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("data directory does not exist: %s", dir)
		}
		t.Errorf("state file was not created at %s", statePath)
	}

	// Read the file directly to verify content
	fileData, err := os.ReadFile(statePath)
	if err != nil {
		t.Errorf("failed to read state file: %v", err)
	} else {
		t.Logf("State file content: %s", string(fileData))
	}

	// Test get data again (should return the state)
	req3 := httptest.NewRequest("GET", "/api/data", nil)
	req3.AddCookie(&http.Cookie{Name: "gymsid", Value: session})
	w3 := httptest.NewRecorder()

	hGetData(w3, req3)

	resp3 := w3.Result()
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp3.StatusCode)
	}

	var body3 map[string]interface{}
	json.NewDecoder(resp3.Body).Decode(&body3)

	if body3["state"] == nil {
		t.Error("expected state not nil after PUT")
	} else {
		t.Logf("Retrieved state: %v", body3["state"])
	}
}

// Test logout functionality
func TestLogout(t *testing.T) {
	initTest()

	user := createTestUser("test-user", "Test User")
	session := makeSession(user)

	// Test logout
	req := httptest.NewRequest("POST", "/api/logout", nil)
	req.AddCookie(&http.Cookie{Name: "gymsid", Value: session})
	w := httptest.NewRecorder()

	hLogout(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Check that cookie was cleared
	cookies := resp.Header["Set-Cookie"]
	found := false
	for _, c := range cookies {
		if c == clearCookieHeader() {
			found = true
			break
		}
	}

	if !found {
		t.Error("logout should clear cookie")
	}

	// Test logout all
	req2 := httptest.NewRequest("POST", "/api/logout/all", nil)
	req2.AddCookie(&http.Cookie{Name: "gymsid", Value: session})
	w2 := httptest.NewRecorder()

	hLogoutAll(w2, req2)

	resp2 := w2.Result()
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp2.StatusCode)
	}

	// Session should be invalidated
	req3 := httptest.NewRequest("GET", "/api/me", nil)
	req3.AddCookie(&http.Cookie{Name: "gymsid", Value: session})
	w3 := httptest.NewRecorder()

	hMe(w3, req3)

	if w3.Code == http.StatusOK {
		t.Error("session should be invalidated after logout all")
	}
}

// Test push subscription
func TestPushSubscription(t *testing.T) {
	initTest()

	user := createTestUser("test-user", "Test User")
	session := makeSession(user)

	// Test subscribe
	subBody := map[string]interface{}{
		"subscription": map[string]interface{}{
			"endpoint": "https://push.example.com/test",
			"keys": map[string]interface{}{
				"p256dh": base64.RawURLEncoding.EncodeToString([]byte("test-p256dh")),
				"auth":   base64.RawURLEncoding.EncodeToString([]byte("test-auth")),
			},
		},
	}
	subBodyJSON, _ := json.Marshal(subBody)

	req := httptest.NewRequest("POST", "/api/push/subscribe", bytes.NewReader(subBodyJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "gymsid", Value: session})
	w := httptest.NewRecorder()

	hPushSubscribe(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	if body["ok"] != true {
		t.Errorf("expected ok=true, got %v", body["ok"])
	}

	// Test unsubscribe
	unsubBody := map[string]interface{}{
		"endpoint": "https://push.example.com/test",
	}
	unsubBodyJSON, _ := json.Marshal(unsubBody)

	req2 := httptest.NewRequest("POST", "/api/push/unsubscribe", bytes.NewReader(unsubBodyJSON))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "gymsid", Value: session})
	w2 := httptest.NewRecorder()

	hPushUnsubscribe(w2, req2)

	resp2 := w2.Result()
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp2.StatusCode)
	}

	// Get public key
	req3 := httptest.NewRequest("GET", "/api/push/public-key", nil)
	w3 := httptest.NewRecorder()

	hPushPublicKey(w3, req3)

	resp3 := w3.Result()
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp3.StatusCode)
	}

	var body3 map[string]interface{}
	json.NewDecoder(resp3.Body).Decode(&body3)

	if body3["key"] == nil {
		t.Error("expected key in response")
	}
}

// Test presence (activity)
func TestPresence(t *testing.T) {
	initTest()

	user := createTestUser("test-user", "Test User")
	session := makeSession(user)

	// Set active presence
	activityBody := map[string]interface{}{
		"active":    true,
		"name":      "Test Workout",
		"exIdx":     0,
		"exTotal":   5,
		"setsDone":  0,
		"setsTotal": 3,
		"startedAt": time.Now().UnixMilli(),
	}
	activityBodyJSON, _ := json.Marshal(activityBody)

	req := httptest.NewRequest("POST", "/api/activity", bytes.NewReader(activityBodyJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "gymsid", Value: session})
	w := httptest.NewRecorder()

	hActivity(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Check presence
	p := livePresence(user.ID)
	if p == nil {
		t.Error("presence should not be nil after setting active")
	}

	if p.Name != "Test Workout" {
		t.Errorf("expected name 'Test Workout', got %s", p.Name)
	}

	// Set inactive presence
	activityBody2 := map[string]interface{}{
		"active": false,
	}
	activityBodyJSON2, _ := json.Marshal(activityBody2)

	req2 := httptest.NewRequest("POST", "/api/activity", bytes.NewReader(activityBodyJSON2))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "gymsid", Value: session})
	w2 := httptest.NewRecorder()

	hActivity(w2, req2)

	resp2 := w2.Result()
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp2.StatusCode)
	}

	// Check presence should be nil
	p2 := livePresence(user.ID)
	if p2 != nil {
		t.Error("presence should be nil after setting inactive")
	}
}

// Test admin functions
func TestAdminFunctions(t *testing.T) {
	initTest()

	// Create admin user
	adminUser := createTestUser("admin", "Admin User")
	adminUser.Admin = true

	// Create regular user
	createTestUser("regular", "Regular User")

	adminSession := makeSession(adminUser)

	// Test admin users list
	req := httptest.NewRequest("GET", "/api/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "gymsid", Value: adminSession})
	w := httptest.NewRecorder()

	hAdminUsers(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	users, ok := body["users"].([]interface{})
	if !ok {
		t.Error("expected users array")
	}

	if len(users) < 2 {
		t.Errorf("expected at least 2 users, got %d", len(users))
	}

	// Test admin user detail
	req2 := httptest.NewRequest("GET", "/api/admin/user?id=regular", nil)
	req2.AddCookie(&http.Cookie{Name: "gymsid", Value: adminSession})
	w2 := httptest.NewRecorder()

	hAdminUser(w2, req2)

	resp2 := w2.Result()
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp2.StatusCode)
	}

	var body2 map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&body2)

	if body2["user"] == nil {
		t.Error("expected user in response")
	}

	// Test admin disable user
	disableBody := map[string]interface{}{
		"id":       "regular",
		"disabled": true,
	}
	disableBodyJSON, _ := json.Marshal(disableBody)

	req3 := httptest.NewRequest("POST", "/api/admin/user/disable", bytes.NewReader(disableBodyJSON))
	req3.Header.Set("Content-Type", "application/json")
	req3.AddCookie(&http.Cookie{Name: "gymsid", Value: adminSession})
	w3 := httptest.NewRecorder()

	hAdminUserDisable(w3, req3)

	resp3 := w3.Result()
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp3.StatusCode)
	}

	// Verify user is disabled
	dbMu.RLock()
	disabledUser := findUser("regular")
	dbMu.RUnlock()

	if disabledUser == nil || !disabledUser.Disabled {
		t.Error("user should be disabled")
	}
}

// Test invite system
func TestInviteSystem(t *testing.T) {
	initTest()

	// Create admin user
	adminUser := createTestUser("admin", "Admin User")
	adminUser.Admin = true

	adminSession := makeSession(adminUser)

	// Test create invite
	inviteBody := map[string]interface{}{
		"note": "Test invite",
	}
	inviteBodyJSON, _ := json.Marshal(inviteBody)

	req := httptest.NewRequest("POST", "/api/admin/invites/new", bytes.NewReader(inviteBodyJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "gymsid", Value: adminSession})
	w := httptest.NewRecorder()

	hAdminInvitesNew(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	invite, ok := body["invite"].(map[string]interface{})
	if !ok {
		t.Error("expected invite in response")
	}

	code, ok := invite["code"].(string)
	if !ok || code == "" {
		t.Error("expected code in invite")
	}

	// Test get invites list
	req2 := httptest.NewRequest("GET", "/api/admin/invites", nil)
	req2.AddCookie(&http.Cookie{Name: "gymsid", Value: adminSession})
	w2 := httptest.NewRecorder()

	hAdminInvites(w2, req2)

	resp2 := w2.Result()
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp2.StatusCode)
	}

	var body2 map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&body2)

	invites, ok := body2["invites"].([]interface{})
	if !ok {
		t.Error("expected invites array")
	}

	if len(invites) < 1 {
		t.Errorf("expected at least 1 invite, got %d", len(invites))
	}

	// Test revoke invite
	revokeBody := map[string]interface{}{
		"code": code,
	}
	revokeBodyJSON, _ := json.Marshal(revokeBody)

	req3 := httptest.NewRequest("POST", "/api/admin/invites/revoke", bytes.NewReader(revokeBodyJSON))
	req3.Header.Set("Content-Type", "application/json")
	req3.AddCookie(&http.Cookie{Name: "gymsid", Value: adminSession})
	w3 := httptest.NewRecorder()

	hAdminInvitesRevoke(w3, req3)

	resp3 := w3.Result()
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp3.StatusCode)
	}
}

// Test rest timer
func TestRestTimer(t *testing.T) {
	initTest()

	user := createTestUser("test-user", "Test User")
	session := makeSession(user)

	// Test schedule rest timer
	timerBody := map[string]interface{}{
		"seconds": 60.5,
	}
	timerBodyJSON, _ := json.Marshal(timerBody)

	req := httptest.NewRequest("POST", "/api/push/rest-timer", bytes.NewReader(timerBodyJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "gymsid", Value: session})
	w := httptest.NewRecorder()

	hRestTimer(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Test cancel rest timer
	req2 := httptest.NewRequest("POST", "/api/push/rest-timer/cancel", nil)
	req2.AddCookie(&http.Cookie{Name: "gymsid", Value: session})
	w2 := httptest.NewRecorder()

	hRestTimerCancel(w2, req2)

	resp2 := w2.Result()
	defer resp.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp2.StatusCode)
	}
}

// Test utility functions
func TestUtilityFunctions(t *testing.T) {
	// Test sign/verify
	secret = []byte("test-secret")
	payload := "test-payload"

	signed := sign(payload)

	verified, ok := verifySig(signed)
	if !ok {
		t.Error("verifySig should succeed")
	}

	if verified != payload {
		t.Errorf("expected %s, got %s", payload, verified)
	}

	// Test tampered signature
	tampered := signed + "x"
	_, ok2 := verifySig(tampered)
	if ok2 {
		t.Error("verifySig should fail for tampered signature")
	}

	// Test orNull
	testStr := "test"
	if orNull(testStr) != testStr {
		t.Errorf("orNull should return %s", testStr)
	}

	emptyStr := ""
	if orNull(emptyStr) != nil {
		t.Error("orNull should return nil for empty string")
	}

	// Test reverse
	arr := []interface{}{1, 2, 3, 4, 5}
	reverse(arr)

	if arr[0] != 5 || arr[4] != 1 {
		t.Error("reverse should reverse array")
	}

	// Test leftPad32
	short := []byte{0x01, 0x02, 0x03}
	padded := leftPad32(short)
	if len(padded) != 32 {
		t.Errorf("expected length 32, got %d", len(padded))
	}

	if padded[29] != 0x01 || padded[30] != 0x02 || padded[31] != 0x03 {
		t.Error("leftPad32 should pad correctly")
	}
}

// Test WebAuthn credential conversion
func TestCredToWebauthn(t *testing.T) {
	cred := &Cred{
		ID:         base64.RawURLEncoding.EncodeToString([]byte("test-id")),
		PublicKey:  base64.RawURLEncoding.EncodeToString([]byte("test-public-key")),
		Transports: []string{"usb", "nfc"},
	}

	wc, err := credToWebauthn(cred)
	if err != nil {
		t.Errorf("credToWebauthn failed: %v", err)
	}

	if string(wc.ID) != "test-id" {
		t.Errorf("expected ID 'test-id', got %s", string(wc.ID))
	}

	if len(wc.Transport) != 2 {
		t.Errorf("expected 2 transports, got %d", len(wc.Transport))
	}
}

// Test challenge store
func TestChallengeStore(t *testing.T) {
	initTest()

	session := webauthn.SessionData{
		Challenge: "test-challenge",
	}

	entry := &challengeEntry{
		session: session,
		name:    "Test User",
		uid:     "test-uid",
		code:    "TEST123",
	}

	cid := putChallenge(entry)

	if cid == "" {
		t.Error("putChallenge should return non-empty cid")
	}

	taken := takeChallenge(cid)
	if taken == nil {
		t.Error("takeChallenge should return entry")
	}

	if taken.name != "Test User" {
		t.Errorf("expected name 'Test User', got %s", taken.name)
	}

	// Should not be found again
	taken2 := takeChallenge(cid)
	if taken2 != nil {
		t.Error("takeChallenge should return nil after removal")
	}
}

// Test URL origin extraction
func TestUrlOrigin(t *testing.T) {
	tests := []struct {
		endpoint string
		expected string
		hasError bool
	}{
		{"https://push.example.com/test", "https://push.example.com", false},
		{"http://localhost:8080/test", "http://localhost:8080", false},
		{"invalid", "", true},
		{"https://example.com", "https://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			origin, err := urlOrigin(tt.endpoint)
			if tt.hasError {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if origin != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, origin)
			}
		})
	}
}

// Test indexOf function
func TestIndexOf(t *testing.T) {
	tests := []struct {
		s        string
		sub      string
		expected int
	}{
		{"hello world", "world", 6},
		{"hello world", "hello", 0},
		{"hello world", "xyz", -1},
		{"", "a", -1},
		{"abc", "", 0},
	}

	for _, tt := range tests {
		result := indexOf(tt.s, tt.sub)
		if result != tt.expected {
			t.Errorf("indexOf(%s, %s) = %d, expected %d", tt.s, tt.sub, result, tt.expected)
		}
	}
}

// Test HKDF functions
func TestHKDF(t *testing.T) {
	salt := make([]byte, 16)
	rand.Read(salt)

	ikm := make([]byte, 32)
	rand.Read(ikm)

	prk := hkdfExtract(salt, ikm)
	if len(prk) != 32 {
		t.Errorf("hkdfExtract should return 32 bytes, got %d", len(prk))
	}

	info := []byte("test-info")
	okm := hkdfExpand(prk, info, 16)
	if len(okm) != 16 {
		t.Errorf("hkdfExpand should return 16 bytes, got %d", len(okm))
	}
}

// Test push encryption error cases
func TestEncryptPayloadErrors(t *testing.T) {
	// Test with invalid p256dh
	_, err := encryptPayload([]byte("test"), "invalid!", "test-auth")
	if err == nil {
		t.Error("expected error for invalid p256dh")
	}

	// Test with invalid auth
	_, err = encryptPayload([]byte("test"), base64.RawURLEncoding.EncodeToString([]byte("valid")), "invalid!")
	if err == nil {
		t.Error("expected error for invalid auth")
	}
}

// Test state file path sanitization
func TestStateFilePath(t *testing.T) {
	uid := "test-user/../dangerous"
	path := stateFilePath(uid)

	if filepath.Base(path) != "state-test-userdangerous.json" {
		t.Errorf("state path should be sanitized, got %s", path)
	}
}

// Benchmark session creation
func BenchmarkMakeSession(b *testing.B) {
	initTest()
	user := createTestUser("test-user", "Test User")

	for i := 0; i < b.N; i++ {
		makeSession(user)
	}
}

// Benchmark JSON marshaling
func BenchmarkJSONMarshal(b *testing.B) {
	data := map[string]interface{}{
		"workouts": []interface{}{
			map[string]interface{}{
				"d":  "2024-01-01",
				"ex": []interface{}{},
			},
		},
	}

	for i := 0; i < b.N; i++ {
		json.Marshal(data)
	}
}

// Test concurrent access to db
func TestConcurrentDB(t *testing.T) {
	initTest()

	// Start multiple goroutines accessing db
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			dbMu.Lock()
			db.Users = append(db.Users, &User{ID: "test", Name: "Test"})
			dbMu.Unlock()
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	dbMu.RLock()
	count := len(db.Users)
	dbMu.RUnlock()

	if count < 10 {
		t.Errorf("expected at least 10 users, got %d", count)
	}
}

// Test invitation validation
func TestInviteValidation(t *testing.T) {
	initTest()

	// Enable invite only mode
	inviteOnly = true

	// Create valid invite
	createTestInvite("VALID123")

	// Create used invite
	usedInvite := createTestInvite("USED456")
	usedInvite.UsedBy = "user"

	// Create revoked invite
	revokedInvite := createTestInvite("REVOKED789")
	revokedInvite.Revoked = true

	// Test registration with valid invite
	regBody := map[string]interface{}{
		"name": "Test User",
		"code": "VALID123",
	}
	regBodyJSON, _ := json.Marshal(regBody)

	req := httptest.NewRequest("POST", "/api/register/options", bytes.NewReader(regBodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	hRegisterOptions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 with valid invite, got %d", w.Code)
	}

	// Test registration with used invite
	regBody2 := map[string]interface{}{
		"name": "Test User 2",
		"code": "USED456",
	}
	regBodyJSON2, _ := json.Marshal(regBody2)

	req2 := httptest.NewRequest("POST", "/api/register/options", bytes.NewReader(regBodyJSON2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()

	hRegisterOptions(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("expected status 403 with used invite, got %d", w2.Code)
	}

	// Test registration with revoked invite
	regBody3 := map[string]interface{}{
		"name": "Test User 3",
		"code": "REVOKED789",
	}
	regBodyJSON3, _ := json.Marshal(regBody3)

	req3 := httptest.NewRequest("POST", "/api/register/options", bytes.NewReader(regBodyJSON3))
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()

	hRegisterOptions(w3, req3)

	if w3.Code != http.StatusForbidden {
		t.Errorf("expected status 403 with revoked invite, got %d", w3.Code)
	}

	// Turn off invite only
	inviteOnly = false
}
