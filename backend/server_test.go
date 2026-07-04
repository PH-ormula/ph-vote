package backend

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
    
	"ph-vote/api"
	"ph-vote/config"

	"crypto/rand"
	"github.com/linckode/circl/blindsign/blindrsa"
)

func TestServerFeatures(t *testing.T) {
	config.Current = &config.AppConfig{
		AdminPassword: "testadminpass",
	}

	_ = os.Remove("server_test.db")
	var err error
	DB, err = sql.Open("sqlite", "server_test.db")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer os.Remove("server_test.db")

	err = InitCrypto()
	if err != nil {
		t.Fatalf("Failed to init keys: %v", err)
	}

	createTables := `
	CREATE TABLE IF NOT EXISTS email_logs (email_hash TEXT PRIMARY KEY, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	CREATE TABLE IF NOT EXISTS otps (otp_hash TEXT PRIMARY KEY, email_hash TEXT, blinded_token TEXT, blinded_signature TEXT);
	CREATE TABLE IF NOT EXISTS used_tokens (token_hash TEXT PRIMARY KEY, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	CREATE TABLE IF NOT EXISTS votes (id INTEGER PRIMARY KEY AUTOINCREMENT, option TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	`
	DB.Exec(createTables)

	t.Run("HandleResults", func(t *testing.T) {
		DB.Exec("DELETE FROM votes")
		DB.Exec("INSERT INTO votes (option) VALUES ('Option1')")
		DB.Exec("INSERT INTO votes (option) VALUES ('Option1')")

		req := httptest.NewRequest(http.MethodGet, "/api/results", nil)
		w := httptest.NewRecorder()

		HandleResults(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d: %s", w.Code, w.Body.String())
		}

		var res api.AdminRes
		if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if res.Votes["Option1"] != 2 {
			t.Errorf("Expected 2 votes for Option1, got %v", res.Votes)
		}
	})

	t.Run("HandleAdminClearDB", func(t *testing.T) {
		reqBody, _ := json.Marshal(api.AdminReq{Password: "wrongpass"})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/clear", bytes.NewBuffer(reqBody))
		w := httptest.NewRecorder()
		HandleAdminClearDB(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}

		reqBody, _ = json.Marshal(api.AdminReq{Password: "testadminpass"})
		req = httptest.NewRequest(http.MethodPost, "/api/admin/clear", bytes.NewBuffer(reqBody))
		w = httptest.NewRecorder()
		HandleAdminClearDB(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d: %s", w.Code, w.Body.String())
		}

		var count int
		DB.QueryRow("SELECT COUNT(*) FROM votes").Scan(&count)
		if count != 0 {
			t.Errorf("Expected DB to be cleared")
		}
	})

	t.Run("HandleSignToken_Idempotency", func(t *testing.T) {
		otp := "999999"
		SetOTP(otp, "user@test.com")
		
		client, err := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, &rsaKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		msg1 := make([]byte, 32)
		prepared1, _ := client.Prepare(rand.Reader, msg1)
		blind1, _, _ := client.Blind(rand.Reader, prepared1)
		
		msg2 := make([]byte, 32)
		prepared2, _ := client.Prepare(rand.Reader, msg2)
		blind2, _, _ := client.Blind(rand.Reader, prepared2)

		// First signature request
		reqBody, _ := json.Marshal(api.SignTokenReq{OTP: otp, BlindedToken: blind1})
		req := httptest.NewRequest(http.MethodPost, "/api/sign-token", bytes.NewBuffer(reqBody))
		w := httptest.NewRecorder()
		HandleSignToken(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d: %s", w.Code, w.Body.String())
		}

		// Second request with SAME blinded token (recovery)
		req2 := httptest.NewRequest(http.MethodPost, "/api/sign-token", bytes.NewBuffer(reqBody))
		w2 := httptest.NewRecorder()
		HandleSignToken(w2, req2)
		if w2.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for identical token recovery, got %d: %s", w2.Code, w2.Body.String())
		}

		// Third request with DIFFERENT blinded token
		reqBody3, _ := json.Marshal(api.SignTokenReq{OTP: otp, BlindedToken: blind2})
		req3 := httptest.NewRequest(http.MethodPost, "/api/sign-token", bytes.NewBuffer(reqBody3))
		w3 := httptest.NewRecorder()
		HandleSignToken(w3, req3)
		if w3.Code != http.StatusConflict {
			t.Errorf("Expected 409 Conflict for different token, got %d: %s", w3.Code, w3.Body.String())
		}
	})

	t.Run("HandleRequestMagicLink_Admin", func(t *testing.T) {
		config.Current.AdminEmails = []string{"admin1@test.com", "admin2@test.com"}
		
		// Test standard email (should not return isAdmin)
		reqBody, _ := json.Marshal(api.MagicLinkReq{Email: "user@test.com"})
		req := httptest.NewRequest(http.MethodPost, "/api/request-magic-link", bytes.NewBuffer(reqBody))
		w := httptest.NewRecorder()
		HandleRequestMagicLink(w, req)
		
		var res map[string]bool
		json.NewDecoder(w.Body).Decode(&res)
		if res["isAdmin"] {
			t.Errorf("Expected isAdmin false for normal user")
		}

		// Test admin email
		reqBody, _ = json.Marshal(api.MagicLinkReq{Email: "admin2@test.com"})
		req = httptest.NewRequest(http.MethodPost, "/api/request-magic-link", bytes.NewBuffer(reqBody))
		w = httptest.NewRecorder()
		HandleRequestMagicLink(w, req)

		var resAdmin map[string]bool
		json.NewDecoder(w.Body).Decode(&resAdmin)
		if !resAdmin["isAdmin"] {
			t.Errorf("Expected isAdmin true for admin email")
		}
	})

	t.Run("HandleRequestMagicLink_NormalUser", func(t *testing.T) {
		config.Current.AllowedSuffix = "@shphschool.com"
		config.Current.SkipEmail = true

		testCases := []struct {
			name     string
			email    string
			expected int
		}{
			{"Valid email exact", "asdf@shphschool.com", http.StatusOK},
			{"Valid email uppercase", "ASDF@SHPHSCHOOL.COM", http.StatusOK},
			{"Valid email trailing space", "asdf@shphschool.com ", http.StatusOK},
			{"Invalid suffix domain", "asdf@gmail.com", http.StatusForbidden},
			{"Invalid suffix substring", "asdf@shphschool.community", http.StatusForbidden},
			{"Empty email", "", http.StatusForbidden},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				reqBody, _ := json.Marshal(api.MagicLinkReq{Email: tc.email})
				req := httptest.NewRequest(http.MethodPost, "/api/request-magic-link", bytes.NewBuffer(reqBody))
				w := httptest.NewRecorder()
				HandleRequestMagicLink(w, req)

				if w.Code != tc.expected {
					t.Errorf("Expected %d for %s, got %d: %s", tc.expected, tc.email, w.Code, w.Body.String())
				}
			})
		}
	})
}
