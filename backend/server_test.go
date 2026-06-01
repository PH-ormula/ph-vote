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

	createTables := `
	CREATE TABLE IF NOT EXISTS email_logs (email_hash TEXT PRIMARY KEY, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	CREATE TABLE IF NOT EXISTS otps (otp TEXT PRIMARY KEY, email_hash TEXT, expires_at DATETIME);
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
			t.Errorf("Expected 200 OK, got %d", w.Code)
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
			t.Errorf("Expected 200 OK, got %d", w.Code)
		}

		var count int
		DB.QueryRow("SELECT COUNT(*) FROM votes").Scan(&count)
		if count != 0 {
			t.Errorf("Expected DB to be cleared")
		}
	})

	t.Run("HandleSignToken_AlreadyVoted", func(t *testing.T) {
		otp := "999999"
		SetOTP(otp, "user@test.com")
		VerifyAndConsumeOTP(otp) // Simulate first vote

		reqBody, _ := json.Marshal(api.SignTokenReq{OTP: otp, BlindedToken: []byte("blind")})
		req := httptest.NewRequest(http.MethodPost, "/api/sign-token", bytes.NewBuffer(reqBody))
		w := httptest.NewRecorder()
		HandleSignToken(w, req)

		if w.Code != http.StatusConflict {
			t.Errorf("Expected 409 Conflict, got %d", w.Code)
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
}
