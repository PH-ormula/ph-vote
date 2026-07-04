package backend

import (
	"database/sql"
	"os"
	"testing"
)

func TestDBFeatures(t *testing.T) {
	_ = os.Remove("test_vote.db")
	var err error
	DB, err = sql.Open("sqlite", "test_vote.db")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer os.Remove("test_vote.db")

	createTables := `
	CREATE TABLE IF NOT EXISTS email_logs (email_hash TEXT PRIMARY KEY, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	CREATE TABLE IF NOT EXISTS otps (otp_hash TEXT PRIMARY KEY, email_hash TEXT, blinded_token TEXT, blinded_signature TEXT);
	CREATE TABLE IF NOT EXISTS used_tokens (token_hash TEXT PRIMARY KEY, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	CREATE TABLE IF NOT EXISTS votes (id INTEGER PRIMARY KEY AUTOINCREMENT, option TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	`
	_, err = DB.Exec(createTables)
	if err != nil {
		t.Fatalf("Failed to create tables: %v", err)
	}

	t.Run("ClearDB", func(t *testing.T) {
		DB.Exec("INSERT INTO votes (option) VALUES ('A')")
		DB.Exec("INSERT INTO email_logs (email_hash) VALUES ('hash1')")
		DB.Exec("INSERT INTO otps (otp_hash, email_hash) VALUES ('123', 'hash1')")
		DB.Exec("INSERT INTO used_tokens (token_hash) VALUES ('tok1')")

		if err := ClearDB(); err != nil {
			t.Fatalf("ClearDB failed: %v", err)
		}

		var count int
		DB.QueryRow("SELECT COUNT(*) FROM votes").Scan(&count)
		if count != 0 {
			t.Errorf("Expected votes to be empty, got %d", count)
		}
		DB.QueryRow("SELECT COUNT(*) FROM email_logs").Scan(&count)
		if count != 0 {
			t.Errorf("Expected email_logs to be empty, got %d", count)
		}
		DB.QueryRow("SELECT COUNT(*) FROM otps").Scan(&count)
		if count != 0 {
			t.Errorf("Expected otps to be empty, got %d", count)
		}
	})

	t.Run("GetOTPRecord and SaveOTPSignature", func(t *testing.T) {
		email := "test@example.com"
		otp := "654321"

		if err := SetOTP(otp, email); err != nil {
			t.Fatalf("SetOTP failed: %v", err)
		}

		rec, err := GetOTPRecord(otp)
		if err != nil {
			t.Fatalf("Expected nil, got %v", err)
		}
		if rec.BlindedToken != "" {
			t.Fatalf("Expected empty blinded token")
		}

		err = SaveOTPSignature(otp, "blind_tok", "blind_sig")
		if err != nil {
			t.Fatalf("SaveOTPSignature failed: %v", err)
		}
		
		rec2, err := GetOTPRecord(otp)
		if err != nil {
			t.Fatalf("Expected nil, got %v", err)
		}
		if rec2.BlindedToken != "blind_tok" {
			t.Fatalf("Expected 'blind_tok', got %v", rec2.BlindedToken)
		}
	})
}
