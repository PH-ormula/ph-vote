package backend

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB() {
	var err error
	DB, err = sql.Open("sqlite", "./vote.db")
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}

	createTables := `
	CREATE TABLE IF NOT EXISTS email_logs (
		email_hash TEXT PRIMARY KEY,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS otps (
		otp TEXT PRIMARY KEY,
		email_hash TEXT,
		expires_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS used_tokens (
		token_hash TEXT PRIMARY KEY,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS votes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		option TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = DB.Exec(createTables)
	if err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}
}

func HashEmail(email string) string {
	h := sha256.Sum256([]byte(email))
	return hex.EncodeToString(h[:])
}

func HashToken(token []byte) string {
	h := sha256.Sum256(token)
	return hex.EncodeToString(h[:])
}

// SetOTP stores an OTP for a hashed email, valid for 10 minutes
func SetOTP(otp, email string) error {
	hash := HashEmail(email)
	expiresAt := time.Now().Add(10 * time.Minute)
	_, err := DB.Exec("INSERT INTO otps (otp, email_hash, expires_at) VALUES (?, ?, ?)", otp, hash, expiresAt)
	return err
}

// VerifyAndConsumeOTP checks if OTP exists and is valid, returns true if valid and deletes it
func VerifyAndConsumeOTP(otp string) bool {
	var expiresAt time.Time
	var emailHash string
	err := DB.QueryRow("SELECT expires_at, email_hash FROM otps WHERE otp = ?", otp).Scan(&expiresAt, &emailHash)
	if err != nil {
		return false
	}

	_, _ = DB.Exec("DELETE FROM otps WHERE otp = ?", otp)

	if time.Now().After(expiresAt) {
		return false
	}

	// Also ensure email hasn't already voted (received signature)
	var count int
	_ = DB.QueryRow("SELECT COUNT(*) FROM email_logs WHERE email_hash = ?", emailHash).Scan(&count)
	if count > 0 {
		return false
	}

	// Mark email as having received signature
	_, _ = DB.Exec("INSERT INTO email_logs (email_hash) VALUES (?)", emailHash)

	return true
}

func RecordVote(token []byte, option string) error {
	tokenHash := HashToken(token)

	// Check if token was already used
	var count int
	_ = DB.QueryRow("SELECT COUNT(*) FROM used_tokens WHERE token_hash = ?", tokenHash).Scan(&count)
	if count > 0 {
		return fmt.Errorf("token already used")
	}

	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec("INSERT INTO used_tokens (token_hash) VALUES (?)", tokenHash)
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT INTO votes (option) VALUES (?)", option)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func GetVotes() (map[string]int, error) {
	rows, err := DB.Query("SELECT option, COUNT(*) FROM votes GROUP BY option")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	votes := make(map[string]int)
	for rows.Next() {
		var option string
		var count int
		if err := rows.Scan(&option, &count); err != nil {
			return nil, err
		}
		votes[option] = count
	}
	return votes, nil
}
