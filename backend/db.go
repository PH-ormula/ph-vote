package backend

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

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
		email_hash TEXT
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

// SetOTP stores an OTP for a hashed email
func SetOTP(otp, email string) error {
	hash := HashEmail(email)
	_, err := DB.Exec("INSERT INTO otps (otp, email_hash) VALUES (?, ?)", otp, hash)
	return err
}

var ErrOTPNotFound = errors.New("OTP not found")
var ErrAlreadyVoted = errors.New("email already voted")

// VerifyAndConsumeOTP checks if OTP exists and is valid. Returns error if invalid or already voted.
func VerifyAndConsumeOTP(otp string) error {
	var emailHash string
	err := DB.QueryRow("SELECT email_hash FROM otps WHERE otp = ?", otp).Scan(&emailHash)
	if err != nil {
		return ErrOTPNotFound
	}

	// Also ensure email hasn't already voted (received signature)
	var count int
	_ = DB.QueryRow("SELECT COUNT(*) FROM email_logs WHERE email_hash = ?", emailHash).Scan(&count)
	if count > 0 {
		return ErrAlreadyVoted
	}

	// Mark email as having received signature
	_, _ = DB.Exec("INSERT INTO email_logs (email_hash) VALUES (?)", emailHash)
	// We don't delete the OTP here so that if they click the link again,
	// it can still map to their email and correctly identify they've already voted.

	return nil
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

// ClearDB removes all votes and used tokens
func ClearDB() error {
	if _, err := DB.Exec("DELETE FROM used_tokens"); err != nil {
		return err
	}
	if _, err := DB.Exec("DELETE FROM email_logs"); err != nil {
		return err
	}
	if _, err := DB.Exec("DELETE FROM otps"); err != nil {
		return err
	}
	if _, err := DB.Exec("DELETE FROM votes"); err != nil {
		return err
	}
	return nil
}
