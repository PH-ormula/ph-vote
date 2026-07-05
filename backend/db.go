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

	// Migration: Drop old otps table if it lacks the blinded_token column
	var count int
	err = DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('otps') WHERE name='blinded_token'").Scan(&count)
	if err == nil && count == 0 {
		DB.Exec("DROP TABLE IF EXISTS otps")
	}

	createTables := `
	CREATE TABLE IF NOT EXISTS email_logs (
		email_hash TEXT PRIMARY KEY,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS otps (
		otp_hash TEXT PRIMARY KEY,
		email_hash TEXT,
		blinded_token TEXT,
		blinded_signature TEXT
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

func HashOTP(otp string) string {
	h := sha256.Sum256([]byte(otp))
	return hex.EncodeToString(h[:])
}

// SetOTP stores an OTP for a hashed email
func SetOTP(otp, email string) error {
	otpHash := HashOTP(otp)
	emailHash := HashEmail(email)
	_, err := DB.Exec("INSERT INTO otps (otp_hash, email_hash, blinded_token, blinded_signature) VALUES (?, ?, '', '')", otpHash, emailHash)
	return err
}

var ErrOTPNotFound = errors.New("OTP not found")
var ErrAlreadyVoted = errors.New("email already voted")

type OTPRecord struct {
	EmailHash        string
	BlindedToken     string
	BlindedSignature string
}

func GetOTPRecord(otp string) (*OTPRecord, error) {
	otpHash := HashOTP(otp)
	var rec OTPRecord
	err := DB.QueryRow("SELECT email_hash, blinded_token, blinded_signature FROM otps WHERE otp_hash = ?", otpHash).Scan(&rec.EmailHash, &rec.BlindedToken, &rec.BlindedSignature)
	if err != nil {
		return nil, ErrOTPNotFound
	}
	return &rec, nil
}

func SaveOTPSignature(otp string, blindedToken string, blindedSignature string) error {
	otpHash := HashOTP(otp)
	_, err := DB.Exec("UPDATE otps SET blinded_token = ?, blinded_signature = ? WHERE otp_hash = ?", blindedToken, blindedSignature, otpHash)
	return err
}

func LogEmailSignature(emailHash string) error {
	_, err := DB.Exec("INSERT OR IGNORE INTO email_logs (email_hash) VALUES (?)", emailHash)
	return err
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

// GetUsedTokens returns a list of all used token hashes
func GetUsedTokens() ([]string, error) {
	rows, err := DB.Query("SELECT token_hash FROM used_tokens")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var tokenHash string
		if err := rows.Scan(&tokenHash); err != nil {
			return nil, err
		}
		tokens = append(tokens, tokenHash)
	}
	return tokens, nil
}
