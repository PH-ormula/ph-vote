package backend

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"sync"

	"ph-vote/api"
	"ph-vote/config"
)

// GenerateOTP creates a high-entropy 32-byte magic link secret
func GenerateOTP() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SendEmail sends a real email using SMTP configuration
func SendEmail(to, otp string) error {
	smtpConfig := config.Current.SMTP
	auth := smtp.PlainAuth("", smtpConfig.User, smtpConfig.Pass, smtpConfig.Host)
	
	from := smtpConfig.User
	subject := "Your Ph-Vote Magic Link"
	body := fmt.Sprintf("Click here to vote securely: %s/?otp=%s\n", config.Current.BaseURL, otp)
	
	msg := []byte("From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n\r\n" +
		body)
		
	addr := fmt.Sprintf("%s:%d", smtpConfig.Host, smtpConfig.Port)
	log.Printf("Sending email to %s via %s", to, addr)
	return smtp.SendMail(addr, auth, from, []string{to}, msg)
}

func HandleRequestMagicLink(w http.ResponseWriter, r *http.Request) {
	var req api.MagicLinkReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	for _, adminEmail := range config.Current.AdminEmails {
		if req.Email == strings.ToLower(strings.TrimSpace(adminEmail)) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"isAdmin": true})
			return
		}
	}

	if !strings.HasSuffix(req.Email, strings.ToLower(strings.TrimSpace(config.Current.AllowedSuffix))) {
		log.Printf("Suffix check failed: req.Email=%q, allowed=%q", req.Email, config.Current.AllowedSuffix); http.Error(w, "Email suffix not allowed", http.StatusForbidden)
		return
	}

	otp, err := GenerateOTP()
	if err != nil {
		http.Error(w, "Failed to generate OTP", http.StatusInternalServerError)
		return
	}

	if err := SetOTP(otp, req.Email); err != nil {
		http.Error(w, "Failed to save OTP", http.StatusInternalServerError)
		return
	}

	link := fmt.Sprintf("%s/?otp=%s", config.Current.BaseURL, otp)
	log.Printf("\n--- MAGIC LINK ---\nTo: %s\nLink: %s\n------------------\n", req.Email, link)

	if !config.Current.SkipEmail {
		if err := SendEmail(req.Email, otp); err != nil {
			log.Printf("Failed to send email to %s: %v", req.Email, err)
			http.Error(w, "Failed to send email", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

var signMutex sync.Mutex

func HandleSignToken(w http.ResponseWriter, r *http.Request) {
	var req api.SignTokenReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	signMutex.Lock()
	defer signMutex.Unlock()

	rec, err := GetOTPRecord(req.OTP)
	if err != nil {
		http.Error(w, "Invalid OTP", http.StatusUnauthorized)
		return
	}

	reqBlindedHex := hex.EncodeToString(req.BlindedToken)

	var sig []byte
	if rec.BlindedToken != "" {
		// Already received a signature
		if rec.BlindedToken == reqBlindedHex {
			// Idempotent recovery! Return the saved signature.
			sig, _ = hex.DecodeString(rec.BlindedSignature)
			log.Printf("[SignToken] Idempotent recovery for OTP: %s", req.OTP)
		} else {
			// Hacked client trying to get a second signature
			log.Printf("[SignToken] 409 Conflict.\nOTP: %s\nSaved: %s\nReceived: %s", req.OTP, rec.BlindedToken, reqBlindedHex)
			http.Error(w, "already_voted", http.StatusConflict) // 409
			return
		}
	} else {
		// New signature request
		sig, err = SignToken(req.BlindedToken)
		if err != nil {
			http.Error(w, "Failed to sign token", http.StatusInternalServerError)
			return
		}

		// Save it so it can be recovered later
		sigHex := hex.EncodeToString(sig)
		if err := SaveOTPSignature(req.OTP, reqBlindedHex, sigHex); err != nil {
			http.Error(w, "Failed to save signature", http.StatusInternalServerError)
			return
		}
		
		// Mark email as having received a signature
		if err := LogEmailSignature(rec.EmailHash); err != nil {
			log.Printf("Failed to log email signature: %v", err)
		}
	}

	res := api.SignTokenRes{
		BlindedSignature: sig,
		PublicKey:        GetPublicKey(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func HandleVote(w http.ResponseWriter, r *http.Request) {
	var req api.VoteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := VerifyToken(req.Token, req.Signature); err != nil {
		http.Error(w, "Invalid signature: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Record the vote
	if err := RecordVote(req.Token, req.Option); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func HandleAdminVotes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req api.AdminReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Password != config.Current.AdminPassword {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	votes, err := GetVotes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api.AdminRes{Votes: votes})
}

// HandleResults returns the results without a password
func HandleResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	votes, err := GetVotes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api.AdminRes{Votes: votes})
}

func HandleAdminClearDB(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req api.AdminReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Password != config.Current.AdminPassword {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := ClearDB(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func HandleConfig(w http.ResponseWriter, r *http.Request) {
	res := api.ConfigRes{
		Title:     config.Current.Title,
		Options:   config.Current.Options,
		PublicKey: GetPublicKey(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}
