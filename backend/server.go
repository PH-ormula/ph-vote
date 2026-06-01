package backend

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"ph-vote/api"
	"ph-vote/config"
)

// GenerateOTP creates a simple numeric 6-digit OTP
func GenerateOTP() (string, error) {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// SendMockEmail simulates sending an email
func SendMockEmail(to, otp string) {
	log.Printf("\n--- MOCK EMAIL ---\nTo: %s\nSubject: Your Ph-Vote Magic Link\nBody: Click here to vote securely: http://localhost:8080/?otp=%s\n------------------\n", to, otp)
}

func HandleRequestMagicLink(w http.ResponseWriter, r *http.Request) {
	var req api.MagicLinkReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for _, adminEmail := range config.Current.AdminEmails {
		if req.Email == adminEmail {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"isAdmin": true})
			return
		}
	}

	if !strings.HasSuffix(req.Email, config.Current.AllowedSuffix) {
		http.Error(w, "Email suffix not allowed", http.StatusForbidden)
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

	// In a real app, send actual email using config.Current.SMTP
	SendMockEmail(req.Email, otp)
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

	err := VerifyAndConsumeOTP(req.OTP)
	if err == ErrAlreadyVoted {
		http.Error(w, "already_voted", http.StatusConflict) // 409
		return
	} else if err != nil {
		http.Error(w, "Invalid or expired OTP", http.StatusUnauthorized)
		return
	}

	sig, err := SignToken(req.BlindedToken)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
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
