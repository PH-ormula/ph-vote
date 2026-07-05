package api

// Endpoints
const (
	PathRequestMagicLink = "/api/request-magic-link"
	PathSignToken        = "/api/sign-token"
	PathVote             = "/api/vote"
	PathAdminVotes       = "/api/admin/votes"
	PathAdminClearDB     = "/api/admin/clear"
	PathResults          = "/api/results"
	PathConfig           = "/api/config" // Exposes safe config to frontend
)

// MagicLinkReq is sent to request a magic link (OTP) to the given email
type MagicLinkReq struct {
	Email string `json:"email"`
}

// SignTokenReq is sent to blind-sign a token using the OTP from the magic link
type SignTokenReq struct {
	OTP          string `json:"otp"`
	BlindedToken []byte `json:"blinded_token"`
}

// SignTokenRes returns the signature from the server
type SignTokenRes struct {
	BlindedSignature []byte `json:"blinded_signature"`
	PublicKey        []byte `json:"public_key"` // PEM encoded
}

// VoteReq is the final unblinded vote submission
type VoteReq struct {
	Token     []byte `json:"token"`
	Signature []byte `json:"signature"`
	Option    string `json:"option"`
}

type AdminReq struct {
	Password string `json:"password"`
}

type AdminRes struct {
	Votes      map[string]int `json:"votes"`
	UsedTokens []string       `json:"used_tokens"`
}

type Candidate struct {
	ID   string `json:"id" toml:"id"`
	Name string `json:"name" toml:"name"`
	HTML string `json:"html" toml:"html"`
}

type ConfigRes struct {
	Title     string      `json:"title"`
	Options   []Candidate `json:"options"`
	PublicKey []byte      `json:"public_key"`
}
