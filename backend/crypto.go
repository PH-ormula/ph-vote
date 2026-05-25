package backend

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/linckode/circl/blindsign/blindrsa"
)

var (
	rsaKey    *rsa.PrivateKey
	rsaPubKey []byte
	Signer    *blindrsa.Signer
)

// InitCrypto generates a new RSA keypair for the blind signatures each time the server starts.
// In a real production environment, you might want to save and load this key.
func InitCrypto() error {
	var err error
	rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	s := blindrsa.NewSigner(rsaKey)
	Signer = &s

	// Encode public key to PEM so we can send it to the frontend
	pubASN1, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return err
	}

	rsaPubKey = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return nil
}

// SignToken takes a blinded message and signs it
func SignToken(blindedMessage []byte) ([]byte, error) {
	if Signer == nil {
		return nil, errors.New("signer not initialized")
	}
	return Signer.BlindSign(blindedMessage)
}

// GetPublicKey returns the PEM encoded public key
func GetPublicKey() []byte {
	return rsaPubKey
}

// VerifyToken verifies the final unblinded signature.
// circl's blindrsa.SHA384PSSRandomized uses SHA384 and PSS.
func VerifyToken(token []byte, sig []byte) error {
	// Reconstruct the message as prepared by blindrsa.
	// Actually, blindrsa Prepare() prefixes the message. 
	// To be perfectly safe, we should use the blindrsa Client to Verify.
	client, err := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, &rsaKey.PublicKey)
	if err != nil {
		return err
	}
	return client.Verify(token, sig)
}
