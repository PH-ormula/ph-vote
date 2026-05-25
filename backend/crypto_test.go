package backend

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/linckode/circl/blindsign/blindrsa"
)

func TestBlindRSA(t *testing.T) {
	// 1. Generate Server Key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := blindrsa.NewSigner(serverKey)

	// Encode public key to PEM
	pubASN1, err := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	// 2. Client Side
	rawToken := make([]byte, 32)
	rand.Read(rawToken)

	block, _ := pem.Decode(pubPEM)
	pubKeyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := pubKeyAny.(*rsa.PublicKey)

	client, err := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, pubKey)
	if err != nil {
		t.Fatal(err)
	}

	prepared, err := client.Prepare(rand.Reader, rawToken)
	if err != nil {
		t.Fatal(err)
	}

	blindedToken, state, err := client.Blind(rand.Reader, prepared)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Server Side Sign
	sig, err := server.BlindSign(blindedToken)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Client Side Unblind
	finalSig, err := client.Finalize(state, sig)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Server Side Verify
	err = client.Verify(prepared, finalSig)
	if err != nil {
		t.Fatalf("Client verify failed: %v", err)
	}
}
