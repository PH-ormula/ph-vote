package frontend

import (
	"crypto/rsa"
	"testing"

	"github.com/linckode/circl/blindsign/blindrsa"
)

func TestDeterministicReader(t *testing.T) {
	otp := "test_otp_string"
	
	// Create mock server key using our deterministic reader for the seed
	dr0 := newDeterministicReader("server_seed")
	privKey, err := rsa.GenerateKey(dr0, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test RSA key: %v", err)
	}

	// First execution simulation
	dr1 := newDeterministicReader(otp)
	rawToken1 := make([]byte, 32)
	dr1.Read(rawToken1)
	client1, _ := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, &privKey.PublicKey)
	prepared1, err := client1.Prepare(dr1, rawToken1)
	if err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}
	blindedToken1, _, err := client1.Blind(dr1, prepared1)
	if err != nil {
		t.Fatalf("Blind failed: %v", err)
	}

	// Second execution simulation
	dr2 := newDeterministicReader(otp)
	rawToken2 := make([]byte, 32)
	dr2.Read(rawToken2)
	client2, _ := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, &privKey.PublicKey)
	prepared2, err := client2.Prepare(dr2, rawToken2)
	if err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}
	blindedToken2, _, err := client2.Blind(dr2, prepared2)
	if err != nil {
		t.Fatalf("Blind failed: %v", err)
	}

	// The tokens must be perfectly identical
	if string(blindedToken1) != string(blindedToken2) {
		t.Fatalf("Tokens do not match!\nToken 1: %x\nToken 2: %x", blindedToken1[:10], blindedToken2[:10])
	}
	
	// Ensure that using a different OTP yields a different token
	dr3 := newDeterministicReader(otp + "different")
	rawToken3 := make([]byte, 32)
	dr3.Read(rawToken3)
	client3, _ := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, &privKey.PublicKey)
	prepared3, _ := client3.Prepare(dr3, rawToken3)
	blindedToken3, _, _ := client3.Blind(dr3, prepared3)
	
	if string(blindedToken1) == string(blindedToken3) {
		t.Fatalf("Different OTP generated identical token!")
	}
}

// Test deterministic generation
func TestNewDeterministicReader_Consistency(t *testing.T) {
	dr1 := newDeterministicReader("seed1")
	dr2 := newDeterministicReader("seed1")
	
	b1 := make([]byte, 100)
	b2 := make([]byte, 100)
	
	dr1.Read(b1)
	dr2.Read(b2)
	
	if string(b1) != string(b2) {
		t.Fatalf("Deterministic reader produced different bytes for same seed")
	}
	
	dr3 := newDeterministicReader("seed2")
	b3 := make([]byte, 100)
	dr3.Read(b3)
	
	if string(b1) == string(b3) {
		t.Fatalf("Deterministic reader produced same bytes for different seeds")
	}
	
	// Test zero filling requirement
	dr4 := newDeterministicReader("seed1")
	b4 := []byte{1, 2, 3, 4, 5}
	dr4.Read(b4)
	
	dr5 := newDeterministicReader("seed1")
	b5 := []byte{0, 0, 0, 0, 0}
	dr5.Read(b5)
	
	if string(b4) != string(b5) {
		t.Fatalf("Deterministic reader did not ignore underlying buffer contents")
	}
}
