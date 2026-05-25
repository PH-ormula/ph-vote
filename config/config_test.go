package config

import (
	"os"
	"testing"
)

func TestLoadTOML(t *testing.T) {
	tomlContent := `
title = "Test Voting"
allowedSuffix = "@test.com"
options = ["A", "B"]
adminPassword = "pass"

[smtp]
host = "smtp.test.com"
port = 123
user = "testuser"
pass = "testpass"
`
	tmpfile, err := os.CreateTemp("", "config-*.toml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(tomlContent)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	if err := Load(tmpfile.Name()); err != nil {
		t.Fatalf("Failed to load TOML: %v", err)
	}

	if Current == nil {
		t.Fatal("Current config is nil")
	}
	if Current.Title != "Test Voting" {
		t.Errorf("Expected title 'Test Voting', got '%s'", Current.Title)
	}
	if Current.SMTP.Host != "smtp.test.com" {
		t.Errorf("Expected SMTP host 'smtp.test.com', got '%s'", Current.SMTP.Host)
	}
	if len(Current.Options) != 2 || Current.Options[0] != "A" {
		t.Errorf("Expected options [A, B], got %v", Current.Options)
	}
}
