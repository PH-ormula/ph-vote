package config

import (
	"os"
	"testing"
)

func TestLoadTOML(t *testing.T) {
	tomlContent := `
title = "Test Voting"
baseURL = "http://test.com"
allowedSuffix = "@test.com"
options = ["A", "B"]
adminEmails = ["admin1@test.com", "admin2@test.com"]
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
	if Current.BaseURL != "http://test.com" {
		t.Errorf("Expected BaseURL 'http://test.com', got '%s'", Current.BaseURL)
	}
	if Current.SMTP.Host != "smtp.test.com" {
		t.Errorf("Expected SMTP host 'smtp.test.com', got '%s'", Current.SMTP.Host)
	}
	if len(Current.Options) != 2 || Current.Options[0] != "A" {
		t.Errorf("Expected options [A, B], got %v", Current.Options)
	}
	if len(Current.AdminEmails) != 2 || Current.AdminEmails[1] != "admin2@test.com" {
		t.Errorf("Expected adminEmails [admin1@test.com, admin2@test.com], got %v", Current.AdminEmails)
	}
}
