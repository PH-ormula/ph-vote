package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// AppConfig maps the JSON config structure
type AppConfig struct {
	Title         string   `json:"title"`
	AllowedSuffix string   `json:"allowedSuffix"`
	Options       []string `json:"options"`
	AdminPassword string   `json:"adminPassword"`
	SMTP          struct {
		Host string `json:"host"`
		Port int    `json:"port"`
		User string `json:"user"`
		Pass string `json:"pass"`
	} `json:"smtp"`
}

var Current *AppConfig

// Load reads and parses config.json
func Load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read config file: %w", err)
	}

	var c AppConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("could not parse config file: %w", err)
	}

	Current = &c
	return nil
}
