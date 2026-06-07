package config

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// AppConfig maps the JSON config structure
type AppConfig struct {
	Title         string   `toml:"title"`
	BaseURL       string   `toml:"baseURL"`
	AllowedSuffix string   `toml:"allowedSuffix"`
	Options       []string `toml:"options"`
	AdminEmails   []string `toml:"adminEmails"`
	AdminPassword string   `toml:"adminPassword"`
	SkipEmail     bool     `toml:"skipEmail"`
	SMTP          struct {
		Host string `toml:"host"`
		Port int    `toml:"port"`
		User string `toml:"user"`
		Pass string `toml:"pass"`
	} `toml:"smtp"`
}

var Current *AppConfig

// Load reads and parses config.toml
func Load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read config file: %w", err)
	}

	var c AppConfig
	if err := toml.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("could not parse config file: %w", err)
	}

	Current = &c
	return nil
}
