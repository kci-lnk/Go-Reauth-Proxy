package config

import (
	"encoding/json"
	"go-reauth-proxy/pkg/models"
	"os"
	"path/filepath"
	"sync"
)

type AppConfig struct {
	Rules             []models.Rule     `json:"rules"`
	DefaultRoute      string            `json:"default_route"`
	AuthConfig        models.AuthConfig `json:"auth_config"`
	IptablesChainName string            `json:"iptables_chain_name,omitempty"`
	SSLCert           string            `json:"ssl_cert,omitempty"`
	SSLKey            string            `json:"ssl_key,omitempty"`
}

type Manager struct {
	filePath string
	mu       sync.RWMutex
}

func NewManager(filePath string) *Manager {
	return &Manager{
		filePath: filePath,
	}
}

func defaultConfig() *AppConfig {
	return &AppConfig{
		Rules:        []models.Rule{},
		DefaultRoute: "/__select__",
		AuthConfig: models.AuthConfig{
			AuthPort:  7997,
			AuthURL:   "/api/auth/verify",
			LoginURL:  "/login",
			LogoutURL: "/api/auth/logout",
		},
	}
}

func applyDefaults(cfg *AppConfig) {
	if cfg.Rules == nil {
		cfg.Rules = []models.Rule{}
	}

	if cfg.DefaultRoute == "" {
		cfg.DefaultRoute = "/__select__"
	}
	if cfg.AuthConfig.AuthPort <= 0 {
		cfg.AuthConfig.AuthPort = 7997
	}
	if cfg.AuthConfig.AuthURL == "" {
		cfg.AuthConfig.AuthURL = "/api/auth/verify"
	}
	if cfg.AuthConfig.LoginURL == "" {
		cfg.AuthConfig.LoginURL = "/login"
	}
	if cfg.AuthConfig.LogoutURL == "" {
		cfg.AuthConfig.LogoutURL = "/api/auth/logout"
	}
}

func (m *Manager) loadUnlocked() (*AppConfig, error) {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultConfig(), nil
		}
		return nil, err
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	applyDefaults(&cfg)
	return &cfg, nil
}

func (m *Manager) saveUnlocked(cfg *AppConfig) error {
	dir := filepath.Dir(m.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.filePath, data, 0644)
}

func (m *Manager) Load() (*AppConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loadUnlocked()
}

func (m *Manager) Save(config *AppConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	applyDefaults(config)
	return m.saveUnlocked(config)
}

func (m *Manager) Update(updateFn func(*AppConfig) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg, err := m.loadUnlocked()
	if err != nil {
		return err
	}

	if err := updateFn(cfg); err != nil {
		return err
	}

	applyDefaults(cfg)
	return m.saveUnlocked(cfg)
}
