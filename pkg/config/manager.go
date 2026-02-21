package config

import (
	"encoding/json"
	"go-reauth-proxy/pkg/models"
	"os"
	"path/filepath"
	"sync"
)

type AppConfig struct {
	Rules        []models.Rule     `json:"rules"`
	DefaultRoute string            `json:"default_route"`
	AuthConfig   models.AuthConfig `json:"auth_config"`
	SSLCert      string            `json:"ssl_cert,omitempty"`
	SSLKey       string            `json:"ssl_key,omitempty"`
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

func (m *Manager) Load() (*AppConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := os.ReadFile(m.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &AppConfig{
				Rules:        []models.Rule{},
				DefaultRoute: "/__select__",
				AuthConfig: models.AuthConfig{
					AuthPort:        7997,
					AuthURL:         "/auth",
					LoginURL:        "/login",
					LogoutURL:       "/logout",
					AuthCacheExpire: 60,
				},
			}, nil
		}
		return nil, err
	}

	var config AppConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	if config.Rules == nil {
		config.Rules = []models.Rule{}
	}

	if config.DefaultRoute == "" {
		config.DefaultRoute = "/__select__"
	}
	if config.AuthConfig.AuthPort <= 0 {
		config.AuthConfig.AuthPort = 7997
	}
	if config.AuthConfig.AuthURL == "" {
		config.AuthConfig.AuthURL = "/auth"
	}
	if config.AuthConfig.LoginURL == "" {
		config.AuthConfig.LoginURL = "/login"
	}
	if config.AuthConfig.LogoutURL == "" {
		config.AuthConfig.LogoutURL = "/logout"
	}
	if config.AuthConfig.AuthCacheExpire <= 0 {
		config.AuthConfig.AuthCacheExpire = 60
	}

	return &config, nil
}

func (m *Manager) Save(config *AppConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	dir := filepath.Dir(m.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.filePath, data, 0644)
}
