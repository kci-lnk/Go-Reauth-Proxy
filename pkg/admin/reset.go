package admin

import (
	"fmt"
	"strings"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/i18n"
)

// ResetAllData clears gateway-owned configuration, logs, and volatile state
// without removing installed assets or changing the process control endpoint.
func (s *Server) ResetAllData() error {
	if s == nil || s.ProxyHandler == nil {
		return fmt.Errorf("proxy handler is not initialized")
	}
	s.streamConfigMu.Lock()
	defer s.streamConfigMu.Unlock()

	resetConfig := config.DefaultConfig()
	resetConfig.AdminPort = s.Port
	currentAuth := s.ProxyHandler.GetAuthConfig()
	if currentAuth.AuthPort > 0 {
		resetConfig.AuthConfig.AuthPort = currentAuth.AuthPort
	}
	currentWAF := s.ProxyHandler.GetWAFConfig()
	resetConfig.WAF.RulesDir = currentWAF.RulesDir

	if s.ConfigManager != nil {
		current, err := s.ConfigManager.Load()
		if err != nil {
			return fmt.Errorf("load current gateway config: %w", err)
		}
		resetConfig.IptablesChainName = current.IptablesChainName
	}
	if strings.TrimSpace(resetConfig.IptablesChainName) == "" && s.IptablesHandler != nil && s.IptablesHandler.Manager != nil {
		resetConfig.IptablesChainName = s.IptablesHandler.Manager.Chain
	}

	if _, err := s.ProxyHandler.SetLoggingConfig(resetConfig.Logging); err != nil {
		return fmt.Errorf("disable gateway logging: %w", err)
	}
	if err := s.ProxyHandler.ClearGatewayLogs(); err != nil {
		return fmt.Errorf("clear gateway logs: %w", err)
	}
	if s.StreamManager != nil {
		if err := s.StreamManager.ReconcileConfig(nil, nil); err != nil {
			return fmt.Errorf("stop gateway stream listeners: %w", err)
		}
	}
	if err := s.ProxyHandler.SetGatewayListenerConfig(resetConfig.GatewayListener); err != nil {
		return fmt.Errorf("reset gateway listener: %w", err)
	}
	if err := s.ProxyHandler.SetProxyProtocolForce(resetConfig.ProxyProtocolForce); err != nil {
		return fmt.Errorf("reset proxy protocol mode: %w", err)
	}
	if err := s.ProxyHandler.SetGatewayProxyProtocolConfig(resetConfig.ProxyProtocol); err != nil {
		return fmt.Errorf("reset external proxy protocol config: %w", err)
	}
	if err := s.ProxyHandler.ResetAllData(resetConfig); err != nil {
		return err
	}

	i18n.SetDefaultLocale(resetConfig.Locale.DefaultLocale)
	return nil
}
