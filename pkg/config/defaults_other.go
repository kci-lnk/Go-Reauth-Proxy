//go:build !windows

package config

import "go-reauth-proxy/pkg/models"

func defaultGatewayListenerScope() string {
	return models.GatewayListenerScopeAll
}
