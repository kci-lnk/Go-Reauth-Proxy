package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"go-reauth-proxy/pkg/models"
	"log"
	"net/netip"
	"sort"
	"strings"
)

type sslRuntimeBundle struct {
	mode         models.SSLDeploymentMode
	defaultCert  *tls.Certificate
	exact        map[string]*tls.Certificate
	wildcards    []sslRuntimeWildcard
	certificates []models.SSLDeployedCertificateInfo
	lanAddresses map[string]struct{}
}

type sslRuntimeWildcard struct {
	pattern string
	cert    *tls.Certificate
}

func newEmptySSLRuntimeBundle(mode models.SSLDeploymentMode) *sslRuntimeBundle {
	if mode != models.SSLDeploymentModeMultiSNI {
		mode = models.SSLDeploymentModeSingleActive
	}
	return &sslRuntimeBundle{
		mode:         mode,
		exact:        make(map[string]*tls.Certificate),
		wildcards:    []sslRuntimeWildcard{},
		certificates: []models.SSLDeployedCertificateInfo{},
		lanAddresses: make(map[string]struct{}),
	}
}

func normalizeLANDeployment(input models.SSLLANDeployment) (models.SSLLANDeployment, error) {
	result := models.SSLLANDeployment{Enabled: input.Enabled}
	seen := make(map[string]struct{})
	for _, raw := range input.Addresses {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !address.Is4() || !isRFC1918IPv4(address) {
			return models.SSLLANDeployment{}, fmt.Errorf("LAN deployment address %q must be an RFC1918 IPv4 address", raw)
		}
		canonical := address.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		result.Addresses = append(result.Addresses, canonical)
	}
	sort.Strings(result.Addresses)
	if len(result.Addresses) > 16 {
		return models.SSLLANDeployment{}, fmt.Errorf("LAN deployment supports at most 16 addresses")
	}
	if !result.Enabled {
		return result, nil
	}
	if len(result.Addresses) == 0 {
		return models.SSLLANDeployment{}, fmt.Errorf("LAN deployment requires at least one address")
	}
	return result, nil
}

func isRFC1918IPv4(address netip.Addr) bool {
	if !address.Is4() {
		return false
	}
	return netip.MustParsePrefix("10.0.0.0/8").Contains(address) ||
		netip.MustParsePrefix("172.16.0.0/12").Contains(address) ||
		netip.MustParsePrefix("192.168.0.0/16").Contains(address)
}

func normalizeSSLConfig(input models.SSLConfig) (models.SSLConfig, error) {
	mode := input.DeploymentMode
	if mode != models.SSLDeploymentModeMultiSNI {
		mode = models.SSLDeploymentModeSingleActive
	}

	certificates := make([]models.SSLDeployedCertificate, 0, len(input.Certificates))
	defaultIndex := -1
	for index, certificate := range input.Certificates {
		next := models.SSLDeployedCertificate{
			ID:        strings.TrimSpace(certificate.ID),
			Label:     strings.TrimSpace(certificate.Label),
			Cert:      strings.TrimSpace(certificate.Cert),
			Key:       strings.TrimSpace(certificate.Key),
			IsDefault: certificate.IsDefault,
		}
		if next.Cert == "" && next.Key == "" {
			continue
		}
		if next.Cert == "" || next.Key == "" {
			return models.SSLConfig{}, fmt.Errorf("certificate #%d must include both cert and key", index+1)
		}
		if next.IsDefault {
			if defaultIndex != -1 {
				return models.SSLConfig{}, fmt.Errorf("only one deployed certificate can be marked as default")
			}
			defaultIndex = len(certificates)
		}
		certificates = append(certificates, next)
	}

	if mode == models.SSLDeploymentModeSingleActive && len(certificates) > 1 {
		return models.SSLConfig{}, fmt.Errorf("single_active mode only supports one deployed certificate")
	}
	if len(certificates) > 0 && defaultIndex == -1 {
		certificates[0].IsDefault = true
	} else if defaultIndex >= 0 {
		for index := range certificates {
			certificates[index].IsDefault = index == defaultIndex
		}
	}

	lanDeployment, err := normalizeLANDeployment(input.LANDeployment)
	if err != nil {
		return models.SSLConfig{}, err
	}

	return models.SSLConfig{
		DeploymentMode: mode,
		Certificates:   certificates,
		LANDeployment:  lanDeployment,
	}, nil
}

func buildLegacySSLConfig(certPEM, keyPEM string) models.SSLConfig {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	if certPEM == "" || keyPEM == "" {
		return models.SSLConfig{
			DeploymentMode: models.SSLDeploymentModeSingleActive,
			Certificates:   []models.SSLDeployedCertificate{},
		}
	}

	return models.SSLConfig{
		DeploymentMode: models.SSLDeploymentModeSingleActive,
		Certificates: []models.SSLDeployedCertificate{
			{
				ID:        "legacy-default",
				Label:     "Legacy SSL",
				Cert:      certPEM,
				Key:       keyPEM,
				IsDefault: true,
			},
		},
	}
}

func validateLegacySSLPair(certPEM, keyPEM string) (string, string, error) {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)

	switch {
	case certPEM == "" && keyPEM == "":
		return "", "", nil
	case certPEM == "":
		return "", "", fmt.Errorf("certificate PEM is required when key is provided")
	case keyPEM == "":
		return "", "", fmt.Errorf("private key PEM is required when certificate is provided")
	default:
		return certPEM, keyPEM, nil
	}
}

func copySSLConfig(input models.SSLConfig) models.SSLConfig {
	certificates := make([]models.SSLDeployedCertificate, len(input.Certificates))
	copy(certificates, input.Certificates)
	return models.SSLConfig{
		DeploymentMode: input.DeploymentMode,
		Certificates:   certificates,
		LANDeployment: models.SSLLANDeployment{
			Enabled:   input.LANDeployment.Enabled,
			Addresses: append([]string(nil), input.LANDeployment.Addresses...),
		},
	}
}

func copySSLInfo(input models.SSLInfo) models.SSLInfo {
	certificates := make([]models.SSLDeployedCertificateInfo, len(input.Certificates))
	for index, certificate := range input.Certificates {
		certificates[index] = models.SSLDeployedCertificateInfo{
			ID:        certificate.ID,
			Label:     certificate.Label,
			Domains:   append([]string{}, certificate.Domains...),
			IsDefault: certificate.IsDefault,
		}
	}
	return models.SSLInfo{
		Enabled:        input.Enabled,
		DeploymentMode: input.DeploymentMode,
		Certificates:   certificates,
		LANDeployment: models.SSLLANDeploymentInfo{
			Enabled:   input.LANDeployment.Enabled,
			Addresses: append([]string(nil), input.LANDeployment.Addresses...),
		},
	}
}

func legacySSLPEMFromConfig(input models.SSLConfig) (string, string) {
	if len(input.Certificates) == 0 {
		return "", ""
	}

	for _, certificate := range input.Certificates {
		if certificate.IsDefault {
			return certificate.Cert, certificate.Key
		}
	}

	return input.Certificates[0].Cert, input.Certificates[0].Key
}

func newSSLRuntimeBundle(config models.SSLConfig) (*sslRuntimeBundle, error) {
	bundle := newEmptySSLRuntimeBundle(config.DeploymentMode)
	if config.LANDeployment.Enabled {
		for _, address := range config.LANDeployment.Addresses {
			bundle.lanAddresses[address] = struct{}{}
		}
	}

	seenWildcards := make(map[string]struct{})
	for index, certificate := range config.Certificates {
		pair, err := tls.X509KeyPair([]byte(certificate.Cert), []byte(certificate.Key))
		if err != nil {
			return nil, fmt.Errorf("invalid deployed certificate #%d: %w", index+1, err)
		}

		domains, err := extractCertificateDomains(&pair)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect deployed certificate #%d: %w", index+1, err)
		}
		if len(domains) == 0 {
			return nil, fmt.Errorf("deployed certificate #%d does not contain any usable SAN/CN", index+1)
		}

		if certificate.IsDefault || bundle.defaultCert == nil {
			bundle.defaultCert = &pair
		}

		for _, domain := range domains {
			if strings.Contains(domain, "*") && !isSupportedWildcardDomain(domain) {
				return nil, fmt.Errorf("unsupported wildcard domain %q in deployed certificate #%d", domain, index+1)
			}

			if isSupportedWildcardDomain(domain) {
				if _, exists := seenWildcards[domain]; exists {
					return nil, fmt.Errorf("duplicate wildcard domain %q across deployed certificates", domain)
				}
				seenWildcards[domain] = struct{}{}
				bundle.wildcards = append(bundle.wildcards, sslRuntimeWildcard{
					pattern: domain,
					cert:    &pair,
				})
				continue
			}

			if _, exists := bundle.exact[domain]; exists {
				return nil, fmt.Errorf("duplicate exact domain %q across deployed certificates", domain)
			}
			bundle.exact[domain] = &pair
		}

		bundle.certificates = append(bundle.certificates, models.SSLDeployedCertificateInfo{
			ID:        certificate.ID,
			Label:     certificate.Label,
			Domains:   domains,
			IsDefault: certificate.IsDefault,
		})
	}

	sort.SliceStable(bundle.wildcards, func(i, j int) bool {
		return len(bundle.wildcards[i].pattern) > len(bundle.wildcards[j].pattern)
	})
	return bundle, nil
}

func extractCertificateDomains(certificate *tls.Certificate) ([]string, error) {
	if certificate == nil || len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}

	leaf := certificate.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return nil, err
		}
		leaf = parsed
		certificate.Leaf = parsed
	}

	seen := make(map[string]struct{})
	addDomain := func(domain string) {
		normalized := normalizeTLSServerName(domain)
		if normalized == "" {
			return
		}
		seen[normalized] = struct{}{}
	}

	for _, domain := range leaf.DNSNames {
		addDomain(domain)
	}
	for _, ip := range leaf.IPAddresses {
		addDomain(ip.String())
	}
	addDomain(leaf.Subject.CommonName)

	domains := make([]string, 0, len(seen))
	for domain := range seen {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains, nil
}

func normalizeTLSServerName(value string) string {
	return strings.TrimSuffix(normalizeRequestHost(value), ".")
}

func isSupportedWildcardDomain(domain string) bool {
	return strings.HasPrefix(domain, "*.") && strings.Count(domain, "*") == 1
}

func wildcardMatchesServerName(pattern, serverName string) bool {
	if !isSupportedWildcardDomain(pattern) {
		return false
	}

	host := normalizeTLSServerName(serverName)
	suffix := strings.TrimPrefix(pattern, "*")
	if host == "" || !strings.HasSuffix(host, suffix) {
		return false
	}

	prefix := strings.TrimSuffix(host, suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
}

func (bundle *sslRuntimeBundle) hasCertificates() bool {
	return bundle != nil && len(bundle.certificates) > 0
}

func (bundle *sslRuntimeBundle) certificateForServerName(serverName string) *tls.Certificate {
	if bundle == nil {
		return nil
	}

	host := normalizeTLSServerName(serverName)
	if host != "" {
		if certificate := bundle.exact[host]; certificate != nil {
			return certificate
		}
		for _, wildcard := range bundle.wildcards {
			if wildcardMatchesServerName(wildcard.pattern, host) {
				return wildcard.cert
			}
		}
	}

	return bundle.defaultCert
}

func (bundle *sslRuntimeBundle) lanAddressAllowed(host string) bool {
	if bundle == nil {
		return false
	}
	_, ok := bundle.lanAddresses[normalizeTLSServerName(host)]
	return ok
}

func (h *Handler) ClearSSLCertificate() error {
	config := h.GetSSLDeployment()
	config.DeploymentMode = models.SSLDeploymentModeSingleActive
	config.Certificates = nil
	return h.SetSSLDeployment(config)
}

func (h *Handler) SetSSLCertificate(cert *tls.Certificate, certPEM, keyPEM string) {
	if cert == nil {
		_ = h.ClearSSLCertificate()
		return
	}
	normalizedCertPEM, normalizedKeyPEM, err := validateLegacySSLPair(certPEM, keyPEM)
	if err != nil {
		log.Printf("Failed to set legacy SSL certificate: %v", err)
		return
	}
	config := buildLegacySSLConfig(normalizedCertPEM, normalizedKeyPEM)
	config.LANDeployment = h.GetSSLDeployment().LANDeployment
	if err := h.SetSSLDeployment(config); err != nil {
		log.Printf("Failed to set legacy SSL certificate: %v", err)
	}
}

func (h *Handler) SetSSLCertificatePEM(certPEM, keyPEM string) error {
	normalizedCertPEM, normalizedKeyPEM, err := validateLegacySSLPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	config := buildLegacySSLConfig(normalizedCertPEM, normalizedKeyPEM)
	config.LANDeployment = h.GetSSLDeployment().LANDeployment
	return h.SetSSLDeployment(config)
}
