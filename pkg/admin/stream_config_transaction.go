package admin

import "go-reauth-proxy/pkg/models"

func (s *Server) applyStreamConfig(
	rules []models.StreamRule,
	availability *models.StreamAvailability,
	policies map[string]models.CompiledIPSet,
	persist func() error,
) (err error, persistFailed bool) {
	if s.StreamManager == nil {
		err = persist()
		return err, err != nil
	}
	err = s.StreamManager.ReconcileConfigBundleWithCommit(rules, availability, policies, func() error {
		err := persist()
		persistFailed = err != nil
		return err
	})
	return err, persistFailed
}
