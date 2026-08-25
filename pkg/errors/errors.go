package errors

import "go-reauth-proxy/pkg/i18n"

const (
	CodeSuccess      = 200
	CodeBadRequest   = 400
	CodeUnauthorized = 401
	CodeForbidden    = 403
	CodeNotFound     = 404
	CodeInternal     = 500
)

const (
	// Admin API Errors
	CodeInvalidRule    = 10001
	CodeRuleNotFound   = 10002
	CodeInvalidJSON    = 10003
	CodeReadBodyFailed = 10004

	// Proxy Errors
	CodeProxyTargetInvalid = 20001
	CodeProxyAuthFailed    = 20002
	CodeProxyTimeout       = 20003
	CodeProxyBadGateway    = 20004
	CodeProxyUnavailable   = 20005

	// Iptables Errors
	CodeIptablesInitError    = 30001
	CodeIptablesCommandError = 30002
	CodeIptablesParseError   = 30003
)

type CustomError struct {
	Code    int
	Message string
}

func (e *CustomError) Error() string {
	return e.Message
}

func New(code int, message string) error {
	return &CustomError{
		Code:    code,
		Message: message,
	}
}

var ErrorKeyMap = map[int]string{
	CodeSuccess:              "api.success",
	CodeBadRequest:           "api.badRequest",
	CodeUnauthorized:         "api.unauthorized",
	CodeForbidden:            "api.forbidden",
	CodeNotFound:             "api.notFound",
	CodeInternal:             "api.internalServerError",
	CodeInvalidRule:          "api.invalidRule",
	CodeRuleNotFound:         "api.ruleNotFound",
	CodeInvalidJSON:          "api.invalidJson",
	CodeReadBodyFailed:       "api.readBodyFailed",
	CodeProxyTargetInvalid:   "api.proxyTargetInvalid",
	CodeProxyAuthFailed:      "api.proxyAuthFailed",
	CodeProxyTimeout:         "api.proxyTimeout",
	CodeProxyBadGateway:      "api.proxyBadGateway",
	CodeProxyUnavailable:     "api.proxyUnavailable",
	CodeIptablesInitError:    "api.iptablesInitError",
	CodeIptablesCommandError: "api.iptablesCommandError",
	CodeIptablesParseError:   "api.iptablesParseError",
}

var ErrorMap = map[int]string{
	CodeSuccess:              i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeSuccess]),
	CodeBadRequest:           i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeBadRequest]),
	CodeUnauthorized:         i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeUnauthorized]),
	CodeForbidden:            i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeForbidden]),
	CodeNotFound:             i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeNotFound]),
	CodeInternal:             i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeInternal]),
	CodeInvalidRule:          i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeInvalidRule]),
	CodeRuleNotFound:         i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeRuleNotFound]),
	CodeInvalidJSON:          i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeInvalidJSON]),
	CodeReadBodyFailed:       i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeReadBodyFailed]),
	CodeProxyTargetInvalid:   i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeProxyTargetInvalid]),
	CodeProxyAuthFailed:      i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeProxyAuthFailed]),
	CodeProxyTimeout:         i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeProxyTimeout]),
	CodeProxyBadGateway:      i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeProxyBadGateway]),
	CodeProxyUnavailable:     i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeProxyUnavailable]),
	CodeIptablesInitError:    i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeIptablesInitError]),
	CodeIptablesCommandError: i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeIptablesCommandError]),
	CodeIptablesParseError:   i18n.T(i18n.DefaultLocale, ErrorKeyMap[CodeIptablesParseError]),
}

func GetMessageForLocale(locale string, code int) string {
	if key, ok := ErrorKeyMap[code]; ok {
		return i18n.T(locale, key)
	}
	return i18n.T(locale, "api.unknownError")
}

func GetMessage(code int) string {
	return GetMessageForLocale(i18n.DefaultLocaleValue(), code)
}
