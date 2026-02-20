package errors

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

var ErrorMap = map[int]string{
	CodeSuccess:              "Success",
	CodeBadRequest:           "Bad Request",
	CodeUnauthorized:         "Unauthorized",
	CodeForbidden:            "Forbidden",
	CodeNotFound:             "Not Found",
	CodeInternal:             "Internal Server Error",
	CodeInvalidRule:          "Invalid Rule Configuration",
	CodeRuleNotFound:         "Rule Not Found",
	CodeInvalidJSON:          "Invalid JSON Format",
	CodeReadBodyFailed:       "Failed to Read Request Body",
	CodeProxyTargetInvalid:   "Invalid Proxy Target",
	CodeProxyAuthFailed:      "Authentication Failed",
	CodeProxyTimeout:         "Upstream Timeout",
	CodeIptablesInitError:    "Iptables Initialization Failed",
	CodeIptablesCommandError: "Iptables Command Failed",
	CodeIptablesParseError:   "Iptables Parse Failed",
}

func GetMessage(code int) string {
	if msg, ok := ErrorMap[code]; ok {
		return msg
	}
	return "Unknown Error"
}
