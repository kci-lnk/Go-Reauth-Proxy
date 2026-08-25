package errors

import (
	stderrors "errors"
	"testing"

	"go-reauth-proxy/pkg/i18n"
)

func TestNewReturnsCustomError(t *testing.T) {
	err := New(CodeInvalidRule, "invalid rule")

	var custom *CustomError
	if !stderrors.As(err, &custom) {
		t.Fatalf("New returned %T, want *CustomError", err)
	}
	if custom.Code != CodeInvalidRule || custom.Message != "invalid rule" {
		t.Fatalf("unexpected custom error: %#v", custom)
	}
}

func TestCustomErrorErrorReturnsMessage(t *testing.T) {
	err := &CustomError{Code: CodeInternal, Message: "boom"}

	if err.Error() != "boom" {
		t.Fatalf("Error() = %q", err.Error())
	}
}

func TestGetMessageForLocaleFallsBackForUnknownLocale(t *testing.T) {
	if got := GetMessageForLocale("missing-locale", CodeSuccess); got != "成功" {
		t.Fatalf("fallback success message = %q", got)
	}
}

func TestGetMessageForLocaleUnknownCodeUsesUnknownErrorKey(t *testing.T) {
	if got := GetMessageForLocale(i18n.LocaleZhCN, -1); got != "未知错误" {
		t.Fatalf("unknown code message = %q", got)
	}
}

func TestGetMessageForLocaleProxyTargetInvalidEnglish(t *testing.T) {
	if got := GetMessageForLocale(i18n.LocaleEn, CodeProxyTargetInvalid); got != "Invalid Proxy Target" {
		t.Fatalf("proxy target invalid message = %q", got)
	}
}

func TestGetMessageForLocaleProxyAuthFailedEnglish(t *testing.T) {
	if got := GetMessageForLocale(i18n.LocaleEn, CodeProxyAuthFailed); got != "Authentication Failed" {
		t.Fatalf("proxy auth failed message = %q", got)
	}
}

func TestGetMessageForLocaleProxyTimeoutEnglish(t *testing.T) {
	if got := GetMessageForLocale(i18n.LocaleEn, CodeProxyTimeout); got != "Upstream Timeout" {
		t.Fatalf("proxy timeout message = %q", got)
	}
}

func TestGetMessageForLocaleProxyAvailabilityEnglish(t *testing.T) {
	if got := GetMessageForLocale(i18n.LocaleEn, CodeProxyBadGateway); got != "Bad Gateway" {
		t.Fatalf("proxy bad gateway message = %q", got)
	}
	if got := GetMessageForLocale(i18n.LocaleEn, CodeProxyUnavailable); got != "Upstream Temporarily Unavailable" {
		t.Fatalf("proxy unavailable message = %q", got)
	}
}

func TestGetMessageForLocaleIptablesInitEnglish(t *testing.T) {
	if got := GetMessageForLocale(i18n.LocaleEn, CodeIptablesInitError); got != "Iptables Initialization Failed" {
		t.Fatalf("iptables init message = %q", got)
	}
}

func TestGetMessageForLocaleIptablesCommandEnglish(t *testing.T) {
	if got := GetMessageForLocale(i18n.LocaleEn, CodeIptablesCommandError); got != "Iptables Command Failed" {
		t.Fatalf("iptables command message = %q", got)
	}
}

func TestGetMessageForLocaleIptablesParseEnglish(t *testing.T) {
	if got := GetMessageForLocale(i18n.LocaleEn, CodeIptablesParseError); got != "Iptables Parse Failed" {
		t.Fatalf("iptables parse message = %q", got)
	}
}

func TestGetMessageWithInvalidDefaultLocaleFallsBack(t *testing.T) {
	i18n.SetDefaultLocale("not-real")
	t.Cleanup(func() {
		i18n.SetDefaultLocale(i18n.DefaultLocale)
	})

	if got := GetMessage(CodeSuccess); got != "成功" {
		t.Fatalf("message with invalid default locale = %q", got)
	}
}

func TestErrorKeyMapContainsHTTPErrorCodes(t *testing.T) {
	for _, code := range []int{CodeBadRequest, CodeUnauthorized, CodeForbidden, CodeNotFound, CodeInternal} {
		if ErrorKeyMap[code] == "" {
			t.Fatalf("missing error key for code %d", code)
		}
	}
}

func TestErrorKeyMapContainsAdminErrorCodes(t *testing.T) {
	for _, code := range []int{CodeInvalidRule, CodeRuleNotFound, CodeInvalidJSON, CodeReadBodyFailed} {
		if ErrorKeyMap[code] == "" {
			t.Fatalf("missing error key for code %d", code)
		}
	}
}

func TestErrorMapContainsLocalizedDefaultMessages(t *testing.T) {
	for _, code := range []int{CodeSuccess, CodeInvalidJSON, CodeProxyTimeout, CodeProxyBadGateway, CodeProxyUnavailable, CodeIptablesParseError} {
		if ErrorMap[code] == "" {
			t.Fatalf("missing localized message for code %d", code)
		}
	}
}

func TestErrorMapUsesDefaultChineseSuccess(t *testing.T) {
	if got := ErrorMap[CodeSuccess]; got != "成功" {
		t.Fatalf("default success error map = %q", got)
	}
}

func TestErrorCodesDoNotOverlapDomainRanges(t *testing.T) {
	if !(CodeInvalidRule/10000 == 1 && CodeProxyTargetInvalid/10000 == 2 && CodeIptablesInitError/10000 == 3) {
		t.Fatalf("unexpected domain ranges: admin=%d proxy=%d iptables=%d", CodeInvalidRule, CodeProxyTargetInvalid, CodeIptablesInitError)
	}
}
