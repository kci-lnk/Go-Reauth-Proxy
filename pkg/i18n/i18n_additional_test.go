package i18n

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeLocaleEmptyString(t *testing.T) {
	if got := NormalizeLocale("   "); got != "" {
		t.Fatalf("empty locale normalized to %q", got)
	}
}

func TestNormalizeLocaleEnglishPrefix(t *testing.T) {
	if got := NormalizeLocale("en-AU"); got != LocaleEn {
		t.Fatalf("en-AU normalized to %q", got)
	}
}

func TestNormalizeLocaleKoreanPrefix(t *testing.T) {
	if got := NormalizeLocale("ko-KP"); got != LocaleKoKR {
		t.Fatalf("ko-KP normalized to %q", got)
	}
}

func TestNormalizeLocaleJapanesePrefix(t *testing.T) {
	if got := NormalizeLocale("ja-Jpan"); got != LocaleJaJP {
		t.Fatalf("ja-Jpan normalized to %q", got)
	}
}

func TestNormalizeLocaleTraditionalChinesePrefix(t *testing.T) {
	if got := NormalizeLocale("zh-Hant-HK"); got != LocaleZhHant {
		t.Fatalf("zh-Hant-HK normalized to %q", got)
	}
}

func TestNormalizeLocaleSimplifiedChinesePrefix(t *testing.T) {
	if got := NormalizeLocale("zh-Hans-SG"); got != LocaleZhCN {
		t.Fatalf("zh-Hans-SG normalized to %q", got)
	}
}

func TestNormalizeLocaleUnderscoreEnglish(t *testing.T) {
	if got := NormalizeLocale("en_US"); got != LocaleEn {
		t.Fatalf("en_US normalized to %q", got)
	}
}

func TestNormalizeLocaleUnknownReturnsEmpty(t *testing.T) {
	if got := NormalizeLocale("fr-CA"); got != "" {
		t.Fatalf("fr-CA normalized to %q", got)
	}
}

func TestNormalizeConfigEmptyDefaultsToChinese(t *testing.T) {
	got := NormalizeConfig(LocaleConfig{})

	if got.DefaultLocale != DefaultLocale {
		t.Fatalf("default locale = %q", got.DefaultLocale)
	}
}

func TestNormalizeConfigAlias(t *testing.T) {
	got := NormalizeConfig(LocaleConfig{DefaultLocale: "en-US"})

	if got.DefaultLocale != LocaleEn {
		t.Fatalf("default locale = %q", got.DefaultLocale)
	}
}

func TestNormalizeConfigInvalidDefaultsToChinese(t *testing.T) {
	got := NormalizeConfig(LocaleConfig{DefaultLocale: "fr-FR"})

	if got.DefaultLocale != DefaultLocale {
		t.Fatalf("default locale = %q", got.DefaultLocale)
	}
}

func TestSetDefaultLocaleNormalizesAlias(t *testing.T) {
	SetDefaultLocale("en-GB")
	t.Cleanup(func() {
		SetDefaultLocale(DefaultLocale)
	})

	if got := DefaultLocaleValue(); got != LocaleEn {
		t.Fatalf("default locale = %q", got)
	}
}

func TestSetDefaultLocaleInvalidFallsBackToDefault(t *testing.T) {
	SetDefaultLocale("fr-FR")
	t.Cleanup(func() {
		SetDefaultLocale(DefaultLocale)
	})

	if got := DefaultLocaleValue(); got != DefaultLocale {
		t.Fatalf("default locale = %q", got)
	}
}

func TestDefaultLocaleValueFallsBackWhenStoreEmpty(t *testing.T) {
	defaultLocale.Store("")
	t.Cleanup(func() {
		SetDefaultLocale(DefaultLocale)
	})

	if got := DefaultLocaleValue(); got != DefaultLocale {
		t.Fatalf("default locale = %q", got)
	}
}

func TestResolveAcceptLanguageEmptyHeader(t *testing.T) {
	if got := ResolveAcceptLanguage(""); got != "" {
		t.Fatalf("empty accept-language resolved to %q", got)
	}
}

func TestResolveAcceptLanguageMalformedHeader(t *testing.T) {
	if got := ResolveAcceptLanguage("not a valid language header"); got != "" {
		t.Fatalf("malformed accept-language resolved to %q", got)
	}
}

func TestResolveAcceptLanguageHonorsQuality(t *testing.T) {
	got := ResolveAcceptLanguage("en;q=0.2, ja-JP;q=0.9")

	if got != LocaleJaJP {
		t.Fatalf("accept-language resolved to %q", got)
	}
}

func TestResolveAcceptLanguageNormalizesMatchedAlias(t *testing.T) {
	got := ResolveAcceptLanguage("en-GB,en;q=0.8")

	if got != LocaleEn {
		t.Fatalf("accept-language resolved to %q", got)
	}
}

func TestResolveRequestLocaleIgnoresNilRequestAndUsesDefault(t *testing.T) {
	SetDefaultLocale(LocaleJaJP)
	t.Cleanup(func() {
		SetDefaultLocale(DefaultLocale)
	})

	if got := ResolveRequestLocale(nil); got != LocaleJaJP {
		t.Fatalf("request locale = %q", got)
	}
}

func TestResolveRequestLocaleIgnoresRequestHeaders(t *testing.T) {
	SetDefaultLocale(LocaleEn)
	t.Cleanup(func() {
		SetDefaultLocale(DefaultLocale)
	})
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set(LocaleHeaderName, LocaleZhCN)

	if got := ResolveRequestLocale(req); got != LocaleEn {
		t.Fatalf("request locale = %q", got)
	}
}

func TestTEnglishGatewaySuccess(t *testing.T) {
	if got := T(LocaleEn, "gateway.success"); got != "Success" {
		t.Fatalf("English success = %q", got)
	}
}

func TestTChineseGatewaySuccess(t *testing.T) {
	if got := T(LocaleZhCN, "gateway.success"); got != "成功" {
		t.Fatalf("Chinese success = %q", got)
	}
}

func TestTTraditionalChineseInvalidJSON(t *testing.T) {
	if got := T(LocaleZhHant, "api.invalidJson"); got != "JSON 格式無效" {
		t.Fatalf("Traditional Chinese invalid JSON = %q", got)
	}
}

func TestTKoreanSuccess(t *testing.T) {
	if got := T(LocaleKoKR, "api.success"); got != "성공" {
		t.Fatalf("Korean success = %q", got)
	}
}

func TestTJapaneseSuccess(t *testing.T) {
	if got := T(LocaleJaJP, "api.success"); got != "成功" {
		t.Fatalf("Japanese success = %q", got)
	}
}

func TestTUnknownLocaleFallsBackToDefault(t *testing.T) {
	if got := T("fr-FR", "gateway.success"); got != "成功" {
		t.Fatalf("unknown locale success = %q", got)
	}
}

func TestTUnknownKeyReturnsKey(t *testing.T) {
	if got := T(LocaleEn, "missing.key"); got != "missing.key" {
		t.Fatalf("unknown key = %q", got)
	}
}

func TestTFallsBackToDefaultLocaleWhenKeyMissingInLocale(t *testing.T) {
	old := messages[LocaleEn]["gateway.success"]
	delete(messages[LocaleEn], "gateway.success")
	t.Cleanup(func() {
		messages[LocaleEn]["gateway.success"] = old
	})

	if got := T(LocaleEn, "gateway.success"); got != "成功" {
		t.Fatalf("fallback message = %q", got)
	}
}

func TestRequestTUsesResolvedDefaultLocale(t *testing.T) {
	SetDefaultLocale(LocaleEn)
	t.Cleanup(func() {
		SetDefaultLocale(DefaultLocale)
	})
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)

	if got := RequestT(req, "gateway.success"); got != "Success" {
		t.Fatalf("request translation = %q", got)
	}
}

func TestLoadMessagesIncludesAllSupportedLocales(t *testing.T) {
	loaded := loadMessages()

	for _, locale := range []string{LocaleZhCN, LocaleZhHant, LocaleEn, LocaleKoKR, LocaleJaJP} {
		if len(loaded[locale]) == 0 {
			t.Fatalf("locale %s did not load messages", locale)
		}
	}
}

func TestLocaleConstantsRemainStable(t *testing.T) {
	if LocaleCookieName != "fn_knock_locale" || LocaleHeaderName != "X-Fn-Knock-Locale" {
		t.Fatalf("unexpected locale transport constants: cookie=%q header=%q", LocaleCookieName, LocaleHeaderName)
	}
}

func TestDefaultLocaleConstantIsChineseSimplified(t *testing.T) {
	if DefaultLocale != LocaleZhCN {
		t.Fatalf("default locale constant = %q", DefaultLocale)
	}
}
