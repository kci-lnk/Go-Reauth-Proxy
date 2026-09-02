package proxy

import (
	"net/http"
	"strings"
)

func toolbarResponseStatusAllowsInjection(status int) bool {
	if status == 0 {
		return true
	}
	if status == http.StatusNoContent || status == http.StatusResetContent || status == http.StatusPartialContent {
		return false
	}
	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		return true
	}
	return status >= http.StatusBadRequest && status <= 599
}

func htmlProxyResponseMustNotHaveBody(resp *http.Response) bool {
	if resp == nil {
		return true
	}
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		return true
	}
	if resp.Body == http.NoBody || (resp.ContentLength == 0 && strings.TrimSpace(resp.Header.Get("Content-Length")) == "0") {
		return true
	}
	return resp.StatusCode >= 100 && resp.StatusCode <= 199 ||
		resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusResetContent ||
		resp.StatusCode == http.StatusNotModified
}
