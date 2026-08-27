package proxy

import (
	"testing"

	"go-reauth-proxy/pkg/grpc/pb"
)

func TestVerifyResponseHasSystemLogin(t *testing.T) {
	tests := []struct {
		name     string
		response *pb.VerifyAuthResponse
		want     bool
	}{
		{name: "missing response"},
		{name: "route access without login", response: &pb.VerifyAuthResponse{Success: true}},
		{name: "explicit login", response: &pb.VerifyAuthResponse{Success: true, LoginAuthenticated: true}, want: true},
		{
			name:     "credential metadata without explicit login",
			response: &pb.VerifyAuthResponse{Success: true},
		},
		{
			name: "temporary grant credential metadata is not login",
			response: &pb.VerifyAuthResponse{
				Success:   true,
				GrantKind: pb.AuthGrantKind_AUTH_GRANT_KIND_SUBDOMAIN_RULE,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := verifyResponseHasSystemLogin(test.response); got != test.want {
				t.Fatalf("verifyResponseHasSystemLogin() = %v, want %v", got, test.want)
			}
		})
	}
}
