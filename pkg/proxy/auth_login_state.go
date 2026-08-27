package proxy

import "go-reauth-proxy/pkg/grpc/pb"

// verifyResponseHasSystemLogin keeps route authorization separate from login
// state. Public routes can return Success for anonymous requests, including
// requests carrying an expired or forged credential. Only the authentication
// bridge's explicit login signal is authoritative for portal data.
func verifyResponseHasSystemLogin(resp *pb.VerifyAuthResponse) bool {
	return resp != nil && resp.GetLoginAuthenticated()
}
