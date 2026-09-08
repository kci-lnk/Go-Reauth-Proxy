package admin

import (
	"context"
	"go-reauth-proxy/pkg/grpc/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"testing"
)

func TestGatewayHTTP3ConfigAuthenticationAndRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	if _, err := server.GetGatewayHttp3Status(context.Background(), &emptypb.Empty{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
	if _, err := server.SetGatewayHttp3Config(context.Background(), &pb.GatewayHttp3Config{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
	ctx := authTestContext()
	for _, port := range []uint32{443, 0, 65535} {
		got, err := server.SetGatewayHttp3Config(ctx, &pb.GatewayHttp3Config{AdvertisedPort: port})
		if err != nil {
			t.Fatal(err)
		}
		if got.GetConfig().GetEnabled() || got.GetConfig().GetAdvertisedPort() != port {
			t.Fatal(got)
		}
		read, err := server.GetGatewayHttp3Status(ctx, &emptypb.Empty{})
		if err != nil || read.GetConfig().GetAdvertisedPort() != port {
			t.Fatalf("%v %v", read, err)
		}
	}
	if _, err := server.SetGatewayHttp3Config(ctx, &pb.GatewayHttp3Config{AdvertisedPort: 65536}); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
	if _, err := server.SetGatewayHttp3Config(ctx, &pb.GatewayHttp3Config{Enabled: true}); status.Code(err) != codes.FailedPrecondition {
		t.Fatal(err)
	}
}
