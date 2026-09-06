// wafwaitfixture is a loopback-only interoperability/performance fixture. It
// exercises the production queue and generated gRPC transport with synthetic
// events; it never reads or alters a running gateway's configuration.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/rpcbridge"
	"go-reauth-proxy/pkg/waf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fixture struct {
	pb.UnimplementedWafServiceServer
	store                                                      *waf.EventStore
	waits, completed, active, drains, acks, releases, sequence atomic.Int64
	legacy                                                     bool
}

func (f *fixture) WaitWafEvents(ctx context.Context, req *pb.WafWaitRequest) (*pb.WafWaitResult, error) {
	f.waits.Add(1)
	if f.legacy {
		return nil, status.Error(codes.Unimplemented, "legacy fixture")
	}
	if req.TimeoutMs > 60000 {
		return nil, status.Error(codes.InvalidArgument, "timeout")
	}
	timeout := req.TimeoutMs
	if timeout == 0 {
		timeout = 60000
	}
	f.active.Add(1)
	defer f.active.Add(-1)
	available, err := f.store.Wait(ctx, time.Duration(timeout)*time.Millisecond)
	if err != nil {
		return nil, status.FromContextError(err).Err()
	}
	f.completed.Add(1)
	return &pb.WafWaitResult{Available: available}, nil
}

func (f *fixture) DrainWafEvents(ctx context.Context, req *pb.WafDrainRequest) (*pb.WafDrainResult, error) {
	var result waf.DrainResult
	switch req.Operation {
	case pb.WafDrainOperation_WAF_DRAIN_OPERATION_LEASE:
		f.drains.Add(1)
		result = f.store.Lease(int(req.Limit))
	case pb.WafDrainOperation_WAF_DRAIN_OPERATION_ACKNOWLEDGE:
		f.acks.Add(1)
		result = f.store.Acknowledge(req.LeaseId)
	case pb.WafDrainOperation_WAF_DRAIN_OPERATION_RELEASE:
		f.releases.Add(1)
		result = f.store.Release(req.LeaseId)
	default:
		f.drains.Add(1)
		result = f.store.Drain(int(req.Limit))
	}
	events := make([]*pb.WafEvent, 0, len(result.Events))
	for _, event := range result.Events {
		events = append(events, &pb.WafEvent{TraceId: event.TraceID, Time: event.Time, Action: event.Action, RuleIds: []int32{941100}, Host: event.Host, Path: event.Path})
	}
	return &pb.WafDrainResult{Events: events, Drained: int32(result.Drained), Remaining: int32(result.Remaining), LeaseId: result.LeaseID, Acknowledged: int32(result.Acknowledged)}, nil
}

func main() {
	legacy := flag.Bool("legacy", false, "simulate a pre-WaitWafEvents gateway")
	flag.Parse()
	f := &fixture{store: waf.NewEventStore(waf.DefaultMaxEvents, waf.DefaultEventTTL), legacy: *legacy}
	rpc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	control, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	server := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		// Use the same token value as the Rust isolated test state. Loopback fixture only.
		valid := false
		for _, value := range md.Get(rpcbridge.InternalTokenMetadataKey) {
			if value == "test-internal-rpc-token" {
				valid = true
			}
		}
		if !valid {
			return nil, status.Error(codes.Unauthenticated, "missing test token")
		}
		return handler(ctx, req)
	}))
	pb.RegisterWafServiceServer(server, f)
	mux := http.NewServeMux()
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		n, _ := strconv.Atoi(r.URL.Query().Get("count"))
		if n < 1 || n > 1000 {
			w.WriteHeader(400)
			return
		}
		for i := 0; i < n; i++ {
			f.store.Add(waf.Event{TraceID: fmt.Sprintf("fixture-%d", f.sequence.Add(1)), Time: time.Now().UTC().Format(time.RFC3339Nano), Action: "log", Host: "fixture.invalid", Path: "/synthetic"})
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		json.NewEncoder(w).Encode(map[string]any{"waits": f.waits.Load(), "completed_waits": f.completed.Load(), "active_waits": f.active.Load(), "drains": f.drains.Load(), "acks": f.acks.Load(), "releases": f.releases.Load(), "pending": f.store.Pending(), "goroutines": runtime.NumGoroutine(), "heap_alloc": mem.HeapAlloc})
	})
	fmt.Printf("{\"rpc\":%q,\"control\":%q}\n", rpc.Addr().String(), "http://"+control.Addr().String())
	go func() {
		if err := server.Serve(rpc); err != nil {
			panic(err)
		}
	}()
	if err := http.Serve(control, mux); err != nil {
		panic(err)
	}
}
