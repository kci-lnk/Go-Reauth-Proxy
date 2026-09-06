package proxy

// This opt-in worker is compiled into BOTH revisions by tools/memorycheck.py's
// documented build procedure. Each role is a separate process. It exercises
// the production transport/coalescer, without production config or listeners.
import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/diagnostics"
)

func memoryWorkerSnapshot() map[string]any {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return map[string]any{"pid": os.Getpid(), "go_version": runtime.Version(), "heap_alloc": m.HeapAlloc, "heap_inuse": m.HeapInuse, "heap_idle": m.HeapIdle, "heap_released": m.HeapReleased, "total_alloc": m.TotalAlloc, "mallocs": m.Mallocs, "num_gc": m.NumGC, "gc_cpu_fraction": m.GCCPUFraction, "goroutines": runtime.NumGoroutine(), "active_bulk": proxyResponseCoalesceActiveBytes.Load(), "diagnostics": diagnostics.Snapshot()}
}

func TestMemoryAcceptanceWorker(t *testing.T) {
	role := os.Getenv("FN_KNOCK_MEMORY_WORKER")
	if role == "" {
		t.Skip("opt-in isolated memory/performance worker")
	}
	if role == "client" {
		memoryAcceptanceClient(t)
		return
	}
	stop := make(chan struct{})
	var once sync.Once
	control := http.NewServeMux()
	control.HandleFunc("/snapshot", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(memoryWorkerSnapshot()) })
	control.HandleFunc("/gc", func(w http.ResponseWriter, r *http.Request) {
		runtime.GC()
		json.NewEncoder(w).Encode(memoryWorkerSnapshot())
	})
	control.HandleFunc("/heap", func(w http.ResponseWriter, r *http.Request) { pprof.Lookup("heap").WriteTo(w, 0) })
	control.HandleFunc("/burst", func(w http.ResponseWriter, r *http.Request) {
		// One controlled phase collects while buffers are still owned, so the
		// baseline's sync.Pool entries survive the subsequent single GC as victims.
		var held [][]byte
		for i := 0; i < 32; i++ {
			b := tryAcquireProxyResponseCoalesceBuffer(proxyResponseCoalesceBufferSize)
			if b == nil {
				t.Error("burst exhausted budget early")
				break
			}
			b = b[:cap(b)]
			for j := 0; j < len(b); j += 4096 {
				b[j] = 1
			}
			held = append(held, b)
		}
		if r.URL.Query().Get("controlled") == "1" {
			runtime.GC()
		}
		for _, b := range held {
			releaseProxyResponseCoalesceBuffer(b)
		}
		held = nil
		json.NewEncoder(w).Encode(memoryWorkerSnapshot())
	})
	control.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) { once.Do(func() { close(stop) }) })
	ctl := httptest.NewServer(control)
	defer ctl.Close()
	var handler http.Handler
	if role == "upstream" {
		payload := make([]byte, 2<<20)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			size := len(payload)
			if r.URL.Path == "/small" {
				size = 1024
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			if r.URL.Path == "/unknown" {
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
			} else {
				w.Header().Set("Content-Length", strconv.Itoa(size))
			}
			for offset := 0; offset < size; offset += 32 << 10 {
				end := min(size, offset+(32<<10))
				if _, err := w.Write(payload[offset:end]); err != nil {
					return
				}
			}
		})
	} else if role == "proxy" {
		target, err := url.Parse(os.Getenv("FN_KNOCK_MEMORY_UPSTREAM"))
		if err != nil {
			t.Fatal(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		transport := newInternalTransport()
		defer transport.CloseIdleConnections()
		proxy.Transport = transport
		proxy.BufferPool = sharedProxyBufferPool
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveReverseProxyWithResponseCoalescing(proxy, w, r) })
	} else {
		t.Fatalf("unknown worker role %q", role)
	}
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	if role == "proxy" {
		server.StartTLS()
	} else {
		server.Start()
	}
	defer server.Close()
	json.NewEncoder(os.Stdout).Encode(map[string]any{"url": server.URL, "control": ctl.URL, "pid": os.Getpid()})
	<-stop
}

func memoryAcceptanceClient(t *testing.T) {
	concurrency, _ := strconv.Atoi(os.Getenv("FN_KNOCK_MEMORY_CONCURRENCY"))
	if concurrency < 1 {
		t.Fatal("invalid concurrency")
	}
	seconds, _ := strconv.ParseFloat(os.Getenv("FN_KNOCK_MEMORY_SECONDS"), 64)
	if seconds <= 0 {
		t.Fatal("invalid duration")
	}
	target := os.Getenv("FN_KNOCK_MEMORY_TARGET")
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: os.Getenv("FN_KNOCK_MEMORY_HTTP2") == "1", MaxIdleConns: 256, MaxIdleConnsPerHost: 256}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	// Warm the actual client's connections before the parent snapshots proxy
	// allocations and starts the clock. This excludes TLS/dial startup noise
	// from steady-state throughput, P95 and per-request allocation accounting.
	var warm sync.WaitGroup
	var warmFailed atomic.Bool
	for i := 0; i < concurrency; i++ {
		warm.Add(1)
		go func() {
			defer warm.Done()
			response, err := client.Get(target)
			if err != nil {
				warmFailed.Store(true)
				return
			}
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK {
				warmFailed.Store(true)
			}
		}()
	}
	warm.Wait()
	if warmFailed.Load() {
		t.Fatal("client warmup failed")
	}
	fmt.Fprintln(os.Stdout, "READY")
	var startSignal string
	if _, err := fmt.Fscanln(os.Stdin, &startSignal); err != nil || startSignal != "start" {
		t.Fatal("missing measurement start signal")
	}
	deadline := time.Now().Add(time.Duration(seconds * float64(time.Second)))
	start := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var latencies []float64
	var transferred int64
	var failures int
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var samples []float64
			var bytes int64
			var errs int
			for time.Now().Before(deadline) {
				begin := time.Now()
				response, err := client.Get(target)
				if err != nil {
					errs++
					continue
				}
				var n int64
				if os.Getenv("FN_KNOCK_MEMORY_SLOW") == "1" {
					buf := make([]byte, 64<<10)
					for {
						got, e := io.ReadFull(response.Body, buf)
						n += int64(got)
						if e == io.EOF || e == io.ErrUnexpectedEOF {
							break
						}
						if e != nil {
							err = e
							break
						}
						time.Sleep(time.Millisecond)
					}
				} else {
					n, err = io.Copy(io.Discard, response.Body)
				}
				response.Body.Close()
				expected := int64(2 << 20)
				if response.Request.URL.Path == "/small" {
					expected = 1024
				}
				wantProto := 1
				if os.Getenv("FN_KNOCK_MEMORY_HTTP2") == "1" {
					wantProto = 2
				}
				if err != nil || response.StatusCode != 200 || n != expected || response.ProtoMajor != wantProto {
					errs++
					continue
				}
				bytes += n
				samples = append(samples, float64(time.Since(begin))/float64(time.Millisecond))
			}
			mu.Lock()
			latencies = append(latencies, samples...)
			transferred += bytes
			failures += errs
			mu.Unlock()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	sort.Float64s(latencies)
	if failures != 0 || len(latencies) == 0 {
		t.Fatalf("failed requests=%d successful=%d", failures, len(latencies))
	}
	p95 := latencies[min(len(latencies)-1, int(float64(len(latencies))*0.95))]
	fmt.Printf("RESULT {\"requests\":%d,\"seconds\":%f,\"mib_s\":%f,\"p95_ms\":%f}\n", len(latencies), elapsed, float64(transferred)/(1<<20)/elapsed, p95)
}
