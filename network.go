package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"slices"

	"github.com/schollz/progressbar/v3"
)

var scanStopped atomic.Bool
var logMu sync.Mutex

var httpClient *http.Client

func initHttpClient(preferIPv6 bool) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 3 * time.Second,
			}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			ips, err := resolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}

			for _, ip := range ips {
				if preferIPv6 {
					if ip.To4() == nil {
						return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
					}
				} else {
					if ip.To4() != nil {
						return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
					}
				}
			}

			return nil, fmt.Errorf("no suitable IP found for %s", host)
		},
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}

	httpClient = &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}

func checkNetworkStats(preferIPv6 bool) {
	fmt.Printf("\n%s Determining network quality to adjust scan options...\n\n", prompt)
	const (
		testTargetURL     = "http://www.google.com/generate_204"
		initialTestCount  = 100
		goodLatencyMs     = 50
		moderateLatencyMs = 100
		poorLatencyMs     = 200
		acceptableLoss    = 5.0
		highLoss          = 10.0
		moderateJitterMs  = 5.0
		highJitterMs      = 10.0
		maxConcurrency    = 5
	)

	var (
		totalLatency       int64
		successCount       int
		wg                 sync.WaitGroup
		latencyResults     = make(chan int64, initialTestCount)
		concurrencyLimiter = make(chan struct{}, maxConcurrency)
	)

	networkMode := "IPv4"
	if preferIPv6 {
		networkMode = "IPv6"
	}
	desc := fmt.Sprintf("Testing %s network...", networkMode)
	bar := progressbar.NewOptions(initialTestCount,
		progressbar.OptionShowBytes(false),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetDescription(desc),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]#[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	initHttpClient(preferIPv6)
	for range initialTestCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			concurrencyLimiter <- struct{}{}
			defer func() { <-concurrencyLimiter }()
			start := time.Now()
			resp, err := httpClient.Head(testTargetURL)
			bar.Add(1)
			latency := time.Since(start).Milliseconds()
			if err == nil && resp.StatusCode == http.StatusNoContent {
				if resp.Body != nil {
					resp.Body.Close()
				}
				latencyResults <- latency
			} else {
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
				latencyResults <- -1
			}
		}()
	}

	wg.Wait()
	close(latencyResults)
	fmt.Println()

	successfulLatencies := make([]int64, 0, successCount)
	for res := range latencyResults {
		if res >= 0 {
			successCount++
			totalLatency += res
			successfulLatencies = append(successfulLatencies, res)
		}
	}

	if successCount == 0 {
		failMessage("Initial network quality test failed. Could not reach test server.")
		fmt.Printf("\n%s Fallback to default scan settings.\n", prompt)
		return
	}

	slices.Sort(successfulLatencies)
	medianLatency := successfulLatencies[len(successfulLatencies)/2]
	lossRate := float64(initialTestCount-successCount) / float64(initialTestCount) * 100
	var avgJitter float64

	if successCount > 1 {
		var totalJitter int64
		for i := 0; i < len(successfulLatencies)-1; i++ {
			diff := successfulLatencies[i+1] - successfulLatencies[i]
			if diff < 0 {
				diff = -diff
			}
			totalJitter += diff
		}
		avgJitter = float64(totalJitter) / float64(successCount-1)
		fmt.Printf("\n%s Avg Latency: %dms | Jitter: %.1fms | Loss: %.1f%%\n", prompt, medianLatency, avgJitter, lossRate)
	} else {
		fmt.Printf("\n%s Avg Latency: %dms | Jitter not calculated (unsuccessful tests) | Loss: %.1f%%\n", prompt, medianLatency, lossRate)
	}

	if medianLatency >= int64(poorLatencyMs) || lossRate >= highLoss || (successCount > 1 && avgJitter >= highJitterMs) {
		scanConfig.IPv4Retries = 7
		successMessage("Network appears slow/unstable.")
	} else if medianLatency >= int64(moderateLatencyMs) || lossRate >= acceptableLoss || (successCount > 1 && avgJitter >= moderateJitterMs) {
		scanConfig.IPv4Retries = 5
		successMessage("Network is moderate or some packet loss detected.")
	} else {
		successMessage("Network quality seems good. Using default scan settings.")
	}
}

func testEndpoint(endpoint string, portIdx int) (ScanResult, bool) {
	proxyURL := must(url.Parse(fmt.Sprintf("http://127.0.0.1:%d", 1080+portIdx)))
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	defer transport.CloseIdleConnections()

	currentRetries := scanConfig.IPv4Retries
	var successCount int
	var totalLatency int64

	for t := range currentRetries {
		if scanStopped.Load() {
			return ScanResult{}, false
		}
		time.Sleep(time.Duration(t*scanConfig.RetryStaggeringMs) * time.Millisecond)

		if scanStopped.Load() {
			return ScanResult{}, false
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "HEAD", "http://www.gstatic.com/generate_204", nil)
		client := &http.Client{Transport: transport}

		start := time.Now()
		resp, err := client.Do(req)
		latency := time.Since(start).Milliseconds()
		cancel()

		if err == nil && resp.StatusCode == 204 {
			if resp.Body != nil {
				resp.Body.Close()
			}
			successCount++
			totalLatency += latency
		}
	}

	if successCount == 0 {
		return ScanResult{}, false
	}

	avgLatency := totalLatency / int64(successCount)
	lossRate := float64(currentRetries-successCount) / float64(currentRetries) * 100
	return ScanResult{Endpoint: endpoint, Loss: lossRate, Latency: avgLatency}, true
}

func scanBatch(endpoints []string, startIdx int) ([]ScanResult, []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, scanConfig.MaxConcurrent)
	var tested atomic.Int32
	var successCount atomic.Int32
	total := int32(len(endpoints))

	var mu sync.Mutex
	var allResults []ScanResult
	var failedEndpoints []string

	for i, endpoint := range endpoints {
		if scanStopped.Load() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ep string, idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			if scanStopped.Load() {
				mu.Lock()
				failedEndpoints = append(failedEndpoints, ep)
				mu.Unlock()
				tested.Add(1)
				return
			}

			result, ok := testEndpoint(ep, startIdx+idx)
			tested.Add(1)

			mu.Lock()
			if ok {
				successCount.Add(1)
				allResults = append(allResults, result)
			} else {
				failedEndpoints = append(failedEndpoints, ep)
			}
			mu.Unlock()

			fmt.Printf("\r%s Scanning... %d/%d found:%d", prompt, tested.Load(), total, successCount.Load())
		}(endpoint, i)
	}
	wg.Wait()

	fmt.Printf("\r%s Scanning... %d/%d found:%d - Done\n", prompt, total, total, successCount.Load())

	return allResults, failedEndpoints
}

func scanEndpoints() ([]ScanResult, error) {
	err := createXrayConfig()
	if err != nil {
		return nil, err
	}

	cmd, err := runXrayCore()
	if err != nil {
		log.Print(err)
		return nil, err
	}

	var allResults []ScanResult
	failedEndpoints := scanConfig.Endpoints

	for retry := 0; retry <= scanConfig.RangeRetries; retry++ {
		if scanStopped.Load() {
			break
		}

		if retry > 0 {
			fmt.Printf("\n%s Retry %d/%d for %d failed endpoints...\n",
				prompt, retry, scanConfig.RangeRetries, len(failedEndpoints))

			if err := cmd.Process.Kill(); err != nil {
				return allResults, fmt.Errorf("error killing Xray core: %w", err)
			}
			cmd.Wait()

			err := createXrayConfig()
			if err != nil {
				return allResults, err
			}
			cmd, err = runXrayCore()
			if err != nil {
				return allResults, err
			}
		}

		results, failed := scanBatch(failedEndpoints, 0)

		for _, r := range results {
			fmt.Printf("%s -> OK Loss:%.1f%% Latency:%dms\n", r.Endpoint, r.Loss, r.Latency)
		}

		allResults = append(allResults, results...)
		failedEndpoints = failed

		if len(failedEndpoints) == 0 {
			break
		}
	}

	if err := cmd.Process.Kill(); err != nil {
		log.Printf("Error killing Xray core: %v", err)
	}
	cmd.Wait()

	return allResults, nil
}
