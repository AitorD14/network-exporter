package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MTR semaphore to limit concurrent processes and prevent CPU saturation
var mtrModuleSemaphore = make(chan struct{}, 1) // Max 1 concurrent MTR process

// MTR cache to avoid running MTR for same IP multiple times
var mtrModuleCache = make(map[string][]MTRHop)
var mtrModuleCacheMutex sync.RWMutex
var mtrModuleCacheTime = make(map[string]time.Time)

// MTRHop represents a single hop in MTR output
type MTRHop struct {
	Hop   int     `json:"count"`
	Host  string  `json:"host"`
	Loss  float64 `json:"Loss%"`
	Avg   float64 `json:"Avg"`
	Best  float64 `json:"Best"`
	Wrst  float64 `json:"Wrst"`
	StDev float64 `json:"StDev"`
}

// MTRReport represents the MTR JSON output structure
type MTRReport struct {
	Report struct {
		Hubs []MTRHop `json:"hubs"`
	} `json:"report"`
}

// mtrProbe performs pure MTR network path tracing
func mtrProbe(ctx context.Context, target string) (string, error) {
	metricPrefix := "networking_"
	startTime := time.Now()

	// 1) DNS lookup with context timeout
	startDNS := time.Now()
	
	// Create DNS resolver with context
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		return buildMTRDNSFailResponse(metricPrefix, target, err), nil
	}
	endDNS := time.Now()
	dnsLookupTime := endDNS.Sub(startDNS).Seconds()
	
	// Convert IPAddr to IP for compatibility
	var ipList []net.IP
	for _, ip := range ips {
		ipList = append(ipList, ip.IP)
	}
	ips2 := ipList

	if len(ips2) == 0 {
		return buildMTRDNSFailResponse(metricPrefix, target, fmt.Errorf("no IP addresses found")), nil
	}

	// Extract IP and protocol
	ipAddress := ips2[0].String()
	ipProtocol := 4
	if ips2[0].To4() == nil {
		ipProtocol = 6
	}
	ipAddrHash := hashMTRIP(ipAddress)

	// 2) MTR - Network path tracing
	mtrHops, err := runMTRJSONModule(ctx, ipAddress)
	if err != nil {
		// If MTR fails, return error response
		if os.Getenv("DEBUG") == "true" || os.Getenv("DEBUG") == "1" {
			log.Printf("DEBUG: MTR failed for %s: %v", ipAddress, err)
		}
		return buildMTRFailResponse(metricPrefix, target, err), nil
	}

	// 3) Calculate total duration
	endProbe := time.Now()
	probeDurationSeconds := endProbe.Sub(startTime).Seconds()

	// Build Prometheus lines efficiently
	var builder strings.Builder
	builder.Grow(2048) // Pre-allocate more capacity for MTR data

	// DNS metric
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("mtr_dns_lookup_time_seconds Time spent resolving DNS.\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("mtr_dns_lookup_time_seconds gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("mtr_dns_lookup_time_seconds ")
	builder.WriteString(strconv.FormatFloat(dnsLookupTime, 'f', 6, 64))
	builder.WriteString("\n")

	// Total probe duration
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("mtr_duration_seconds Total duration of the MTR probe (seconds).\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("mtr_duration_seconds gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("mtr_duration_seconds ")
	builder.WriteString(strconv.FormatFloat(probeDurationSeconds, 'f', 6, 64))
	builder.WriteString("\n")

	// IP hash
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("ip_addr_hash Hash of the resolved IP address.\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("ip_addr_hash gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("ip_addr_hash ")
	builder.WriteString(strconv.FormatUint(uint64(ipAddrHash), 10))
	builder.WriteString("\n")

	// IP protocol
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("ip_protocol IP protocol version (4 or 6).\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("ip_protocol gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("ip_protocol ")
	builder.WriteString(strconv.Itoa(ipProtocol))
	builder.WriteString("\n")

	// MTR hops count
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("mtr_hops_total Number of hops found by MTR.\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("mtr_hops_total gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("mtr_hops_total ")
	builder.WriteString(strconv.Itoa(len(mtrHops)))
	builder.WriteString("\n")

	// MTR hops metrics
	for _, hop := range mtrHops {
		// Loss percentage
		builder.WriteString("# HELP ")
		builder.WriteString(metricPrefix)
		builder.WriteString("mtr_hop_loss_percent Packet loss percentage for each hop.\n# TYPE ")
		builder.WriteString(metricPrefix)
		builder.WriteString("mtr_hop_loss_percent gauge\n")
		builder.WriteString(metricPrefix)
		builder.WriteString("mtr_hop_loss_percent{hop=\"")
		builder.WriteString(strconv.Itoa(hop.Hop))
		builder.WriteString("\",host=\"")
		builder.WriteString(hop.Host)
		builder.WriteString("\"} ")
		builder.WriteString(strconv.FormatFloat(hop.Loss, 'f', 6, 64))
		builder.WriteString("\n")
		
		// Average latency
		builder.WriteString(metricPrefix)
		builder.WriteString("mtr_hop_avg_latency_ms{hop=\"")
		builder.WriteString(strconv.Itoa(hop.Hop))
		builder.WriteString("\",host=\"")
		builder.WriteString(hop.Host)
		builder.WriteString("\"} ")
		builder.WriteString(strconv.FormatFloat(hop.Avg, 'f', 6, 64))
		builder.WriteString("\n")
		
		// Best latency
		builder.WriteString(metricPrefix)
		builder.WriteString("mtr_hop_best_latency_ms{hop=\"")
		builder.WriteString(strconv.Itoa(hop.Hop))
		builder.WriteString("\",host=\"")
		builder.WriteString(hop.Host)
		builder.WriteString("\"} ")
		builder.WriteString(strconv.FormatFloat(hop.Best, 'f', 6, 64))
		builder.WriteString("\n")
		
		// Worst latency
		builder.WriteString(metricPrefix)
		builder.WriteString("mtr_hop_worst_latency_ms{hop=\"")
		builder.WriteString(strconv.Itoa(hop.Hop))
		builder.WriteString("\",host=\"")
		builder.WriteString(hop.Host)
		builder.WriteString("\"} ")
		builder.WriteString(strconv.FormatFloat(hop.Wrst, 'f', 6, 64))
		builder.WriteString("\n")
		
		// Standard deviation
		builder.WriteString(metricPrefix)
		builder.WriteString("mtr_hop_stdev_latency_ms{hop=\"")
		builder.WriteString(strconv.Itoa(hop.Hop))
		builder.WriteString("\",host=\"")
		builder.WriteString(hop.Host)
		builder.WriteString("\"} ")
		builder.WriteString(strconv.FormatFloat(hop.StDev, 'f', 6, 64))
		builder.WriteString("\n")
	}

	// Success
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_success Whether the probe was successful (1 = OK, 0 = fail).\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_success gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_success 1\n")

	return builder.String(), nil
}

// runMTRJSONModule runs MTR in JSON mode with concurrency control for the MTR module
func runMTRJSONModule(ctx context.Context, ipAddress string) ([]MTRHop, error) {
	// Check cache first (120 second TTL)
	mtrModuleCacheMutex.RLock()
	if cached, exists := mtrModuleCache[ipAddress]; exists {
		if time.Since(mtrModuleCacheTime[ipAddress]) < 120*time.Second {
			mtrModuleCacheMutex.RUnlock()
			return cached, nil
		}
	}
	mtrModuleCacheMutex.RUnlock()

	// Acquire semaphore to limit concurrent MTR processes (wait for slot)
	mtrModuleSemaphore <- struct{}{}        // Block until slot available
	defer func() { <-mtrModuleSemaphore }() // Release slot when done

	// Use reasonable timeout for MTR while preventing CPU overload
	mtrCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Balanced MTR: reasonable count and hops for good coverage
	cmd := exec.CommandContext(mtrCtx, "mtr", "--json", "-c", "3", "-i", "0.1", "-m", "10", ipAddress)
	
	// Create a channel to receive the result
	done := make(chan struct{})
	var output []byte
	var err error
	
	go func() {
		defer close(done)
		output, err = cmd.Output()
	}()
	
	// Wait for either completion or timeout
	select {
	case <-done:
		// Command completed
		if err != nil {
			return nil, err
		}
	case <-mtrCtx.Done():
		// Force kill the process if it's still running
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return nil, fmt.Errorf("MTR timeout exceeded")
	}

	var mtrReport MTRReport
	if err := json.Unmarshal(output, &mtrReport); err != nil {
		return nil, err
	}

	var result []MTRHop
	for _, hub := range mtrReport.Report.Hubs {
		result = append(result, MTRHop{
			Hop:   hub.Hop, // This maps to "count" field in JSON
			Host:  hub.Host,
			Loss:  hub.Loss,
			Avg:   hub.Avg,
			Best:  hub.Best,
			Wrst:  hub.Wrst,
			StDev: hub.StDev,
		})
	}

	// Cache the result
	mtrModuleCacheMutex.Lock()
	mtrModuleCache[ipAddress] = result
	mtrModuleCacheTime[ipAddress] = time.Now()
	mtrModuleCacheMutex.Unlock()

	return result, nil
}

// hashMTRIP creates a numeric hash from IP address
func hashMTRIP(ip string) uint32 {
	h := sha256.Sum256([]byte(ip))
	return uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
}

// buildMTRDNSFailResponse returns minimal Prometheus metrics with success=0 for DNS failures
func buildMTRDNSFailResponse(metricPrefix, target string, err error) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("# HELP %sprobe_success Whether the probe was successful (1 = OK, 0 = fail).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sprobe_success gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sprobe_success 0", metricPrefix))
	lines = append(lines, fmt.Sprintf("# MTR DNS resolution failed for '%s': %v", target, err))
	return strings.Join(lines, "\n") + "\n"
}

// buildMTRFailResponse returns minimal Prometheus metrics with success=0 for MTR failures
func buildMTRFailResponse(metricPrefix, target string, err error) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("# HELP %sprobe_success Whether the probe was successful (1 = OK, 0 = fail).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sprobe_success gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sprobe_success 0", metricPrefix))
	lines = append(lines, fmt.Sprintf("# MTR probe failed for '%s': %v", target, err))
	return strings.Join(lines, "\n") + "\n"
}