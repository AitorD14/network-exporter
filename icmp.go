package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Global semaphore to limit concurrent MTR processes
var mtrSemaphore = make(chan struct{}, 5) // Max 5 concurrent MTR processes

// MTR cache to avoid running MTR for same IP multiple times
var mtrCache = make(map[string][]MTRHop)
var mtrCacheMutex sync.RWMutex
var mtrCacheTime = make(map[string]time.Time)

// icmpProbe performs DNS lookup, ICMP ping, MTR and returns metrics in Prometheus format
func icmpProbe(ctx context.Context, target string) (string, error) {
	metricPrefix := "networking_"
	startTime := time.Now()

	// 1) DNS lookup with context timeout
	startDNS := time.Now()
	
	// Create DNS resolver with context
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		return buildDNSFailResponse(metricPrefix, target, err), nil
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
		return buildDNSFailResponse(metricPrefix, target, fmt.Errorf("no IP addresses found")), nil
	}

	// Extract IP and protocol
	ipAddress := ips2[0].String()
	ipProtocol := 4
	if ips2[0].To4() == nil {
		ipProtocol = 6
	}
	ipAddrHash := hashIP(ipAddress)

	// 2) ICMP Ping with context
	icmpSuccess, icmpReplyHopLimit, icmpTimes, err := runPing(ctx, ipAddress)
	if err != nil {
		icmpSuccess = 0
	}
	// Store DNS time in the icmp_times for convenience
	icmpTimes["resolve"] = dnsLookupTime

	// 3) MTR - TEMPORARILY DISABLED FOR CPU TESTING
	// mtrHops, err := runMTRJSON(ipAddress)
	// if err != nil {
	// 	// If MTR fails, continue without MTR data
	// 	mtrHops = []MTRHop{}
	// }
	mtrHops := []MTRHop{} // Skip MTR temporarily to test CPU usage

	// 4) Calculate total duration
	endProbe := time.Now()
	probeDurationSeconds := endProbe.Sub(startTime).Seconds()

	// Build Prometheus lines
	var lines []string

	// DNS metric
	lines = append(lines, fmt.Sprintf("# HELP %sdns_lookup_time_seconds Time spent resolving DNS.", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sdns_lookup_time_seconds gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sdns_lookup_time_seconds %f", metricPrefix, dnsLookupTime))

	// Total probe duration
	lines = append(lines, fmt.Sprintf("# HELP %sduration_seconds Total duration of the ICMP probe (seconds).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sduration_seconds gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sduration_seconds %f", metricPrefix, probeDurationSeconds))

	// ICMP durations
	lines = append(lines, fmt.Sprintf("# HELP %sicmp_duration_seconds Duration of ICMP request by phase.", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sicmp_duration_seconds gauge", metricPrefix))
	for phaseName, phaseValue := range icmpTimes {
		lines = append(lines, fmt.Sprintf("%sicmp_duration_seconds{phase=\"%s\"} %f", metricPrefix, phaseName, phaseValue))
	}

	// TTL / hop limit from ping
	lines = append(lines, fmt.Sprintf("# HELP %sicmp_reply_hop_limit Replied packet hop limit (IPv4 TTL).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sicmp_reply_hop_limit gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sicmp_reply_hop_limit %f", metricPrefix, icmpReplyHopLimit))

	// IP hash
	lines = append(lines, fmt.Sprintf("# HELP %sip_addr_hash Hash of the resolved IP address.", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sip_addr_hash gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sip_addr_hash %d", metricPrefix, ipAddrHash))

	// IP protocol
	lines = append(lines, fmt.Sprintf("# HELP %sip_protocol IP protocol version (4 or 6).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sip_protocol gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sip_protocol %d", metricPrefix, ipProtocol))

	// Success
	lines = append(lines, fmt.Sprintf("# HELP %ssuccess Whether the probe was successful (1 = OK, 0 = fail).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %ssuccess gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%ssuccess %d", metricPrefix, icmpSuccess))

	// MTR hops
	for _, hop := range mtrHops {
		lines = append(lines, fmt.Sprintf("%smtr_hop_loss{hop=\"%d\",host=\"%s\"} %f", metricPrefix, hop.Hop, hop.Host, hop.Loss))
		lines = append(lines, fmt.Sprintf("%smtr_hop_avg_latency{hop=\"%d\",host=\"%s\"} %f", metricPrefix, hop.Hop, hop.Host, hop.Avg))
		lines = append(lines, fmt.Sprintf("%smtr_hop_best_latency{hop=\"%d\",host=\"%s\"} %f", metricPrefix, hop.Hop, hop.Host, hop.Best))
		lines = append(lines, fmt.Sprintf("%smtr_hop_worst_latency{hop=\"%d\",host=\"%s\"} %f", metricPrefix, hop.Hop, hop.Host, hop.Wrst))
		lines = append(lines, fmt.Sprintf("%smtr_hop_stdev_latency{hop=\"%d\",host=\"%s\"} %f", metricPrefix, hop.Hop, hop.Host, hop.StDev))
	}

	return strings.Join(lines, "\n") + "\n", nil
}

// runPing runs a single ICMP ping using 'ping' command with context timeout
func runPing(ctx context.Context, ipAddress string) (int, float64, map[string]float64, error) {
	startSetup := time.Now()
	endSetup := time.Now()
	setupTime := endSetup.Sub(startSetup).Seconds()

	startRTT := time.Now()
	replyTTL := 0.0
	success := 0

	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ipAddress)
	output, err := cmd.Output()
	endRTT := time.Now()
	rttTime := endRTT.Sub(startRTT).Seconds()

	if err == nil {
		success = 1
		// Extract TTL from output, e.g. "ttl=56"
		outputStr := string(output)
		if strings.Contains(outputStr, "ttl=") {
			parts := strings.Split(outputStr, "ttl=")
			if len(parts) > 1 {
				ttlStr := strings.Fields(parts[1])[0]
				if ttlValue, err := strconv.ParseFloat(ttlStr, 64); err == nil {
					replyTTL = ttlValue
				}
			}
		}
	}

	return success, replyTTL, map[string]float64{
		"setup": setupTime,
		"rtt":   rttTime,
	}, nil
}

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

// runMTRJSON runs MTR in JSON mode with concurrency control, timeout and caching
func runMTRJSON(ipAddress string) ([]MTRHop, error) {
	// Check cache first (30 second TTL)
	mtrCacheMutex.RLock()
	if cached, exists := mtrCache[ipAddress]; exists {
		if time.Since(mtrCacheTime[ipAddress]) < 30*time.Second {
			mtrCacheMutex.RUnlock()
			return cached, nil
		}
	}
	mtrCacheMutex.RUnlock()

	// Acquire semaphore to limit concurrent MTR processes
	select {
	case mtrSemaphore <- struct{}{}:
		defer func() { <-mtrSemaphore }()
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("MTR queue timeout - too many concurrent requests")
	}

	// Create context with timeout (needs more than 5s even with optimizations)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Optimized for speed: fewer hops, faster interval
	cmd := exec.CommandContext(ctx, "mtr", "--json", "-c", "1", "-i", "0.05", "-m", "10", ipAddress)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
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
	mtrCacheMutex.Lock()
	mtrCache[ipAddress] = result
	mtrCacheTime[ipAddress] = time.Now()
	mtrCacheMutex.Unlock()

	return result, nil
}

// hashIP creates a numeric hash from IP address
func hashIP(ip string) uint32 {
	h := sha256.Sum256([]byte(ip))
	return uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
}

// buildDNSFailResponse returns minimal Prometheus metrics with success=0
func buildDNSFailResponse(metricPrefix, target string, err error) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("# HELP %ssuccess Whether the probe was successful (1 = OK, 0 = fail).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %ssuccess gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%ssuccess 0", metricPrefix))
	lines = append(lines, fmt.Sprintf("# DNS resolution failed for '%s': %v", target, err))
	return strings.Join(lines, "\n") + "\n"
}