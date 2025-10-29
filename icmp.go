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

// Removed MTR semaphore to prevent blocking and timeouts

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

	// 3) MTR - Network path tracing
	mtrHops, err := runMTRJSON(ctx, ipAddress)
	if err != nil {
		// If MTR fails, continue without MTR data
		if os.Getenv("DEBUG") == "true" || os.Getenv("DEBUG") == "1" {
			log.Printf("DEBUG: MTR failed for %s: %v", ipAddress, err)
		}
		mtrHops = []MTRHop{}
	}

	// 4) Calculate total duration
	endProbe := time.Now()
	probeDurationSeconds := endProbe.Sub(startTime).Seconds()

	// Build Prometheus lines efficiently
	var builder strings.Builder
	builder.Grow(1024) // Pre-allocate capacity

	// DNS metric
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("dns_lookup_time_seconds Time spent resolving DNS.\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("dns_lookup_time_seconds gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("dns_lookup_time_seconds ")
	builder.WriteString(strconv.FormatFloat(dnsLookupTime, 'f', 6, 64))
	builder.WriteString("\n")

	// Total probe duration
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("duration_seconds Total duration of the ICMP probe (seconds).\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("duration_seconds gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("duration_seconds ")
	builder.WriteString(strconv.FormatFloat(probeDurationSeconds, 'f', 6, 64))
	builder.WriteString("\n")

	// ICMP durations
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("icmp_duration_seconds Duration of ICMP request by phase.\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("icmp_duration_seconds gauge\n")
	for phaseName, phaseValue := range icmpTimes {
		builder.WriteString(metricPrefix)
		builder.WriteString("icmp_duration_seconds{phase=\"")
		builder.WriteString(phaseName)
		builder.WriteString("\"} ")
		builder.WriteString(strconv.FormatFloat(phaseValue, 'f', 6, 64))
		builder.WriteString("\n")
	}

	// TTL / hop limit from ping
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("icmp_reply_hop_limit Replied packet hop limit (IPv4 TTL).\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("icmp_reply_hop_limit gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("icmp_reply_hop_limit ")
	builder.WriteString(strconv.FormatFloat(icmpReplyHopLimit, 'f', 6, 64))
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

	// Success
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("success Whether the probe was successful (1 = OK, 0 = fail).\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("success gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("success ")
	builder.WriteString(strconv.Itoa(icmpSuccess))
	builder.WriteString("\n")

	// MTR hops (currently disabled but code ready)
	for _, hop := range mtrHops {
		builder.WriteString(metricPrefix)
		builder.WriteString("mtr_hop_loss{hop=\"")
		builder.WriteString(strconv.Itoa(hop.Hop))
		builder.WriteString("\",host=\"")
		builder.WriteString(hop.Host)
		builder.WriteString("\"} ")
		builder.WriteString(strconv.FormatFloat(hop.Loss, 'f', 6, 64))
		builder.WriteString("\n")
		
		builder.WriteString(metricPrefix)
		builder.WriteString("mtr_hop_avg_latency{hop=\"")
		builder.WriteString(strconv.Itoa(hop.Hop))
		builder.WriteString("\",host=\"")
		builder.WriteString(hop.Host)
		builder.WriteString("\"} ")
		builder.WriteString(strconv.FormatFloat(hop.Avg, 'f', 6, 64))
		builder.WriteString("\n")
		
		builder.WriteString(metricPrefix)
		builder.WriteString("mtr_hop_best_latency{hop=\"")
		builder.WriteString(strconv.Itoa(hop.Hop))
		builder.WriteString("\",host=\"")
		builder.WriteString(hop.Host)
		builder.WriteString("\"} ")
		builder.WriteString(strconv.FormatFloat(hop.Best, 'f', 6, 64))
		builder.WriteString("\n")
		
		builder.WriteString(metricPrefix)
		builder.WriteString("mtr_hop_worst_latency{hop=\"")
		builder.WriteString(strconv.Itoa(hop.Hop))
		builder.WriteString("\",host=\"")
		builder.WriteString(hop.Host)
		builder.WriteString("\"} ")
		builder.WriteString(strconv.FormatFloat(hop.Wrst, 'f', 6, 64))
		builder.WriteString("\n")
		
		builder.WriteString(metricPrefix)
		builder.WriteString("mtr_hop_stdev_latency{hop=\"")
		builder.WriteString(strconv.Itoa(hop.Hop))
		builder.WriteString("\",host=\"")
		builder.WriteString(hop.Host)
		builder.WriteString("\"} ")
		builder.WriteString(strconv.FormatFloat(hop.StDev, 'f', 6, 64))
		builder.WriteString("\n")
	}

	return builder.String(), nil
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
func runMTRJSON(ctx context.Context, ipAddress string) ([]MTRHop, error) {
	// Check cache first (30 second TTL)
	mtrCacheMutex.RLock()
	if cached, exists := mtrCache[ipAddress]; exists {
		if time.Since(mtrCacheTime[ipAddress]) < 30*time.Second {
			mtrCacheMutex.RUnlock()
			return cached, nil
		}
	}
	mtrCacheMutex.RUnlock()

	// No semaphore blocking - let MTR run freely with context timeout

	// Use provided context with sufficient timeout for MTR
	mtrCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	// Optimized for speed: fewer hops, faster interval
	cmd := exec.CommandContext(mtrCtx, "mtr", "--json", "-c", "1", "-i", "0.05", "-m", "10", ipAddress)
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

// buildICMPFailResponse returns minimal Prometheus metrics with success=0 for ICMP failures
func buildICMPFailResponse(metricPrefix, target string, err error) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("# HELP %ssuccess Whether the probe was successful (1 = OK, 0 = fail).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %ssuccess gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%ssuccess 0", metricPrefix))
	lines = append(lines, fmt.Sprintf("# ICMP probe failed for '%s': %v", target, err))
	return strings.Join(lines, "\n") + "\n"
}