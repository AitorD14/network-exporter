package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// http2xxProbe performs HTTP/HTTPS probe expecting 2xx responses
func http2xxProbe(ctx context.Context, target string) (string, error) {
	return httpProbe(ctx, target, true)
}

// http4xxProbe performs HTTP/HTTPS probe expecting 4xx responses
func http4xxProbe(ctx context.Context, target string) (string, error) {
	return httpProbe(ctx, target, false)
}

// httpProbe performs HTTP/HTTPS connectivity checks
func httpProbe(ctx context.Context, target string, expect2xx bool) (string, error) {
	metricPrefix := "networking_"
	startTime := time.Now()

	// Parse URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return buildHTTPFailResponse(metricPrefix, target, err), nil
	}

	// DNS resolution timing with context
	startDNS := time.Now()
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, parsedURL.Hostname())
	if err != nil {
		return buildHTTPFailResponse(metricPrefix, target, err), nil
	}
	endDNS := time.Now()
	dnsLookupTime := endDNS.Sub(startDNS).Seconds()

	if len(ips) == 0 {
		return buildHTTPFailResponse(metricPrefix, target, fmt.Errorf("no IP addresses found")), nil
	}

	// IP details
	ipAddress := ips[0].IP.String()
	ipProtocol := 4
	if ips[0].IP.To4() == nil {
		ipProtocol = 6
	}
	ipAddrHash := hashIP(ipAddress)

	// HTTP Client configuration with context
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return buildHTTPFailResponse(metricPrefix, target, err), nil
	}
	req.Header.Set("User-Agent", "CubePath Monitoring")

	// Perform HTTP request
	startHTTP := time.Now()
	resp, err := client.Do(req)
	endHTTP := time.Now()
	httpDuration := endHTTP.Sub(startHTTP).Seconds()

	var statusCode int
	var success int

	if err != nil {
		statusCode = 0
		success = 0
	} else {
		statusCode = resp.StatusCode
		resp.Body.Close()

		if expect2xx {
			// For http_2xx module, success if 2xx
			if statusCode >= 200 && statusCode < 300 {
				success = 1
			} else {
				success = 0
			}
		} else {
			// For http_4xx module, success if 4xx
			if statusCode >= 400 && statusCode < 500 {
				success = 1
			} else {
				success = 0
			}
		}
	}

	// SSL certificate details (if HTTPS)
	var sslEarliestCertExpiry float64
	if parsedURL.Scheme == "https" && resp != nil && resp.TLS != nil {
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			sslEarliestCertExpiry = float64(cert.NotAfter.Unix())
		}
	}

	// Calculate total duration
	endProbe := time.Now()
	probeDurationSeconds := endProbe.Sub(startTime).Seconds()

	// Build Prometheus lines efficiently
	var builder strings.Builder
	builder.Grow(1024) // Pre-allocate capacity

	// DNS metric
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_dns_lookup_time_seconds Time spent resolving DNS.\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_dns_lookup_time_seconds gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_dns_lookup_time_seconds ")
	builder.WriteString(strconv.FormatFloat(dnsLookupTime, 'f', 6, 64))
	builder.WriteString("\n")

	// Total probe duration
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_duration_seconds Total duration of the HTTP probe (seconds).\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_duration_seconds gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_duration_seconds ")
	builder.WriteString(strconv.FormatFloat(probeDurationSeconds, 'f', 6, 64))
	builder.WriteString("\n")

	// HTTP duration phases
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_http_duration_seconds Duration of HTTP request by phase.\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_http_duration_seconds gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_http_duration_seconds{phase=\"resolve\"} ")
	builder.WriteString(strconv.FormatFloat(dnsLookupTime, 'f', 6, 64))
	builder.WriteString("\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_http_duration_seconds{phase=\"connect\"} ")
	builder.WriteString(strconv.FormatFloat(httpDuration, 'f', 6, 64))
	builder.WriteString("\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_http_duration_seconds{phase=\"processing\"} ")
	builder.WriteString(strconv.FormatFloat(httpDuration, 'f', 6, 64))
	builder.WriteString("\n")

	// HTTP status code
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_http_status_code HTTP status code.\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_http_status_code gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_http_status_code ")
	builder.WriteString(strconv.Itoa(statusCode))
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

	// SSL certificate expiry (if applicable)
	if sslEarliestCertExpiry > 0 {
		builder.WriteString("# HELP ")
		builder.WriteString(metricPrefix)
		builder.WriteString("probe_ssl_earliest_cert_expiry SSL certificate expiry timestamp.\n# TYPE ")
		builder.WriteString(metricPrefix)
		builder.WriteString("probe_ssl_earliest_cert_expiry gauge\n")
		builder.WriteString(metricPrefix)
		builder.WriteString("probe_ssl_earliest_cert_expiry ")
		builder.WriteString(strconv.FormatFloat(sslEarliestCertExpiry, 'f', 6, 64))
		builder.WriteString("\n")
	}

	// Success
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_success Whether the probe was successful (1 = OK, 0 = fail).\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_success gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("probe_success ")
	builder.WriteString(strconv.Itoa(success))
	builder.WriteString("\n")

	return builder.String(), nil
}

// buildHTTPFailResponse returns minimal Prometheus metrics with success=0
func buildHTTPFailResponse(metricPrefix, target string, err error) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("# HELP %sprobe_success Whether the probe was successful (1 = OK, 0 = fail).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sprobe_success gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sprobe_success 0", metricPrefix))
	lines = append(lines, fmt.Sprintf("# HTTP probe failed for '%s': %v", target, err))
	return strings.Join(lines, "\n") + "\n"
}