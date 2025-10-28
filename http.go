package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

	// DNS resolution timing
	startDNS := time.Now()
	ips, err := net.LookupIP(parsedURL.Hostname())
	if err != nil {
		return buildHTTPFailResponse(metricPrefix, target, err), nil
	}
	endDNS := time.Now()
	dnsLookupTime := endDNS.Sub(startDNS).Seconds()

	if len(ips) == 0 {
		return buildHTTPFailResponse(metricPrefix, target, fmt.Errorf("no IP addresses found")), nil
	}

	// IP details
	ipAddress := ips[0].String()
	ipProtocol := 4
	if ips[0].To4() == nil {
		ipProtocol = 6
	}
	ipAddrHash := hashIP(ipAddress)

	// HTTP Client configuration
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: 15 * time.Second,
		}).DialContext,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
	}

	// Create request
	req, err := http.NewRequest("GET", target, nil)
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

	// Build Prometheus lines
	var lines []string

	// DNS metric
	lines = append(lines, fmt.Sprintf("# HELP %sprobe_dns_lookup_time_seconds Time spent resolving DNS.", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sprobe_dns_lookup_time_seconds gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sprobe_dns_lookup_time_seconds %f", metricPrefix, dnsLookupTime))

	// Total probe duration
	lines = append(lines, fmt.Sprintf("# HELP %sprobe_duration_seconds Total duration of the HTTP probe (seconds).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sprobe_duration_seconds gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sprobe_duration_seconds %f", metricPrefix, probeDurationSeconds))

	// HTTP duration
	lines = append(lines, fmt.Sprintf("# HELP %sprobe_http_duration_seconds Duration of HTTP request by phase.", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sprobe_http_duration_seconds gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sprobe_http_duration_seconds{phase=\"resolve\"} %f", metricPrefix, dnsLookupTime))
	lines = append(lines, fmt.Sprintf("%sprobe_http_duration_seconds{phase=\"connect\"} %f", metricPrefix, httpDuration))
	lines = append(lines, fmt.Sprintf("%sprobe_http_duration_seconds{phase=\"processing\"} %f", metricPrefix, httpDuration))

	// HTTP status code
	lines = append(lines, fmt.Sprintf("# HELP %sprobe_http_status_code HTTP status code.", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sprobe_http_status_code gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sprobe_http_status_code %d", metricPrefix, statusCode))

	// IP hash
	lines = append(lines, fmt.Sprintf("# HELP %sip_addr_hash Hash of the resolved IP address.", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sip_addr_hash gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sip_addr_hash %d", metricPrefix, ipAddrHash))

	// IP protocol
	lines = append(lines, fmt.Sprintf("# HELP %sip_protocol IP protocol version (4 or 6).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sip_protocol gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sip_protocol %d", metricPrefix, ipProtocol))

	// SSL certificate expiry (if applicable)
	if sslEarliestCertExpiry > 0 {
		lines = append(lines, fmt.Sprintf("# HELP %sprobe_ssl_earliest_cert_expiry SSL certificate expiry timestamp.", metricPrefix))
		lines = append(lines, fmt.Sprintf("# TYPE %sprobe_ssl_earliest_cert_expiry gauge", metricPrefix))
		lines = append(lines, fmt.Sprintf("%sprobe_ssl_earliest_cert_expiry %f", metricPrefix, sslEarliestCertExpiry))
	}

	// Success
	lines = append(lines, fmt.Sprintf("# HELP %sprobe_success Whether the probe was successful (1 = OK, 0 = fail).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sprobe_success gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sprobe_success %d", metricPrefix, success))

	return strings.Join(lines, "\n") + "\n", nil
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