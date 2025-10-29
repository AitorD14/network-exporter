package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// tcpProbe performs basic TCP connectivity checks
func tcpProbe(ctx context.Context, target string) (string, error) {
	metricPrefix := "networking_"
	startTime := time.Now()

	// Parse target (host:port or [host]:port for IPv6)
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return buildTCPFailResponse(metricPrefix, target, err), nil
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return buildTCPFailResponse(metricPrefix, target, fmt.Errorf("invalid port: %s", portStr)), nil
	}

	// DNS resolution timing with context
	startDNS := time.Now()
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return buildTCPDNSFailResponse(metricPrefix, target, err), nil
	}
	endDNS := time.Now()
	dnsLookupTime := endDNS.Sub(startDNS).Seconds()

	if len(ips) == 0 {
		return buildTCPDNSFailResponse(metricPrefix, target, fmt.Errorf("no IP addresses found")), nil
	}

	// IP details
	ipAddress := ips[0].IP.String()
	ipProtocol := 4
	if ips[0].IP.To4() == nil {
		ipProtocol = 6
	}
	ipAddrHash := hashIP(ipAddress)

	// TCP connection timing with context
	startConnect := time.Now()
	address := net.JoinHostPort(ipAddress, portStr)
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", address)
	endConnect := time.Now()
	connectDuration := endConnect.Sub(startConnect).Seconds()

	var success int
	var tlsHandshakeDuration float64
	var sslEarliestCertExpiry float64

	if err != nil {
		return buildTCPFailResponse(metricPrefix, target, err), nil
	}
	
	success = 1
	defer conn.Close()

	// Check if this is a TLS port (common secure ports)
	isTLSPort := port == 443 || port == 993 || port == 995 || port == 465 || port == 587
	if isTLSPort {
		// Attempt TLS handshake
		startTLS := time.Now()
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		
		if err := tlsConn.Handshake(); err == nil {
			endTLS := time.Now()
			tlsHandshakeDuration = endTLS.Sub(startTLS).Seconds()

			// Get certificate info
			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				sslEarliestCertExpiry = float64(cert.NotAfter.Unix())
			}
		}
		tlsConn.Close()
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
	builder.WriteString("tcp_dns_lookup_time_seconds Time spent resolving DNS.\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("tcp_dns_lookup_time_seconds gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("tcp_dns_lookup_time_seconds ")
	builder.WriteString(strconv.FormatFloat(dnsLookupTime, 'f', 6, 64))
	builder.WriteString("\n")

	// Total probe duration
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("tcp_duration_seconds Total duration of the TCP probe (seconds).\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("tcp_duration_seconds gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("tcp_duration_seconds ")
	builder.WriteString(strconv.FormatFloat(probeDurationSeconds, 'f', 6, 64))
	builder.WriteString("\n")

	// TCP connection duration
	builder.WriteString("# HELP ")
	builder.WriteString(metricPrefix)
	builder.WriteString("tcp_connect_duration_seconds Duration of TCP connection establishment.\n# TYPE ")
	builder.WriteString(metricPrefix)
	builder.WriteString("tcp_connect_duration_seconds gauge\n")
	builder.WriteString(metricPrefix)
	builder.WriteString("tcp_connect_duration_seconds ")
	builder.WriteString(strconv.FormatFloat(connectDuration, 'f', 6, 64))
	builder.WriteString("\n")

	// TLS handshake duration (if applicable)
	if tlsHandshakeDuration > 0 {
		builder.WriteString("# HELP ")
		builder.WriteString(metricPrefix)
		builder.WriteString("tcp_tls_handshake_duration_seconds Duration of TLS handshake.\n# TYPE ")
		builder.WriteString(metricPrefix)
		builder.WriteString("tcp_tls_handshake_duration_seconds gauge\n")
		builder.WriteString(metricPrefix)
		builder.WriteString("tcp_tls_handshake_duration_seconds ")
		builder.WriteString(strconv.FormatFloat(tlsHandshakeDuration, 'f', 6, 64))
		builder.WriteString("\n")
	}

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
		builder.WriteString("tcp_ssl_earliest_cert_expiry SSL certificate expiry timestamp.\n# TYPE ")
		builder.WriteString(metricPrefix)
		builder.WriteString("tcp_ssl_earliest_cert_expiry gauge\n")
		builder.WriteString(metricPrefix)
		builder.WriteString("tcp_ssl_earliest_cert_expiry ")
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

// buildTCPFailResponse returns minimal Prometheus metrics with success=0
func buildTCPFailResponse(metricPrefix, target string, err error) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("# HELP %sprobe_success Whether the probe was successful (1 = OK, 0 = fail).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sprobe_success gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sprobe_success 0", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TCP probe failed for '%s': %v", target, err))
	return strings.Join(lines, "\n") + "\n"
}

// buildTCPDNSFailResponse returns minimal Prometheus metrics with success=0 for DNS failures
func buildTCPDNSFailResponse(metricPrefix, target string, err error) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("# HELP %sprobe_success Whether the probe was successful (1 = OK, 0 = fail).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sprobe_success gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sprobe_success 0", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TCP DNS resolution failed for '%s': %v", target, err))
	return strings.Join(lines, "\n") + "\n"
}