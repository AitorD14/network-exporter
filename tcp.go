package main

import (
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

	// DNS resolution timing
	startDNS := time.Now()
	ips, err := net.LookupIP(host)
	if err != nil {
		return buildTCPFailResponse(metricPrefix, target, err), nil
	}
	endDNS := time.Now()
	dnsLookupTime := endDNS.Sub(startDNS).Seconds()

	if len(ips) == 0 {
		return buildTCPFailResponse(metricPrefix, target, fmt.Errorf("no IP addresses found")), nil
	}

	// IP details
	ipAddress := ips[0].String()
	ipProtocol := 4
	if ips[0].To4() == nil {
		ipProtocol = 6
	}
	ipAddrHash := hashIP(ipAddress)

	// TCP connection timing
	startConnect := time.Now()
	address := net.JoinHostPort(ipAddress, portStr)
	conn, err := net.DialTimeout("tcp", address, 15*time.Second)
	endConnect := time.Now()
	connectDuration := endConnect.Sub(startConnect).Seconds()

	var success int
	var tlsHandshakeDuration float64
	var sslEarliestCertExpiry float64

	if err != nil {
		success = 0
	} else {
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
	}

	// Calculate total duration
	endProbe := time.Now()
	probeDurationSeconds := endProbe.Sub(startTime).Seconds()

	// Build Prometheus lines
	var lines []string

	// DNS metric
	lines = append(lines, fmt.Sprintf("# HELP %stcp_dns_lookup_time_seconds Time spent resolving DNS.", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %stcp_dns_lookup_time_seconds gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%stcp_dns_lookup_time_seconds %f", metricPrefix, dnsLookupTime))

	// Total probe duration
	lines = append(lines, fmt.Sprintf("# HELP %stcp_duration_seconds Total duration of the TCP probe (seconds).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %stcp_duration_seconds gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%stcp_duration_seconds %f", metricPrefix, probeDurationSeconds))

	// TCP connection duration
	lines = append(lines, fmt.Sprintf("# HELP %stcp_connect_duration_seconds Duration of TCP connection establishment.", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %stcp_connect_duration_seconds gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%stcp_connect_duration_seconds %f", metricPrefix, connectDuration))

	// TLS handshake duration (if applicable)
	if tlsHandshakeDuration > 0 {
		lines = append(lines, fmt.Sprintf("# HELP %stcp_tls_handshake_duration_seconds Duration of TLS handshake.", metricPrefix))
		lines = append(lines, fmt.Sprintf("# TYPE %stcp_tls_handshake_duration_seconds gauge", metricPrefix))
		lines = append(lines, fmt.Sprintf("%stcp_tls_handshake_duration_seconds %f", metricPrefix, tlsHandshakeDuration))
	}

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
		lines = append(lines, fmt.Sprintf("# HELP %stcp_ssl_earliest_cert_expiry SSL certificate expiry timestamp.", metricPrefix))
		lines = append(lines, fmt.Sprintf("# TYPE %stcp_ssl_earliest_cert_expiry gauge", metricPrefix))
		lines = append(lines, fmt.Sprintf("%stcp_ssl_earliest_cert_expiry %f", metricPrefix, sslEarliestCertExpiry))
	}

	// Success
	lines = append(lines, fmt.Sprintf("# HELP %sprobe_success Whether the probe was successful (1 = OK, 0 = fail).", metricPrefix))
	lines = append(lines, fmt.Sprintf("# TYPE %sprobe_success gauge", metricPrefix))
	lines = append(lines, fmt.Sprintf("%sprobe_success %d", metricPrefix, success))

	return strings.Join(lines, "\n") + "\n", nil
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