package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Determine if DEBUG is enabled via environment variable
	debug := os.Getenv("DEBUG")
	if debug == "true" || debug == "1" {
		log.Println("DEBUG mode is ON.")
	} else {
		log.Println("DEBUG mode is OFF (INFO level).")
	}

	// Load web configuration
	webConfig, err := LoadWebConfig("")
	if err != nil {
		log.Fatalf("Failed to load web config: %v", err)
	}

	// Create router
	r := mux.NewRouter()

	// Add basic auth middleware to all routes except health
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/probe", basicAuthWithConfig(webConfig, probeHandler)).Methods("GET")
	
	// Add debug profiling routes (only in debug mode)
	if os.Getenv("DEBUG") == "true" || os.Getenv("DEBUG") == "1" {
		r.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
	}

	// Server configuration
	port := os.Getenv("PORT")
	if port == "" {
		port = "9115"
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
		// Disable HTTP/2 to fix concurrency issues
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		// Optimize for high concurrency
		MaxHeaderBytes: 1 << 16, // 64KB
		// Basic TLS config
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		// Suppress TLS error logging
		ErrorLog: log.New(io.Discard, "", 0),
	}

	// Check SSL configuration from web_config.yml
	certFile, keyFile := webConfig.GetSSLPaths()
	
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			log.Printf("Starting Network Exporter with HTTPS on port %s", port)
			log.Printf("Using SSL cert: %s, key: %s", certFile, keyFile)
			log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
		}
	}
	
	log.Printf("Starting Network Exporter with HTTP on port %s", port)
	log.Fatal(srv.ListenAndServe())
}

// healthHandler handles /health endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK\n")
}

// probeHandler handles /probe endpoint
func probeHandler(w http.ResponseWriter, r *http.Request) {
	// Add aggressive request timeout to prevent goroutine leaks
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	
	module := r.URL.Query().Get("module")
	target := r.URL.Query().Get("target")

	// Debug logging
	if os.Getenv("DEBUG") == "true" || os.Getenv("DEBUG") == "1" {
		log.Printf("DEBUG: Probe request - module=%s target=%s", module, target)
	}

	if target == "" {
		http.Error(w, "Error: 'target' not specified\n", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")

	switch module {
	case "icmp":
		result, err := icmpProbe(ctx, target)
		if err != nil {
			http.Error(w, fmt.Sprintf("ICMP probe failed: %v\n", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, result)
	case "http_2xx":
		result, err := http2xxProbe(ctx, target)
		if err != nil {
			http.Error(w, fmt.Sprintf("HTTP 2xx probe failed: %v\n", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, result)
	case "http_4xx":
		result, err := http4xxProbe(ctx, target)
		if err != nil {
			http.Error(w, fmt.Sprintf("HTTP 4xx probe failed: %v\n", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, result)
	case "tcp_connect":
		result, err := tcpProbe(ctx, target)
		if err != nil {
			http.Error(w, fmt.Sprintf("TCP probe failed: %v\n", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, result)
	default:
		http.Error(w, fmt.Sprintf("Error: Unsupported module '%s'\n", module), http.StatusBadRequest)
	}
}

// basicAuthWithConfig provides basic authentication middleware using web config
func basicAuthWithConfig(webConfig *WebConfig, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Network Exporter"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get expected credentials from web config
		users := webConfig.GetBasicAuthUsers()
		expectedPassword, userExists := users[username]
		
		if !userExists {
			w.Header().Set("WWW-Authenticate", `Basic realm="Network Exporter"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if password is bcrypt hash or plain text
		var passwordMatch bool
		if strings.HasPrefix(expectedPassword, "$2b$") || strings.HasPrefix(expectedPassword, "$2a$") {
			// Bcrypt hash - use bcrypt.CompareHashAndPassword
			err := bcrypt.CompareHashAndPassword([]byte(expectedPassword), []byte(password))
			passwordMatch = (err == nil)
		} else {
			// Plain text password - use constant time compare
			passwordMatch = (subtle.ConstantTimeCompare([]byte(password), []byte(expectedPassword)) == 1)
		}

		if !passwordMatch {
			w.Header().Set("WWW-Authenticate", `Basic realm="Network Exporter"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}