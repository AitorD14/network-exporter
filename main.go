package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

func main() {
	// Determine if DEBUG is enabled via environment variable
	debug := os.Getenv("DEBUG")
	if debug == "true" || debug == "1" {
		log.Println("DEBUG mode is ON.")
	} else {
		log.Println("DEBUG mode is OFF (INFO level).")
	}

	// Create router
	r := mux.NewRouter()

	// Add basic auth middleware to all routes except health
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/probe", basicAuth(probeHandler)).Methods("GET")

	// Server configuration
	port := os.Getenv("PORT")
	if port == "" {
		port = "9116"
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Check if SSL certificates exist
	certFile := "/etc/network_exporter/cert.pem"
	keyFile := "/etc/network_exporter/key.pem"
	
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			log.Printf("Starting Network Exporter with HTTPS on port %s", port)
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
	module := r.URL.Query().Get("module")
	target := r.URL.Query().Get("target")

	if target == "" {
		http.Error(w, "Error: 'target' not specified\n", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain")

	switch module {
	case "icmp":
		result, err := icmpProbe(target)
		if err != nil {
			http.Error(w, fmt.Sprintf("ICMP probe failed: %v\n", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, result)
	case "http_2xx":
		result, err := http2xxProbe(target)
		if err != nil {
			http.Error(w, fmt.Sprintf("HTTP 2xx probe failed: %v\n", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, result)
	case "http_4xx":
		result, err := http4xxProbe(target)
		if err != nil {
			http.Error(w, fmt.Sprintf("HTTP 4xx probe failed: %v\n", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, result)
	case "tcp_connect":
		result, err := tcpProbe(target)
		if err != nil {
			http.Error(w, fmt.Sprintf("TCP probe failed: %v\n", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, result)
	default:
		http.Error(w, fmt.Sprintf("Error: Unsupported module '%s'\n", module), http.StatusBadRequest)
	}
}

// basicAuth provides basic authentication middleware
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read credentials from file (like Python version)
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Network Exporter"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Expected credentials (same as Python version)
		expectedUsername := "network_exporter"
		expectedPassword := "monitoring123" // Default password, should read from htpasswd file

		// Use subtle.ConstantTimeCompare to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(username), []byte(expectedUsername)) != 1 ||
			subtle.ConstantTimeCompare([]byte(password), []byte(expectedPassword)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="Network Exporter"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}