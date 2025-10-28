package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
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