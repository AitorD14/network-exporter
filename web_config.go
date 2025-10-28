package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

// WebConfig represents the web configuration structure
type WebConfig struct {
	TLSServerConfig *TLSServerConfig       `yaml:"tls_server_config,omitempty"`
	BasicAuthUsers  map[string]string      `yaml:"basic_auth_users,omitempty"`
	HTTPConfig      *HTTPConfig            `yaml:"http_config,omitempty"`
}

type TLSServerConfig struct {
	CertFile string `yaml:"cert_file,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`
}

type HTTPConfig struct {
	HTTP2 bool `yaml:"http2,omitempty"`
}

// LoadWebConfig loads configuration from web_config.yml file
func LoadWebConfig(configFile string) (*WebConfig, error) {
	if configFile == "" {
		configFile = "/etc/network_exporter/web_config.yml"
	}

	// Check if file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Printf("Web config file not found: %s, using defaults", configFile)
		return &WebConfig{}, nil
	}

	// Read file
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %v", configFile, err)
	}

	// Parse YAML
	var config WebConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %v", configFile, err)
	}

	log.Printf("Loaded web config from %s", configFile)
	return &config, nil
}

// GetSSLPaths returns the SSL certificate and key paths
func (wc *WebConfig) GetSSLPaths() (string, string) {
	if wc.TLSServerConfig != nil {
		return wc.TLSServerConfig.CertFile, wc.TLSServerConfig.KeyFile
	}
	
	// Default paths if not specified in config
	return "/etc/network_exporter/cert.pem", "/etc/network_exporter/key.pem"
}

// GetBasicAuthUsers returns the basic auth users map
func (wc *WebConfig) GetBasicAuthUsers() map[string]string {
	if wc.BasicAuthUsers != nil {
		return wc.BasicAuthUsers
	}
	
	// Default user if not specified
	return map[string]string{
		"network_exporter": "monitoring123",
	}
}