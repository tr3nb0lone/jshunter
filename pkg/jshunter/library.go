package jshunter

import "fmt"

// Bootstraps an opinionated config
func NewConfig() *Config {
	return &Config{
		Threads:        5,
		Timeout:        30,
		Retry:          3,
		MinConfidence:  DefaultMinConfidence,
		MaxBytes:       DefaultMaxBytes,
		VerifyTimeout:  6,
		PerHost:        3,
		VerifyWorkers:  8,
		Quiet:          true,
		AllowInternal:  false,
		SkipTLS:        false,
		RateLimit:      0,
		FoundOnly:      false,
		ShowConfidence: false,
	}
}

func normalizeLibraryConfig(config *Config) *Config {
	if config == nil {
		config = NewConfig()
	}
	if config.Timeout <= 0 {
		config.Timeout = 30
	}
	if config.Retry < 0 {
		config.Retry = 0
	}
	if config.Threads <= 0 {
		config.Threads = 5
	}
	if config.MinConfidence <= 0 {
		config.MinConfidence = DefaultMinConfidence
	}
	if config.MaxBytes <= 0 {
		config.MaxBytes = DefaultMaxBytes
	}
	if config.VerifyTimeout <= 0 {
		config.VerifyTimeout = 6
	}
	if config.PerHost <= 0 {
		config.PerHost = 3
	}
	if config.VerifyWorkers <= 0 {
		config.VerifyWorkers = 8
	}
	return config
}

// ScanURL fetches and scans a JavaScript URL with programmatic configuration.
func ScanURL(urlStr string, config *Config) (map[string][]string, error) {
	if urlStr == "" {
		return nil, fmt.Errorf("url is required")
	}
	config = normalizeLibraryConfig(config)
	_, matches := searchForSensitiveDataWithConfig(urlStr, config)
	return matches, nil
}

// ExtractEndpointsURL fetches a JavaScript URL and extracts endpoint paths.
func ExtractEndpointsURL(urlStr string, config *Config) ([]string, error) {
	if urlStr == "" {
		return nil, fmt.Errorf("url is required")
	}
	config = normalizeLibraryConfig(config)
	endpoints := extractEndpointsFromURLWithConfig(urlStr, config)
	return endpoints, nil
}

// ScanJSContent analyzes JavaScript content without performing network requests.
func ScanJSContent(source string, body []byte, minConfidence float64) []*Finding {
	if minConfidence <= 0 {
		minConfidence = DefaultMinConfidence
	}
	return analyzeBody(source, body, minConfidence)
}
