# JSHunter Library Integration

JSHunter is available as a Go library from:

```go
import "github.com/tr3nb0lone/jshunter/pkg/jshunter"
```

## Quick start

```go
package main

import (
	"fmt"

	"github.com/tr3nb0lone/jshunter/pkg/jshunter"
)

func main() {
	cfg := jshunter.NewConfig()
	cfg.Secrets = true
	cfg.Tokens = true

	matches, err := jshunter.ScanURL("https://example.com/app.js", cfg)
	if err != nil {
		panic(err)
	}
	fmt.Printf("categories: %d\n", len(matches))
}
```

## Core integration APIs

- `jshunter.NewConfig() *jshunter.Config`
  - Returns a library-friendly default config (quiet mode enabled, sane timeouts/retries).
- `jshunter.ScanURL(url string, config *jshunter.Config) (map[string][]string, error)`
  - Fetches and analyzes JavaScript at a URL.
- `jshunter.ExtractEndpointsURL(url string, config *jshunter.Config) ([]string, error)`
  - Fetches JavaScript and extracts endpoint-like paths/URLs.
- `jshunter.ScanJSContent(source string, body []byte, minConfidence float64) []*jshunter.Finding`
  - Runs offline analysis on in-memory JavaScript content.

## Additional exported building blocks

The package also exposes integration primitives such as:

- `Config`, `Finding`, `Rule`, `Severity`, `VerifyResult`
- `ExtractFromHTML`, `FetchAndScanSourceMap`, `ParseCSPOrigins`
- `LoadRulesFile`, `LoadIgnoreFile`, `DiffPrevious`
- `FetchRobots`, `IngestHAR`, `ToSARIF`, `VerifyAllConcurrent`

Use these directly when you need lower-level orchestration.
