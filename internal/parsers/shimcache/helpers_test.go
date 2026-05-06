package shimcache_test

import "forensiq/internal/parsers/shimcache"

// exportParseBlob is a test-only alias that lets shimcache_test call the
// internal parseBlob function via the exported bridge in export_test.go.
var exportParseBlob = shimcache.ExportParseBlob
