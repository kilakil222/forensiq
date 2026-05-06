package shimcache

// ExportParseBlob exposes parseBlob for white-box testing from the
// shimcache_test package.
func ExportParseBlob(blob []byte) ([]string, error) {
	entries, err := parseBlob(blob)
	if err != nil {
		return nil, err
	}
	paths := make([]string, len(entries))
	for i, e := range entries {
		paths[i] = e.path
	}
	return paths, nil
}
