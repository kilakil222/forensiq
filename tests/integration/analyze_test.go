package integration_test

import (
	"os"
	"path/filepath"
	"testing"

	"forensiq/internal/fcase"
	"forensiq/internal/orchestrator"
	"forensiq/internal/schema"
)

func TestAnalyzeTriage(t *testing.T) {
	if _, err := os.Stat("../../tests/testdata/triage.zip"); err != nil {
		t.Skip("testdata/triage.zip not found — run: go run tests/testdata/make_testdata.go")
	}

	casePath := filepath.Join(t.TempDir(), "test.fcase")
	opts := orchestrator.Options{
		TriagePath: "../../tests/testdata/triage.zip",
		CasePath:   casePath,
		CaseName:   "IntegrationTest",
	}

	c, result, err := orchestrator.Run(opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer c.Close()

	if result.TotalArtifacts == 0 {
		t.Error("expected at least one artifact extracted")
	}

	var count int64
	c.DB().QueryRow("SELECT COUNT(*) FROM prefetch").Scan(&count)
	if count == 0 {
		t.Error("expected prefetch rows from triage.zip")
	}

	t.Logf("Extracted %d artifacts in %v", result.TotalArtifacts, result.Elapsed)
}

func TestSchemaIntegrity(t *testing.T) {
	c, err := fcase.Open(filepath.Join(t.TempDir(), "s.fcase"), "schema-check")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := schema.Apply(c); err != nil {
		t.Fatalf("schema.Apply: %v", err)
	}

	views := []string{
		"v_process_activity", "v_network_activity", "v_lateral_movement",
		"v_persistence", "v_file_activity", "v_user_activity", "v_alerts",
	}
	for _, v := range views {
		rows, err := c.Query("SELECT * FROM " + v + " LIMIT 0")
		if err != nil {
			t.Errorf("view %s not queryable: %v", v, err)
			continue
		}
		rows.Close()
	}
}
