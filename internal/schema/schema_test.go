package schema_test

import (
	"path/filepath"
	"testing"

	"forensiq/internal/fcase"
	"forensiq/internal/schema"
)

func TestApply(t *testing.T) {
	c, err := fcase.Open(filepath.Join(t.TempDir(), "s.fcase"), "schema-test")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	if err := schema.Apply(c); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Verify key tables exist
	tables := []string{
		"evtx_events", "mft", "mem_pslist", "ioc_indicators", "prefetch",
		"amcache", "shimcache", "auth_events", "kerberos_events", "services",
		"scheduled_tasks", "wmi_subs", "mem_netscan", "mem_malfind", "mem_cmdline",
		"ps_scriptblock", "defender_events", "lnk_files", "persistence",
	}
	for _, tbl := range tables {
		rows, err := c.Query("SELECT COUNT(*) FROM " + tbl)
		if err != nil {
			t.Errorf("table %s missing: %v", tbl, err)
			continue
		}
		rows.Close()
	}

	// Verify all semantic views are valid
	views := []string{
		"v_process_activity", "v_network_activity", "v_lateral_movement",
		"v_persistence", "v_file_activity", "v_user_activity", "v_alerts",
	}
	for _, v := range views {
		rows, err := c.Query("SELECT * FROM " + v + " LIMIT 0")
		if err != nil {
			t.Errorf("view %s broken: %v", v, err)
			continue
		}
		rows.Close()
	}
}
