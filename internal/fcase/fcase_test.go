package fcase_test

import (
	"os"
	"path/filepath"
	"testing"

	"forensiq/internal/fcase"
)

func TestOpenCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.fcase")

	c, err := fcase.Open(path, "TestCase")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestExec(t *testing.T) {
	dir := t.TempDir()
	c, err := fcase.Open(filepath.Join(dir, "t.fcase"), "T")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	err = c.Exec("CREATE TABLE test_tbl (id INTEGER, val TEXT)")
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}

	err = c.Exec("INSERT INTO test_tbl VALUES (1, 'hello')")
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rows, err := c.Query("SELECT val FROM test_tbl WHERE id = 1")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("expected one row")
	}
	var val string
	if err := rows.Scan(&val); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if val != "hello" {
		t.Fatalf("got %q, want hello", val)
	}
}
