package fcase

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

type Case struct {
	db   *sql.DB
	Path string
	Name string
}

func Open(path, name string) (*Case, error) {
	db, err := sql.Open("duckdb", filepath.ToSlash(path))
	if err != nil {
		return nil, fmt.Errorf("open duckdb %s: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping duckdb: %w", err)
	}
	c := &Case{db: db, Path: path, Name: name}
	if err := c.initMeta(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init meta: %w", err)
	}
	return c, nil
}

func (c *Case) Close() error {
	return c.db.Close()
}

func (c *Case) Exec(query string, args ...any) error {
	_, err := c.db.Exec(query, args...)
	return err
}

func (c *Case) Query(query string, args ...any) (*sql.Rows, error) {
	return c.db.Query(query, args...)
}

func (c *Case) DB() *sql.DB {
	return c.db
}

func (c *Case) initMeta() error {
	return c.Exec(`
		CREATE TABLE IF NOT EXISTS case_meta (
			id          INTEGER PRIMARY KEY,
			name        TEXT NOT NULL,
			created_at  TIMESTAMP NOT NULL,
			os_type     TEXT,
			analyst     TEXT,
			notes       TEXT
		)
	`)
}

func (c *Case) SetMeta(name, osType, analyst string) error {
	return c.Exec(`
		INSERT INTO case_meta (id, name, created_at, os_type, analyst)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			os_type = excluded.os_type,
			analyst = excluded.analyst
	`, name, time.Now().UTC(), osType, analyst)
}
