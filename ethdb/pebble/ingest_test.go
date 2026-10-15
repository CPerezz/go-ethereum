// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package pebble

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTable builds a sorted table of the ascending pairs kvs in dir.
func writeTable(t *testing.T, db *Database, dir, name string, kvs [][2]string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	w, err := db.NewTableWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range kvs {
		if err := w.Put([]byte(kv[0]), []byte(kv[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIngest(t *testing.T) {
	db, err := New(t.TempDir(), 0, 0, "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	dir := t.TempDir()

	// Disjoint tables are adopted together, and readable.
	a := writeTable(t, db, dir, "a.sst", [][2]string{{"a", "1"}, {"b", "2"}})
	c := writeTable(t, db, dir, "c.sst", [][2]string{{"c", "3"}, {"d", "4"}})
	if err := db.Ingest([]string{a, c}); err != nil {
		t.Fatalf("ingesting disjoint tables: %v", err)
	}
	for k, want := range map[string]string{"a": "1", "b": "2", "c": "3", "d": "4"} {
		if got, err := db.Get([]byte(k)); err != nil || string(got) != want {
			t.Fatalf("Get(%q) = %q, %v; want %q", k, got, err, want)
		}
	}
	// Tables whose bounds touch are refused, and their files removed.
	e := writeTable(t, db, dir, "e.sst", [][2]string{{"e", "5"}, {"f", "6"}})
	f := writeTable(t, db, dir, "f.sst", [][2]string{{"f", "7"}, {"g", "8"}})
	if err := db.Ingest([]string{e, f}); err == nil {
		t.Fatal("ingested tables whose bounds touch")
	}
	for _, p := range []string{e, f} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("refused table %s left behind: %v", p, err)
		}
	}
	if _, err := db.Get([]byte("e")); err == nil {
		t.Fatal("a refused table's record is readable")
	}
}
