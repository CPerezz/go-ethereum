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
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/ethdb"
)

// TestIngest: disjoint tables are adopted together and readable; tables whose
// bounds touch are refused and their files removed. Both engines: a legacy
// database opens with pebble v1.
func TestIngest(t *testing.T) {
	type store interface {
		ethdb.TableIngester
		ethdb.KeyValueReader
		io.Closer
	}
	for name, open := range map[string]func(dir string) (store, error){
		"v2": func(dir string) (store, error) { return New(dir, 0, 0, "", false) },
		"v1": func(dir string) (store, error) { return NewV1(dir, 0, 0, "", false) },
	} {
		t.Run(name, func(t *testing.T) {
			db, err := open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			dir := t.TempDir()
			table := func(file string, kvs ...[2]string) string {
				path := filepath.Join(dir, file)
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
			a := table("a.sst", [2]string{"a", "1"}, [2]string{"b", "2"})
			c := table("c.sst", [2]string{"c", "3"}, [2]string{"d", "4"})
			if err := db.Ingest([]string{a, c}); err != nil {
				t.Fatalf("ingesting disjoint tables: %v", err)
			}
			for k, want := range map[string]string{"a": "1", "b": "2", "c": "3", "d": "4"} {
				if got, err := db.Get([]byte(k)); err != nil || string(got) != want {
					t.Fatalf("Get(%q) = %q, %v; want %q", k, got, err, want)
				}
			}
			e := table("e.sst", [2]string{"e", "5"}, [2]string{"f", "6"})
			f := table("f.sst", [2]string{"f", "7"}, [2]string{"g", "8"})
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
		})
	}
}
