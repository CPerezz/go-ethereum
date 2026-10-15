// Copyright 2026 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

// nsWriter writes records into the binary tree namespace under key family ‖
// k1 ‖ k2, each family's in ascending key order. flush lets it write out what
// it holds; close writes the rest and returns the first error met.
type nsWriter interface {
	put(family, k1, k2, value []byte) error
	flush() error
	close() error
}

// newNamespaceWriter returns a writer into db's binary tree namespace: one
// ingesting sorted tables built under tmpDir if the database can, batches
// otherwise. Tables skip the write-ahead log, the memtables and their
// flushes, and land below anything they do not overlap, where batches would
// stall a live node's block processing.
func newNamespaceWriter(db ethdb.Database, tmpDir string) (nsWriter, error) {
	if ing, ok := rawdb.KeyValueStoreOf(db).(ethdb.TableIngester); ok {
		dir, err := os.MkdirTemp(tmpDir, "bintrie-tables-")
		if err != nil {
			return nil, err
		}
		return &tableStage{db: ing, dir: dir, tables: make(map[string]*familyTable)}, nil
	}
	return &batchWriter{Batch: db.NewBatch()}, nil
}

// batchWriter writes namespace records through a batch, building each key in
// a buffer of its own.
type batchWriter struct {
	ethdb.Batch
	key []byte
}

func (b *batchWriter) put(family, k1, k2, value []byte) error {
	b.key = append(append(append(append(b.key[:0], rawdb.PBTPrefix...), family...), k1...), k2...)
	return b.Put(b.key, value)
}

func (b *batchWriter) flush() error {
	if b.ValueSize() < ethdb.IdealBatchSize {
		return nil
	}
	return b.close()
}

func (b *batchWriter) close() error {
	if err := b.Write(); err != nil {
		return err
	}
	b.Reset()
	return nil
}

// ingestTableBytes is the size a family's table is cut at.
const ingestTableBytes = 64 << 20

// tableStage writes namespace records into sorted tables, one open per key
// family, and ingests them all at close. Families never overlap, and a
// family's tables follow each other in key order, so none of the tables do.
type tableStage struct {
	db     ethdb.TableIngester
	dir    string // on the database's filesystem, the tables are linked in
	tables map[string]*familyTable
	paths  []string
	key    []byte
	err    error
	closed bool
}

type familyTable struct {
	w    ethdb.TableWriter
	size int
}

func (s *tableStage) put(family, k1, k2, value []byte) error {
	if s.err != nil {
		return s.err
	}
	t := s.tables[string(family)]
	if t == nil {
		path := filepath.Join(s.dir, fmt.Sprintf("%d.sst", len(s.paths)))
		w, err := s.db.NewTableWriter(path)
		if err != nil {
			s.err = err
			return err
		}
		s.paths = append(s.paths, path)
		t = &familyTable{w: w}
		s.tables[string(family)] = t
	}
	s.key = append(append(append(append(s.key[:0], rawdb.PBTPrefix...), family...), k1...), k2...)
	if s.err = t.w.Put(s.key, value); s.err != nil {
		return s.err
	}
	if t.size += len(s.key) + len(value); t.size >= ingestTableBytes {
		delete(s.tables, string(family))
		s.err = t.w.Close()
	}
	return s.err
}

func (s *tableStage) flush() error { return s.err }

// close finishes the open tables and, unless a write failed, ingests them
// all in one call. Later calls return the same.
func (s *tableStage) close() error {
	if s.closed {
		return s.err
	}
	s.closed = true
	for _, t := range s.tables {
		if err := t.w.Close(); err != nil && s.err == nil {
			s.err = err
		}
	}
	if s.err == nil && len(s.paths) > 0 {
		s.err = s.db.Ingest(s.paths)
	}
	os.RemoveAll(s.dir)
	return s.err
}
