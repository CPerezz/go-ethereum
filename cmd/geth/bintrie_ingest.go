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

// familyWriter writes one key family of the binary tree namespace, in
// ascending key order, keys relative to the namespace. commit makes what was
// put readable; abort drops it, and is a no-op after commit.
type familyWriter interface {
	put(key, value []byte) error
	commit() error
	abort()
}

// newFamilyWriter returns a writer of one key family into pbtdb, the
// namespace of chaindb: sorted tables built under tmpDir that commit ingests,
// if the database can, batches otherwise. Tables skip the write-ahead log,
// the memtables, their flushes and every compaction after, and land in the
// bottom level, where a key range the database holds nothing in goes. The
// node's own writes share the memtables with batches, so every flushed table
// would span them and the family's keys alike, and the database would rewrite
// the family on each level down.
func newFamilyWriter(chaindb, pbtdb ethdb.Database, tmpDir string) (familyWriter, error) {
	ing, ok := rawdb.KeyValueStoreOf(chaindb).(ethdb.TableIngester)
	if !ok {
		return &batchFamily{batch: pbtdb.NewBatch()}, nil
	}
	dir, err := os.MkdirTemp(tmpDir, "bintrie-tables-")
	if err != nil {
		return nil, err
	}
	return &tableFamily{db: ing, dir: dir}, nil
}

// batchFamily writes a family through a batch, written out as it fills.
type batchFamily struct {
	batch ethdb.Batch
}

func (b *batchFamily) put(key, value []byte) error {
	if err := b.batch.Put(key, value); err != nil {
		return err
	}
	if b.batch.ValueSize() < ethdb.IdealBatchSize {
		return nil
	}
	return b.commit()
}

func (b *batchFamily) commit() error {
	if err := b.batch.Write(); err != nil {
		return err
	}
	b.batch.Reset()
	return nil
}

func (b *batchFamily) abort() { b.batch.Reset() }

// familyTableBytes is the record bytes a family's table is cut at: the
// database's bottom-level table size.
const familyTableBytes = 128 << 20

// tableFamily writes a family into sorted tables under dir, one after the
// other, which commit ingests in one call: a family's tables follow each
// other in key order, so none overlap.
type tableFamily struct {
	db    ethdb.TableIngester
	dir   string // on the database's filesystem, the tables are linked in
	w     ethdb.TableWriter
	size  int
	paths []string
	key   []byte
}

func (t *tableFamily) put(key, value []byte) error {
	if t.w == nil {
		path := filepath.Join(t.dir, fmt.Sprintf("%06d.sst", len(t.paths)))
		w, err := t.db.NewTableWriter(path)
		if err != nil {
			return err
		}
		t.w, t.size, t.paths = w, 0, append(t.paths, path)
	}
	t.key = append(append(t.key[:0], rawdb.PBTPrefix...), key...)
	if err := t.w.Put(t.key, value); err != nil {
		return err
	}
	if t.size += len(t.key) + len(value); t.size < familyTableBytes {
		return nil
	}
	w := t.w
	t.w = nil
	return w.Close()
}

func (t *tableFamily) commit() error {
	defer os.RemoveAll(t.dir)
	if t.w != nil {
		w := t.w
		t.w = nil
		if err := w.Close(); err != nil {
			return err
		}
	}
	if len(t.paths) == 0 {
		return nil
	}
	paths := t.paths
	t.paths = nil
	return t.db.Ingest(paths)
}

func (t *tableFamily) abort() {
	if t.w != nil {
		t.w.Close()
		t.w = nil
	}
	t.paths = nil
	os.RemoveAll(t.dir)
}

// flatWriters writes the flat state check 2 re-derives: storage rows, then
// account rows, each family through its own writer.
type flatWriters struct{ storage, accounts familyWriter }

func newFlatWriters(chaindb, pbtdb ethdb.Database, tmpDir string) (*flatWriters, error) {
	storage, err := newFamilyWriter(chaindb, pbtdb, tmpDir)
	if err != nil {
		return nil, err
	}
	accounts, err := newFamilyWriter(chaindb, pbtdb, tmpDir)
	if err != nil {
		storage.abort()
		return nil, err
	}
	return &flatWriters{storage: storage, accounts: accounts}, nil
}

func (f *flatWriters) abort() {
	f.storage.abort()
	f.accounts.abort()
}
