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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

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
func newFamilyWriter(chaindb, pbtdb ethdb.Database, tmpDir string, y *blockYield) (familyWriter, error) {
	ing := ingesterOf(chaindb)
	if ing == nil {
		return &batchFamily{batch: pbtdb.NewBatch()}, nil
	}
	dir, err := os.MkdirTemp(tmpDir, "bintrie-tables-")
	if err != nil {
		return nil, err
	}
	return newTableFamily(ing, dir, y), nil
}

// ingesterOf returns the table ingester behind db, nil if its store has none.
func ingesterOf(db ethdb.Database) ethdb.TableIngester {
	ing, _ := rawdb.KeyValueStoreOf(db).(ethdb.TableIngester)
	return ing
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
// other in key order, so none overlap. put only copies records into batches;
// a goroutine of the family's own builds the tables, off the writer's
// critical path, and stands aside while the node processes a block.
type tableFamily struct {
	db  ethdb.TableIngester
	dir string // on the database's filesystem, the tables are linked in
	y   *blockYield

	cur        *recordBatch
	work, free chan *recordBatch
	done       chan struct{}
	err        atomic.Pointer[error] // the first error build met
	paths      []string              // owned by build until done is closed
}

func newTableFamily(db ethdb.TableIngester, dir string, y *blockYield) *tableFamily {
	t := &tableFamily{
		db:   db,
		dir:  dir,
		y:    y,
		work: make(chan *recordBatch, 4),
		free: make(chan *recordBatch, 5),
		done: make(chan struct{}),
	}
	for range cap(t.free) {
		t.free <- new(recordBatch)
	}
	t.cur = <-t.free
	go t.build()
	return t
}

// build writes each batch's records into the family's tables until work
// closes, cutting a table at familyTableBytes. After an error it only
// recycles the batches.
func (t *tableFamily) build() {
	defer close(t.done)
	var (
		w    ethdb.TableWriter
		size int
		key  []byte // the record's, under the namespace's prefix
		err  error
	)
	for b := range t.work {
		t.y.pause(context.Background())
		for i := 0; err == nil && i < b.len(); i++ {
			if w == nil {
				path := filepath.Join(t.dir, fmt.Sprintf("%06d.sst", len(t.paths)))
				if w, err = t.db.NewTableWriter(path); err != nil {
					w = nil
					break
				}
				t.paths, size = append(t.paths, path), 0
			}
			key = append(append(key[:0], rawdb.PBTPrefix...), b.key(i)...)
			value := b.value(i)
			if err = w.Put(key, value); err != nil {
				break
			}
			if size += len(key) + len(value); size >= familyTableBytes {
				err, w = w.Close(), nil
			}
		}
		if err != nil {
			t.err.CompareAndSwap(nil, &err)
		}
		b.reset()
		t.free <- b
	}
	if w != nil {
		if cerr := w.Close(); cerr != nil {
			t.err.CompareAndSwap(nil, &cerr)
		}
	}
}

func (t *tableFamily) put(key, value []byte) error {
	t.cur.add(key, value)
	if !t.cur.full() {
		return nil
	}
	t.work <- t.cur
	t.cur = <-t.free
	if err := t.err.Load(); err != nil {
		return *err
	}
	return nil
}

// finish hands over the last batch and waits until every record put is in a
// table.
func (t *tableFamily) finish() {
	if t.work == nil {
		return
	}
	if t.cur.len() > 0 {
		t.work <- t.cur
	}
	close(t.work)
	<-t.done
	t.work, t.cur, t.free = nil, nil, nil
}

func (t *tableFamily) commit() error {
	defer os.RemoveAll(t.dir)
	t.finish()
	if err := t.err.Load(); err != nil {
		return *err
	}
	paths := t.paths
	t.paths = nil
	if len(paths) == 0 {
		return nil
	}
	return t.db.Ingest(paths)
}

func (t *tableFamily) abort() {
	t.finish()
	t.paths = nil
	os.RemoveAll(t.dir)
}

// flatWriters writes the flat state check 2 re-derives: storage rows, then
// account rows, each family through its own writer.
type flatWriters struct{ storage, accounts familyWriter }

func newFlatWriters(chaindb, pbtdb ethdb.Database, tmpDir string, y *blockYield) (*flatWriters, error) {
	storage, err := newFamilyWriter(chaindb, pbtdb, tmpDir, y)
	if err != nil {
		return nil, err
	}
	accounts, err := newFamilyWriter(chaindb, pbtdb, tmpDir, y)
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
