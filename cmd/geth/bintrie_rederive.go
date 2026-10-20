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
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/holiman/uint256"
	"golang.org/x/sync/errgroup"
)

// The merkle re-derivation shared by both commands: the converter demands
// the state root it scanned, the importer the root its anchor commits.

const merkleAccountRecordLen = 8 + 32 + common.HashLength

// appendMerkleAccountRecord appends the account fields the fold needs. The
// storage root is absent: it is recomputed from the storage records.
func appendMerkleAccountRecord(dst []byte, nonce uint64, balance *uint256.Int, codeHash common.Hash) []byte {
	dst = binary.BigEndian.AppendUint64(dst, nonce)
	balance32 := balance.Bytes32()
	dst = append(dst, balance32[:]...)
	return append(dst, codeHash[:]...)
}

// appendAccountRLP appends a's encoding with storage root root: the consensus
// one, or with slim the flat-state one, whose empty root and code hash are
// empty strings (types.SlimAccountRLP). It encodes through enc's reused
// buffer, where rlp.EncodeToBytes allocates the account and its encoding.
func appendAccountRLP(dst []byte, enc *rlp.EncoderBuffer, a *foldAccount, root common.Hash, slim bool) []byte {
	enc.Reset(nil)
	list := enc.List()
	enc.WriteUint64(a.nonce)
	enc.WriteUint256(&a.balance)
	if slim && root == types.EmptyRootHash {
		enc.WriteBytes(nil)
	} else {
		enc.WriteBytes(root[:])
	}
	if slim && a.codeHash == types.EmptyCodeHash {
		enc.WriteBytes(nil)
	} else {
		enc.WriteBytes(a.codeHash[:])
	}
	enc.ListEnd(list)
	return enc.AppendToBytes(dst)
}

// heldStream wraps a sorted record stream with one record of lookahead.
type heldStream struct {
	stream     *bintrie.RecordStream
	key, value []byte
	done       bool
}

// current returns the held record, loading one if none is held.
func (h *heldStream) current() ([]byte, []byte, error) {
	if h.done || h.key != nil {
		return h.key, h.value, nil
	}
	key, value, err := h.stream.Next()
	if err == io.EOF {
		h.done = true
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	h.key, h.value = key, value
	return key, value, nil
}

// advance drops the held record.
func (h *heldStream) advance() { h.key, h.value = nil, nil }

// rederiveMerkleRoot folds account and storage records back into a
// merkle-patricia trie and returns its root. Both streams must ascend, which
// the sorters guarantee. Storage under no account is the loss this check
// exists to catch, so it errors rather than being skipped.
//
// The calling goroutine walks both streams in keccak order; workers fold the
// storage tries and one more goroutine the account trie, taking the storage
// roots in account order. With flat writers, the walk also writes the flat
// state: storage rows as it goes, account rows spilled to a file under tmpDir
// and written after the last storage row, each family through its own writer.
// Everything is committed by return.
func rederiveMerkleRoot(ctx context.Context, accounts, slots *bintrie.RecordStream, flat *flatWriters, tmpDir string, workers int, total uint64, y *blockYield) (common.Hash, error) {
	workers = max(workers, 1)
	var (
		g, gctx   = errgroup.WithContext(ctx)
		jobs      = make([]chan *foldBatch, workers)
		roots     = make([]chan []common.Hash, workers)
		free      = make(chan *foldBatch, 3*workers)
		accts     = make(chan []foldAccount, 4)
		acctsFree = make(chan []foldAccount, 6)
		root      common.Hash
	)
	for range cap(free) {
		free <- new(foldBatch)
	}
	for range cap(acctsFree) {
		acctsFree <- make([]foldAccount, 0, foldBatchSize)
	}
	for i := range workers {
		jobs[i], roots[i] = make(chan *foldBatch, 2), make(chan []common.Hash, 2)
		g.Go(func() error { return foldStorage(gctx, jobs[i], roots[i], free, y) })
	}
	g.Go(func() error {
		var err error
		root, err = foldAccounts(gctx, accts, acctsFree, roots, y)
		return err
	})
	g.Go(func() error {
		defer func() {
			for _, ch := range jobs {
				close(ch)
			}
			close(accts)
		}()
		return walkMerkleRecords(gctx, accounts, slots, flat, tmpDir, total, jobs, free, accts, acctsFree, y)
	})
	if err := g.Wait(); err != nil {
		return common.Hash{}, err
	}
	return root, nil
}

// foldBatchSize is how many slots, or accounts, a fold batch carries.
var foldBatchSize = 4096

// foldBatch carries storage slots to a fold worker, the value of keys[i]
// ending at vals[ends[i]]. Each of accounts closes one account's slots, at
// that index; slots past the last close continue into the worker's next
// batch. done ends the worker's job, after a close.
type foldBatch struct {
	keys     []common.Hash
	vals     []byte
	ends     []int
	accounts []int
	done     bool
}

// foldAccount is an account on its way to the account trie.
type foldAccount struct {
	hash     common.Hash
	nonce    uint64
	balance  uint256.Int
	codeHash common.Hash
	storage  bool
}

// walkMerkleRecords joins the account and slot streams in keccak order,
// writing the flat state if batch is set, and hands the slots to the fold
// workers and the accounts to the account trie: a job of whole accounts to
// one worker, the next job to the next. total is the accounts and slots
// expected, for progress reports.
func walkMerkleRecords(ctx context.Context, accounts, slots *bintrie.RecordStream, flat *flatWriters, tmpDir string, total uint64,
	jobs []chan *foldBatch, free chan *foldBatch, accts, acctsFree chan []foldAccount, y *blockYield) error {
	var (
		slotHeld   = &heldStream{stream: slots}
		walked     atomic.Uint64 // accounts and slots
		walkedAccs uint64
		acctRows   *spillFile
		worker     int
		cur        *foldBatch
		pending    []foldAccount
		// Encodings and keys, reused: the writers and the spill copy them.
		enc          = rlp.NewEncoderBuffer(nil)
		slim, rowKey []byte
	)
	prog := startProgress("Re-deriving merkle state", "records", total, walked.Load)
	defer prog.stop()
	if flat != nil {
		var err error
		if acctRows, err = newSpillFile(tmpDir, "bintrie-acctrows-*"); err != nil {
			return err
		}
		defer acctRows.close()
	}
	take := func() error {
		if err := y.pause(ctx); err != nil {
			return err
		}
		select {
		case cur = <-free:
		case <-ctx.Done():
			return ctx.Err()
		}
		cur.keys, cur.vals, cur.ends, cur.accounts, cur.done = cur.keys[:0], cur.vals[:0], cur.ends[:0], cur.accounts[:0], false
		return nil
	}
	send := func(done bool) error {
		cur.done = done
		select {
		case jobs[worker] <- cur:
		case <-ctx.Done():
			return ctx.Err()
		}
		if done {
			worker = (worker + 1) % len(jobs)
		}
		return take()
	}
	sendAccounts := func() error {
		select {
		case accts <- pending:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case pending = <-acctsFree:
		case <-ctx.Done():
			return ctx.Err()
		}
		pending = pending[:0]
		return nil
	}
	if err := take(); err != nil {
		return err
	}
	select {
	case pending = <-acctsFree:
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		akey, avalue, err := accounts.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(avalue) != merkleAccountRecordLen {
			return fmt.Errorf("account record for %x is %d bytes, want %d", akey, len(avalue), merkleAccountRecordLen)
		}
		acct := foldAccount{
			hash:     common.BytesToHash(akey),
			nonce:    binary.BigEndian.Uint64(avalue[:8]),
			codeHash: common.BytesToHash(avalue[40:merkleAccountRecordLen]),
		}
		acct.balance.SetBytes(avalue[8:40])
		for {
			skey, svalue, err := slotHeld.current()
			if err != nil {
				return err
			}
			if skey == nil {
				break
			}
			switch bytes.Compare(skey[:common.HashLength], acct.hash[:]) {
			case -1:
				return fmt.Errorf("storage under account hash %x, which holds no account", skey[:common.HashLength])
			case 1:
			default:
				cur.keys = append(cur.keys, common.Hash(skey[common.HashLength:]))
				cur.vals = append(cur.vals, svalue...)
				cur.ends = append(cur.ends, len(cur.vals))
				if flat != nil {
					rowKey = append(append(rowKey[:0], rawdb.SnapshotStoragePrefix...), skey...)
					if err := flat.storage.put(rowKey, svalue); err != nil {
						return err
					}
				}
				acct.storage = true
				slotHeld.advance()
				walked.Add(1)
				// A storage trie past a batch goes on in the same worker's next.
				if len(cur.keys) == 2*foldBatchSize {
					if err := send(false); err != nil {
						return err
					}
				}
				continue
			}
			break
		}
		if acct.storage {
			cur.accounts = append(cur.accounts, len(cur.keys))
		}
		if acctRows != nil {
			slim = appendAccountRLP(slim[:0], &enc, &acct, types.EmptyRootHash, true)
			if err := acctRows.add(akey, slim); err != nil {
				return err
			}
		}
		// Accounts reach the account trie only after their storage job is
		// out, so it never waits on roots no worker has.
		pending = append(pending, acct)
		if len(pending) == cap(pending) || len(cur.keys) >= foldBatchSize {
			if len(cur.accounts) > 0 {
				if err := send(true); err != nil {
					return err
				}
			}
			if err := sendAccounts(); err != nil {
				return err
			}
		}
		walked.Add(1)
		walkedAccs++
		if walkedAccs%uint64(foldBatchSize) == 0 {
			if err := y.pause(ctx); err != nil {
				return err
			}
		}
	}
	if skey, _, err := slotHeld.current(); err != nil {
		return err
	} else if skey != nil {
		return fmt.Errorf("storage under account hash %x, which holds no account", skey[:common.HashLength])
	}
	if len(cur.accounts) > 0 {
		if err := send(true); err != nil {
			return err
		}
	}
	if len(pending) > 0 {
		if err := sendAccounts(); err != nil {
			return err
		}
	}
	prog.stop()
	if flat == nil {
		return nil
	}
	if err := flat.storage.commit(); err != nil {
		return err
	}
	var rows atomic.Uint64
	prog = startProgress("Writing flat accounts", "accounts", walkedAccs, rows.Load)
	defer prog.stop()
	err := acctRows.replay(bufio.NewReaderSize(nil, 256<<10), func(hash, row []byte) error {
		rowKey = append(append(rowKey[:0], rawdb.SnapshotAccountPrefix...), hash...)
		if err := flat.accounts.put(rowKey, row); err != nil {
			return err
		}
		if rows.Add(1)%uint64(foldBatchSize) == 0 {
			return y.pause(ctx)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := flat.accounts.commit(); err != nil {
		return err
	}
	prog.finish("Wrote flat accounts", "accounts", rows.Load())
	return nil
}

// foldStorage hashes the storage tries of the accounts it is sent and
// reports the roots of each job's accounts, in their order.
func foldStorage(ctx context.Context, in <-chan *foldBatch, out chan<- []common.Hash, free chan<- *foldBatch, y *blockYield) error {
	var (
		st    = trie.NewStackTrie(nil)
		found []common.Hash
	)
	for b := range in {
		if err := y.pause(ctx); err != nil {
			return err
		}
		var next, val int
		update := func(to int) error {
			for ; next < to; next++ {
				if err := st.Update(b.keys[next][:], b.vals[val:b.ends[next]]); err != nil {
					return err
				}
				val = b.ends[next]
			}
			return nil
		}
		for _, end := range b.accounts {
			if err := update(end); err != nil {
				return err
			}
			found = append(found, st.Hash())
			st.Reset()
		}
		if err := update(len(b.keys)); err != nil {
			return err
		}
		done := b.done
		free <- b
		if done {
			select {
			case out <- found:
			case <-ctx.Done():
				return ctx.Err()
			}
			found = nil
		}
	}
	return nil
}

// foldAccounts builds the account trie from the accounts in order, taking
// each one's storage root from the workers' jobs, in the order they were
// handed out.
func foldAccounts(ctx context.Context, in <-chan []foldAccount, free chan<- []foldAccount, roots []chan []common.Hash, y *blockYield) (common.Hash, error) {
	var (
		tr   = trie.NewStackTrie(nil)
		have []common.Hash
		job  int
		enc  = rlp.NewEncoderBuffer(nil)
		full []byte
	)
	for accounts := range in {
		if err := y.pause(ctx); err != nil {
			return common.Hash{}, err
		}
		for i := range accounts {
			acct := &accounts[i]
			root := types.EmptyRootHash
			if acct.storage {
				for len(have) == 0 {
					select {
					case have = <-roots[job%len(roots)]:
						job++
					case <-ctx.Done():
						return common.Hash{}, ctx.Err()
					}
				}
				root, have = have[0], have[1:]
			}
			full = appendAccountRLP(full[:0], &enc, acct, root, false)
			if err := tr.Update(acct.hash[:], full); err != nil {
				return common.Hash{}, err
			}
		}
		free <- accounts
	}
	return tr.Hash(), nil
}

// recordBatch packs records back to back: ends holds each record's key end,
// then its value end.
type recordBatch struct {
	buf  []byte
	ends []int
}

// add copies one record into the batch.
func (b *recordBatch) add(key, value []byte) {
	b.buf = append(b.buf, key...)
	b.ends = append(b.ends, len(b.buf))
	b.buf = append(b.buf, value...)
	b.ends = append(b.ends, len(b.buf))
}

func (b *recordBatch) len() int { return len(b.ends) / 2 }

func (b *recordBatch) key(i int) []byte {
	start := 0
	if i > 0 {
		start = b.ends[2*i-1]
	}
	return b.buf[start:b.ends[2*i]]
}

func (b *recordBatch) value(i int) []byte { return b.buf[b.ends[2*i]:b.ends[2*i+1]] }

func (b *recordBatch) reset() { b.buf, b.ends = b.buf[:0], b.ends[:0] }

// full reports whether the batch is ready to hand over: it carries
// recordBatchSize records, or recordBatchBytes, whichever comes first.
func (b *recordBatch) full() bool {
	return len(b.ends) == 2*recordBatchSize || len(b.buf) >= recordBatchBytes
}

const (
	recordBatchSize  = 4096
	recordBatchBytes = 256 << 10
)

// writeStagedNodes writes the staged tree nodes into the namespace in key
// order through w, and commits them.
func writeStagedNodes(ctx context.Context, w familyWriter, nodes *nodeStager, y *blockYield) error {
	var (
		staged  uint64
		flushed atomic.Uint64
		prog    = startProgress("Writing tree nodes", "nodes", nodes.count, flushed.Load)
		key     []byte // the node's, reused: the writer copies it
		size    int    // bytes put since the last pause
	)
	defer prog.stop()
	err := nodes.replay(func(path, blob []byte) error {
		key = append(append(key[:0], rawdb.TrieNodeAccountPrefix...), path...)
		if err := w.put(key, blob); err != nil {
			return err
		}
		staged++
		if size += len(key) + len(blob); size < ethdb.IdealBatchSize {
			return nil
		}
		size = 0
		flushed.Store(staged)
		return y.pause(ctx)
	})
	if err != nil {
		return err
	}
	if err := w.commit(); err != nil {
		return err
	}
	prog.finish("Wrote tree nodes", "nodes", staged)
	return nil
}
