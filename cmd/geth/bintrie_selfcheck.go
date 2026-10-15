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
	"context"
	"fmt"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/holiman/uint256"
)

// A self-converter owes EIP-8347's dual-check on the leaves it derives: they
// must re-derive the merkle root it converted, and code must reassemble from
// its chunks. Its scan walks the merkle state in that root's own order, so
// the scan folds the merkle state as it emits the leaves, from the values
// those leaves decode back to, and writes the flat state on the way. What
// stands between the emitted leaves and the tree is the sort, which a
// multiset sum covers: the tree must be built from exactly the leaves the
// scan emitted, none lost, added or changed. Code is reassembled from its
// chunks where the scan chunks it (emitAccountHeader).

// leafSum is a multiset hash of tree leaves: the sum, modulo 2^256, of the
// tree's key hash of each leaf's key and value, and the leaf count. Sums of
// the same leaves agree in any order.
type leafSum struct {
	sum uint256.Int
	n   uint64
}

func (s *leafSum) add(key, value []byte) {
	var buf [bintrie.StorageKeyLength + 32]byte
	h := bintrie.KeyHash(append(append(buf[:0], key...), value...))
	var x uint256.Int
	x.SetBytes32(h[:])
	s.sum.Add(&s.sum, &x)
	s.n++
}

func (s *leafSum) merge(o *leafSum) {
	s.sum.Add(&s.sum, &o.sum)
	s.n += o.n
}

// selfCheck is one scan worker's share of the dual-check: it sums the leaves
// the worker emits, folds each account's storage trie, spills the accounts
// for the account trie, and writes the flat state of the worker's range.
type selfCheck struct {
	sum                       leafSum
	storage                   *trie.StackTrie
	accounts                  *spillFile // keccak(address) -> full account RLP, in key order
	flat                      nsWriter
	flatAccounts, flatStorage *digestAhead

	// The account under the scan: its header leaves as emitted, and whether
	// its storage trie holds anything.
	basic, kind [32]byte
	delegated   bool
	slots       bool
	key         []byte
}

// newSelfCheck checks the i-th of plan's ranges, writing its flat state into
// db's namespace and its digests into written.
func newSelfCheck(db ethdb.Database, tmpDir string, written *writtenState, i int) (*selfCheck, error) {
	accounts, err := newSpillFile(tmpDir, "bintrie-accounts-*")
	if err != nil {
		return nil, err
	}
	flat, err := newNamespaceWriter(db, tmpDir)
	if err != nil {
		accounts.close()
		return nil, err
	}
	return &selfCheck{
		storage:      trie.NewStackTrie(nil),
		accounts:     accounts,
		flat:         flat,
		flatAccounts: written.accounts.ranges[i].d.ahead(),
		flatStorage:  written.storage.ranges[i].d.ahead(),
	}, nil
}

// leaf notes a leaf the scan emits, keeping the account header's.
func (c *selfCheck) leaf(key []byte, value [32]byte) {
	c.sum.add(key, value[:])
	if key[0] != bintrie.AccountZone {
		return
	}
	switch key[len(key)-1] {
	case bintrie.BasicDataLeafKey:
		c.basic = value
	case bintrie.CodeHashLeafKey:
		c.kind, c.delegated = value, false
	case bintrie.DelegationLeafKey:
		c.kind, c.delegated = value, true
	}
}

// slot folds a storage slot of the account under the scan, as its leaf holds
// it, and writes its flat-state row.
func (c *selfCheck) slot(accountHash, slotHash common.Hash, value [32]byte) error {
	enc, err := rlp.EncodeToBytes(common.TrimLeftZeroes(value[:]))
	if err != nil {
		return err
	}
	if err := c.storage.Update(slotHash[:], enc); err != nil {
		return err
	}
	c.slots = true
	c.key = append(append(c.key[:0], accountHash[:]...), slotHash[:]...)
	c.flatStorage.add(c.key, enc)
	if err := c.flat.put(rawdb.SnapshotStoragePrefix, accountHash[:], slotHash[:], enc); err != nil {
		return err
	}
	return c.flat.flush()
}

// account seals the account under the scan, from its header leaves as they
// decode, and readies the check for the next.
func (c *selfCheck) account(accountHash common.Hash) error {
	_, _, nonce, balance := bintrie.DecodeBasicData(c.basic[:])
	codeHash := common.Hash(c.kind)
	if c.delegated {
		// The leaf derives from a 20-byte target: its designator is always
		// the 23-byte EIP-7702 indicator.
		codeHash = crypto.Keccak256Hash(c.kind[:23])
	}
	root := types.EmptyRootHash
	if c.slots {
		root = c.storage.Hash()
		c.storage.Reset()
	}
	full, err := rlp.EncodeToBytes(&types.StateAccount{Nonce: nonce, Balance: balance, Root: root, CodeHash: codeHash[:]})
	if err != nil {
		return err
	}
	if err := c.accounts.add(accountHash[:], full); err != nil {
		return err
	}
	slim := types.SlimAccountRLP(types.StateAccount{Nonce: nonce, Balance: balance, Root: types.EmptyRootHash, CodeHash: codeHash[:]})
	c.flatAccounts.add(accountHash[:], slim)
	if err := c.flat.put(rawdb.SnapshotAccountPrefix, accountHash[:], nil, slim); err != nil {
		return err
	}
	c.basic, c.kind, c.delegated, c.slots = [32]byte{}, [32]byte{}, false, false
	return c.flat.flush()
}

// finish writes out the worker's flat state and completes its digests.
func (c *selfCheck) finish() error {
	err := c.flatAccounts.finish()
	if serr := c.flatStorage.finish(); err == nil {
		err = serr
	}
	if ferr := c.flat.close(); err == nil {
		err = ferr
	}
	return err
}

// close releases the check, finished or not.
func (c *selfCheck) close() {
	c.finish()
	c.accounts.close()
}

// foldSpilledAccounts builds the account trie from every check's accounts,
// in order: the checks' ranges ascend, and each spilled its own in order.
func foldSpilledAccounts(ctx context.Context, checks []*selfCheck, total uint64) (common.Hash, error) {
	var (
		tr     = trie.NewStackTrie(nil)
		r      = bufio.NewReaderSize(nil, 1<<20)
		folded atomic.Uint64
	)
	prog := startProgress("Re-deriving the merkle account trie", "accounts", total, folded.Load)
	defer prog.stop()
	for _, c := range checks {
		err := c.accounts.replay(r, func(hash, full []byte) error {
			if folded.Add(1)%recordBatchSize == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			return tr.Update(hash, full)
		})
		if err != nil {
			return common.Hash{}, err
		}
	}
	root := tr.Hash()
	prog.finish("Re-derived the merkle account trie", "accounts", folded.Load(), "root", root)
	return root, nil
}

// buildOwnTree builds the tree from a self-converter's sorted leaves, staging
// its nodes, and requires the leaves to be exactly those its scan emitted.
// It writes the nodes into db's namespace once built, and returns the root
// and the nodes' digest.
func buildOwnTree(ctx context.Context, db ethdb.Database, leaves leafReader, emitted *leafSum, opts conversionOptions) (common.Hash, *familyDigest, error) {
	nodes, err := newNodeStager(opts.tmpDir)
	if err != nil {
		return common.Hash{}, nil, err
	}
	defer nodes.close()
	builder := bintrie.NewParallelStackBuilder(func(path []byte, _ common.Hash, blob []byte) { nodes.add(path, blob) }, opts.workers)
	defer builder.Stop()

	var (
		built leafSum
		count atomic.Uint64
	)
	prog := startProgress("Building the binary tree", "leaves", emitted.n, count.Load)
	defer prog.stop()
	pipe := startLeafPipeline(leaves, builder)
	defer pipe.stop()
	for b := range pipe.leaves {
		if err := ctx.Err(); err != nil {
			return common.Hash{}, nil, err
		}
		for i := range b.values {
			built.add(b.key(i), b.values[i][:])
		}
		count.Add(uint64(len(b.values)))
		pipe.release(b)
	}
	if err := pipe.wait(); err != nil {
		return common.Hash{}, nil, err
	}
	root := builder.Finish()
	if built != *emitted {
		return common.Hash{}, nil, fmt.Errorf("the tree is built from other leaves than the scan derived: %d built, %d derived", built.n, emitted.n)
	}
	prog.finish("Built the binary tree", "root", root, "leaves", built.n)
	digest, err := writeStagedNodes(ctx, db, opts.tmpDir, nodes, opts.workers)
	if err != nil {
		return common.Hash{}, nil, err
	}
	return root, digest, nil
}

// streamLeaves hands the leaf pipeline a sorted leaf stream.
type streamLeaves struct{ *bintrie.RecordStream }

func (s streamLeaves) next() ([]byte, [32]byte, error) {
	key, value, err := s.Next()
	if err != nil {
		return nil, [32]byte{}, err
	}
	return key, [32]byte(value), nil
}
