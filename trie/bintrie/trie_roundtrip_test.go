// Copyright 2026 go-ethereum Authors
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

// Package bintrie_test hosts round-trip integration tests that exercise
// BinaryTrie through pathdb. It lives in an external test package because
// pathdb imports trie/bintrie — the reverse dependency would create an
// import cycle if we co-located this with the bintrie_test file.
package bintrie_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
)

// roundtripKeyN derives a distinct 32-byte key from a seed integer.
func roundtripKeyN(i int) [bintrie.HashSize]byte {
	var k [bintrie.HashSize]byte
	binary.BigEndian.PutUint64(k[:8], uint64(i)*0x9e3779b97f4a7c15)
	binary.BigEndian.PutUint64(k[8:16], uint64(i)*0xc2b2ae3d27d4eb4f)
	binary.BigEndian.PutUint64(k[16:24], uint64(i)*0x165667b19e3779f9)
	binary.BigEndian.PutUint64(k[24:32], uint64(i)*0x85ebca77c2b2ae63)
	return k
}

// TestBinaryTrieRoundTripAcrossCommits exercises the production
// Commit → triedb.Update → triedb.Commit → NewBinaryTrie → read loop
// across five rounds. Every round inserts a new batch of keys, commits,
// reloads from disk, and verifies every key ever inserted is still
// readable. This is the regression guard for the class of bug fixed in
// f57dd2046 — a missed needsFlush=true setter that made CollectNodes
// skip a new stem; the parent InternalNode flushed with a dangling hash,
// and subsequent reads failed with "missing trie node".
func TestBinaryTrieRoundTripAcrossCommits(t *testing.T) {
	chaindb := rawdb.NewMemoryDatabase()
	tdb := triedb.NewDatabase(chaindb, &triedb.Config{
		IsUBT:  true,
		PathDB: pathdb.Defaults,
	})
	defer tdb.Close()

	const rounds = 5
	const keysPerRound = 20
	root := types.EmptyBinaryHash
	inserted := map[[bintrie.HashSize]byte][bintrie.HashSize]byte{}

	for r := 0; r < rounds; r++ {
		tr, err := bintrie.NewBinaryTrie(root, tdb)
		if err != nil {
			t.Fatalf("round %d: NewBinaryTrie: %v", r, err)
		}
		for i := 0; i < keysPerRound; i++ {
			k := roundtripKeyN(r*1000 + i + 1)
			var v [bintrie.HashSize]byte
			binary.BigEndian.PutUint64(v[24:], uint64(r*1000+i+1))

			values := make([][]byte, bintrie.StemNodeWidth)
			values[k[bintrie.StemSize]] = v[:]
			if err := tr.UpdateStem(k[:bintrie.StemSize], values); err != nil {
				t.Fatalf("round %d key %d: UpdateStem: %v", r, i, err)
			}
			inserted[k] = v
		}

		newRoot, nodeSet := tr.Commit(false)
		if nodeSet == nil {
			t.Fatalf("round %d: Commit returned nil NodeSet", r)
		}
		merged := trienode.NewWithNodeSet(nodeSet)
		if err := tdb.Update(newRoot, root, uint64(r+1), merged, triedb.NewStateSet()); err != nil {
			t.Fatalf("round %d: triedb.Update: %v", r, err)
		}
		if err := tdb.Commit(newRoot, false); err != nil {
			t.Fatalf("round %d: triedb.Commit: %v", r, err)
		}
		root = newRoot

		// Reload from disk and verify every key inserted so far.
		verify, err := bintrie.NewBinaryTrie(root, tdb)
		if err != nil {
			t.Fatalf("round %d: reload NewBinaryTrie: %v", r, err)
		}
		for k, want := range inserted {
			addr := common.BytesToAddress(k[12:32])
			// We drove UpdateStem directly with arbitrary 31-byte stems,
			// so we can't round-trip through GetAccount/GetStorage (those
			// expect EIP-7864-derived stems). Use the low-level tree
			// traversal via the unexported getter — but since this is an
			// external test package, we go through a stem-level read by
			// re-deriving the stem and calling GetWithHashedKey.
			_ = addr
			got, err := verify.GetWithHashedKey(k[:])
			if err != nil {
				t.Fatalf("round %d: GetWithHashedKey(%x): %v", r, k, err)
			}
			if !bytes.Equal(got, want[:]) {
				t.Fatalf("round %d: key %x value mismatch: got %x, want %x", r, k, got, want[:])
			}
		}
	}
}
