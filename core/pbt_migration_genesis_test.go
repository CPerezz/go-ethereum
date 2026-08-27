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

package core

import "testing"

// TestMigrationGenesisCommitsMerklePatricia pins the discovery that motivated
// migration mode: scheduling the tree in the FUTURE used to flip block zero to
// a binary commitment anyway, because genesis construction asked "is the fork
// scheduled" instead of "has this genesis reached it". The three schedules
// must split exactly two ways: nil and future commit the merkle-patricia
// genesis (byte-identical blocks), at-genesis stays the pinned binary block
// from pbt_genesis_mode_test.go.
func TestMigrationGenesisCommitsMerklePatricia(t *testing.T) {
	base, _, _, _ := pbtChainGenesis(t)

	variant := func(tree *uint64) *Genesis {
		g := *base
		cfg := *base.Config
		cfg.BinaryTrieTime = tree
		g.Config = &cfg
		return &g
	}
	var (
		hashNil    = variant(nil).ToBlock().Hash()
		hashFuture = variant(u64(base.Timestamp + 1800)).ToBlock().Hash()
		hashAt     = variant(u64(base.Timestamp)).ToBlock().Hash()
	)
	if hashFuture != hashNil {
		t.Fatalf("a future schedule commits %s, the merkle-patricia genesis is %s — migration mode must start on the merkle trie", hashFuture, hashNil)
	}
	if hashFuture == hashAt {
		t.Fatal("a future schedule still commits the binary-tree genesis")
	}
	if hashAt != pinnedPBTGenesisHash {
		t.Fatalf("the at-genesis arm drifted from its pin: %s != %s", hashAt, pinnedPBTGenesisHash)
	}

	// Genesis.IsPBT answers block zero's commitment, never the schedule; the
	// schedule question stays with ChainConfig.IsPBT.
	if variant(u64(base.Timestamp + 1800)).IsPBT() {
		t.Fatal("a future schedule claims a binary-tree genesis")
	}
	if !variant(u64(base.Timestamp)).IsPBT() {
		t.Fatal("an at-genesis schedule denies its binary-tree genesis")
	}
	if !variant(u64(base.Timestamp + 1800)).Config.IsPBT() {
		t.Fatal("a future schedule stopped counting as scheduled at all")
	}
}
