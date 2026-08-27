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

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
)

// The pbtGenesis-mode pins. The migration work (EIP-8347) teaches the node to
// treat a binaryTrieTime AFTER the genesis timestamp as "merkle-patricia now,
// binary tree later"; a binaryTrieTime AT the genesis timestamp must keep
// meaning what it means today — the tree commits the state from block zero.
//
// These constants hold that behavior still. They were computed by running
// this very test on the branch BEFORE the migration change, so any drift in
// genesis construction or database selection for the at-genesis schedule
// fails here first, loudly, instead of surfacing as a devnet whose clients
// disagree about block zero.
var (
	pinnedPBTGenesisHash = common.HexToHash("0x8ad6f3ae34ddccca3178397d05397aacbebf66bbb6cace92e248eca298c81f45")
	pinnedPBTGenesisRoot = common.HexToHash("0x6e434dbab050bc1c92cba65e0c3afbad2cd96345e5d1612ace1b79a5bd01bbe9")
)

// TestPBTGenesisModePins pins the at-genesis schedule's genesis block: with
// binaryTrieTime equal to the genesis timestamp, ToBlock commits the alloc
// with the binary tree, and the resulting hash and root must never move.
func TestPBTGenesisModePins(t *testing.T) {
	genesis, _, _, _ := pbtChainGenesis(t)
	block := genesis.ToBlock()
	if got := block.Hash(); got != pinnedPBTGenesisHash {
		t.Errorf("pbtGenesis genesis hash drifted: got %s, pinned %s", got, pinnedPBTGenesisHash)
	}
	if got := block.Root(); got != pinnedPBTGenesisRoot {
		t.Errorf("pbtGenesis genesis root drifted: got %s, pinned %s", got, pinnedPBTGenesisRoot)
	}
}

// TestPBTGenesisModeSelectsBinaryTree pins database selection for the
// at-genesis schedule: a chain whose config schedules the tree at the genesis
// timestamp opens on the binary tree from block zero. The migration change
// must route only FUTURE schedules elsewhere.
func TestPBTGenesisModeSelectsBinaryTree(t *testing.T) {
	genesis, _, _, _ := pbtChainGenesis(t)
	engine := beacon.New(ethash.NewFaker())
	db, _, _ := GenerateChainWithGenesis(genesis, engine, 0, nil)

	chain, err := NewBlockChain(db, genesis, engine, DefaultConfig().WithStateScheme(rawdb.PathScheme))
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()

	if !chain.TrieDB().IsPBT() {
		t.Fatal("an at-genesis binary tree schedule did not open on the binary tree")
	}
	head := chain.CurrentBlock()
	if head.Number.Uint64() != 0 || head.Root != pinnedPBTGenesisRoot {
		t.Fatalf("head is block %d root %s, want block 0 root %s", head.Number, head.Root, pinnedPBTGenesisRoot)
	}
}
