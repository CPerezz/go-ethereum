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

package state

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

var (
	eip8188Addr = common.HexToAddress("0xabcd")
	eip8188Slot = common.HexToHash("0x01")
	eip8188Val  = common.HexToHash("0x42")
)

// commit8188 writes a balance, nonce and one storage slot to a fresh account and
// commits at the given block, optionally with EIP-8188 tagging enabled.
func commit8188(t *testing.T, enabled bool, block uint64) (common.Hash, *CachingDB) {
	t.Helper()
	db := NewDatabaseForTesting()
	st, err := New(types.EmptyRootHash, db)
	if err != nil {
		t.Fatal(err)
	}
	st.SetBlockContext(block, enabled)
	st.SetBalance(eip8188Addr, uint256.NewInt(1000), tracing.BalanceChangeUnspecified)
	st.SetNonce(eip8188Addr, 3, tracing.NonceChangeUnspecified)
	st.SetState(eip8188Addr, eip8188Slot, eip8188Val)
	root, err := st.Commit(block, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.TrieDB().Commit(root, false); err != nil {
		t.Fatal(err)
	}
	return root, db
}

func readAccountLeaf(t *testing.T, db *CachingDB, root common.Hash) types.StateAccount {
	t.Helper()
	tr, err := trie.New(trie.StateTrieID(root), db.TrieDB())
	if err != nil {
		t.Fatal(err)
	}
	blob, err := tr.Get(crypto.Keccak256(eip8188Addr.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var acc types.StateAccount
	if err := rlp.DecodeBytes(blob, &acc); err != nil {
		t.Fatal(err)
	}
	return acc
}

func readSlotLeaf(t *testing.T, db *CachingDB, root common.Hash) (common.Hash, uint64) {
	t.Helper()
	acc := readAccountLeaf(t, db, root)
	tr, err := trie.New(trie.StorageTrieID(root, crypto.Keccak256Hash(eip8188Addr.Bytes()), acc.Root), db.TrieDB())
	if err != nil {
		t.Fatal(err)
	}
	blob, err := tr.Get(crypto.Keccak256(eip8188Slot.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	value, lwb, err := types.DecodeStorageSlot(blob)
	if err != nil {
		t.Fatal(err)
	}
	return common.BytesToHash(value), lwb
}

// Fork-off must reproduce the legacy (untagged) root; fork-on must stamp the
// account and slot leaves with the commit block, changing the root.
func TestEIP8188WritePathTagging(t *testing.T) {
	const block = uint64(24402727)

	rootOff, dbOff := commit8188(t, false, block)
	rootOn, dbOn := commit8188(t, true, block)

	if rootOff == rootOn {
		t.Fatal("EIP-8188 tagging must change the state root")
	}
	// Fork-off: both leaves untagged.
	if acc := readAccountLeaf(t, dbOff, rootOff); acc.LastWritten != 0 {
		t.Fatalf("fork-off account must be untagged, got lwb=%d", acc.LastWritten)
	}
	if _, lwb := readSlotLeaf(t, dbOff, rootOff); lwb != 0 {
		t.Fatalf("fork-off slot must be untagged, got lwb=%d", lwb)
	}
	// Fork-on: account + slot tagged with the commit block.
	if acc := readAccountLeaf(t, dbOn, rootOn); acc.LastWritten != uint32(block) {
		t.Fatalf("fork-on account lwb: got %d want %d", acc.LastWritten, block)
	}
	if v, lwb := readSlotLeaf(t, dbOn, rootOn); lwb != block || v != eip8188Val {
		t.Fatalf("fork-on slot: value=%x lwb=%d want value=%x lwb=%d", v, lwb, eip8188Val, block)
	}
}

// When a slot written at block P is overwritten at block N, the pathdb origin
// (reverse-diff) leaf must carry the prior last_written_block P so a rollback
// restores byte-exact leaves.
func TestEIP8188OriginCarriesPriorLwb(t *testing.T) {
	const blockP, blockN = uint64(100), uint64(200)
	db := NewDatabaseForTesting()

	// Block P: create the account and write slot = 0x11.
	st1, err := New(types.EmptyRootHash, db)
	if err != nil {
		t.Fatal(err)
	}
	st1.SetBlockContext(blockP, true)
	st1.SetBalance(eip8188Addr, uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	st1.SetState(eip8188Addr, eip8188Slot, common.HexToHash("0x11"))
	root1, err := st1.Commit(blockP, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.TrieDB().Commit(root1, false); err != nil {
		t.Fatal(err)
	}

	// Block N: overwrite slot = 0x22; capture the resulting state update.
	st2, err := New(root1, db)
	if err != nil {
		t.Fatal(err)
	}
	st2.SetBlockContext(blockN, true)
	st2.SetState(eip8188Addr, eip8188Slot, common.HexToHash("0x22"))
	_, update, err := st2.CommitWithUpdate(blockN, false, false)
	if err != nil {
		t.Fatal(err)
	}

	originBlob := update.storagesOrigin[eip8188Addr][crypto.Keccak256Hash(eip8188Slot.Bytes())]
	val, lwb, err := types.DecodeStorageSlot(originBlob)
	if err != nil {
		t.Fatal(err)
	}
	if common.BytesToHash(val) != common.HexToHash("0x11") {
		t.Fatalf("origin value: got %x want 0x11", val)
	}
	if lwb != blockP {
		t.Fatalf("origin lwb: got %d want %d", lwb, blockP)
	}
}
