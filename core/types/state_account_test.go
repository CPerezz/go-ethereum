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

package types

import (
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

func sample8188Account(lwb uint32) *StateAccount {
	return &StateAccount{
		Nonce:       7,
		Balance:     uint256.NewInt(1000),
		Root:        EmptyRootHash,
		CodeHash:    EmptyCodeHash[:],
		LastWritten: lwb,
	}
}

func countListElems(t *testing.T, enc []byte) int {
	t.Helper()
	_, content, _, err := rlp.Split(enc)
	if err != nil {
		t.Fatal(err)
	}
	n, err := rlp.CountValues(content)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// With LastWritten==0 the account must encode as the legacy 4-element list, so
// pre-fork state roots are unchanged.
func TestStateAccountLegacyEncodingUnchanged(t *testing.T) {
	enc, err := rlp.EncodeToBytes(sample8188Account(0))
	if err != nil {
		t.Fatal(err)
	}
	if n := countListElems(t, enc); n != 4 {
		t.Fatalf("lwb==0 must encode as 4 elements, got %d", n)
	}
}

// With LastWritten>0 the account encodes as a 5-element list and round-trips.
func TestStateAccountTaggedRoundtrip(t *testing.T) {
	const block = uint32(24402727)
	enc, err := rlp.EncodeToBytes(sample8188Account(block))
	if err != nil {
		t.Fatal(err)
	}
	if n := countListElems(t, enc); n != 5 {
		t.Fatalf("lwb>0 must encode as 5 elements, got %d", n)
	}
	var got StateAccount
	if err := rlp.DecodeBytes(enc, &got); err != nil {
		t.Fatal(err)
	}
	if got.LastWritten != block {
		t.Fatalf("LastWritten mismatch: got %d want %d", got.LastWritten, block)
	}
}

// A legacy 4-element account must decode with LastWritten==0 (tolerant decode).
func TestStateAccountDecodeLegacy(t *testing.T) {
	legacy, err := rlp.EncodeToBytes([]any{uint64(7), uint256.NewInt(1000), EmptyRootHash, EmptyCodeHash[:]})
	if err != nil {
		t.Fatal(err)
	}
	var got StateAccount
	if err := rlp.DecodeBytes(legacy, &got); err != nil {
		t.Fatalf("legacy 4-element decode failed: %v", err)
	}
	if got.LastWritten != 0 {
		t.Fatalf("legacy account LastWritten must be 0, got %d", got.LastWritten)
	}
	if got.Nonce != 7 {
		t.Fatalf("nonce mismatch after legacy decode: %d", got.Nonce)
	}
}

// SlimAccount carries the tag too: tagged round-trips, untagged stays 4 elements.
func TestSlimAccountTaggedRoundtrip(t *testing.T) {
	const block = uint32(123456)
	enc, err := rlp.EncodeToBytes(&SlimAccount{Nonce: 3, Balance: uint256.NewInt(5), LastWritten: block})
	if err != nil {
		t.Fatal(err)
	}
	var got SlimAccount
	if err := rlp.DecodeBytes(enc, &got); err != nil {
		t.Fatal(err)
	}
	if got.LastWritten != block {
		t.Fatalf("slim LastWritten mismatch: got %d want %d", got.LastWritten, block)
	}
	enc0, err := rlp.EncodeToBytes(&SlimAccount{Nonce: 3, Balance: uint256.NewInt(5)})
	if err != nil {
		t.Fatal(err)
	}
	if n := countListElems(t, enc0); n != 4 {
		t.Fatalf("untagged slim must encode as 4 elements, got %d", n)
	}
}

// The slim<->full conversion (used by the snapshot/pathdb path) must preserve the tag.
func TestSlimFullAccountConversionCarriesTag(t *testing.T) {
	const block = uint32(99999)
	slimRLP := SlimAccountRLP(*sample8188Account(block))
	full, err := FullAccount(slimRLP)
	if err != nil {
		t.Fatal(err)
	}
	if full.LastWritten != block {
		t.Fatalf("slim<->full conversion dropped the tag: got %d want %d", full.LastWritten, block)
	}
}
