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
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/holiman/uint256"
)

// A proof narrowed to what a block covered is only correct if every class of
// request is the right width. Too narrow and a replay faults on a valid block;
// too wide and the size win goes away. These cases drop one request at a time
// and name the operation that must then fail, which is what pins the class
// rather than the coverage that happened to work.
//
// A blanket "drop any request and replay fails" sweep would be unsound: some
// requests are redundant by construction, since the prover drops a target whose
// bits fall at or above a split, so a path another target descends through
// contributes nothing to the bytes.

// proofState seeds a tree with several accounts, one of which owns overflow
// storage, and returns a state opened on the committed root.
func proofState(t *testing.T) (*StateDB, common.Address, common.Hash) {
	t.Helper()

	sdb, db := newPBTState(t)
	var owner common.Address
	for i := 1; i <= 8; i++ {
		addr := common.Address{byte(i)}
		sdb.SetNonce(addr, uint64(i), tracing.NonceChangeUnspecified)
		sdb.SetBalance(addr, uint256.NewInt(uint64(i)*1000), tracing.BalanceChangeUnspecified)
		if i == 1 {
			owner = addr
		}
	}
	// Above HeaderStorageOffset, so these live in the overflow bucket rather than
	// in the account's header stem: a slot the account read does not cover.
	slot := common.BigToHash(uint256.NewInt(4096).ToBig())
	sdb.SetState(owner, slot, common.Hash{0xaa})
	sdb.SetState(owner, common.BigToHash(uint256.NewInt(8192).ToBig()), common.Hash{0xbb})

	return reopenPBT(t, sdb, db, 1), owner, slot
}

// proveReduced proves the pre-state over req and rebuilds a trie from the
// result, which is what a stateless verifier does with a witness it received.
func proveReduced(t *testing.T, sdb *StateDB, req bintrie.ProofRequests) *bintrie.BinaryTrie {
	t.Helper()

	tr, err := sdb.db.OpenTrie(sdb.originalRoot)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := tr.(*bintrie.BinaryTrie).ProveRequests(req)
	if err != nil {
		t.Fatalf("proving the reduced set: %v", err)
	}
	// Through the wire form, so the decoder's canonical check runs: verifying a
	// proof straight out of the prover skips it.
	decoded, err := bintrie.DecodeMultiproof(mp.Encode())
	if err != nil {
		t.Fatalf("the prover emitted a proof its own decoder refuses: %v", err)
	}
	verified, err := bintrie.VerifyMultiproof(sdb.originalRoot, decoded)
	if err != nil {
		t.Fatalf("verifying the reduced proof: %v", err)
	}
	return verified
}

// TestProofRequestClassesAreLoadBearing drops one request of each class and
// requires the operation that depends on it to fail.
func TestProofRequestClassesAreLoadBearing(t *testing.T) {
	sdb, owner, slot := proofState(t)
	var (
		headerStem = bintrie.HeaderStem(owner)
		slotKey    = bintrie.StorageSlotKey(owner, slot.Bytes())
		full       = bintrie.ProofRequests{
			Stems: [][]byte{headerStem},
			Keys:  [][]byte{slotKey},
		}
	)
	// The control: with both requests the reads answer.
	tr := proveReduced(t, sdb, full)
	if _, err := tr.GetAccount(owner); err != nil {
		t.Fatalf("the account read failed on the full set: %v", err)
	}
	if _, err := tr.GetStemValue(slotKey); err != nil {
		t.Fatalf("the slot read failed on the full set: %v", err)
	}

	t.Run("without the slot key", func(t *testing.T) {
		// Nothing else reaches that stem, so its group ships as a single hash and
		// the walk faults rather than reading the slot as absent.
		tr := proveReduced(t, sdb, bintrie.ProofRequests{Stems: [][]byte{headerStem}})
		if _, err := tr.GetStemValue(slotKey); err == nil {
			t.Fatal("an unproved slot read back without error")
		}
	})

	t.Run("without the header stem", func(t *testing.T) {
		// A key into the header stem instead of the whole stem. The group arrives
		// partially covered, which is exactly what an account read cannot use: it
		// needs the group whole to fold it.
		tr := proveReduced(t, sdb, bintrie.ProofRequests{
			Keys: [][]byte{bintrie.BasicDataKey(owner), slotKey},
		})
		if _, err := tr.GetStemValue(bintrie.BasicDataKey(owner)); err != nil {
			t.Fatalf("the covered key should still read: %v", err)
		}
		if _, err := tr.GetAccount(owner); !errors.Is(err, bintrie.ErrPartialStem) {
			t.Fatalf("account read over a partially covered stem: got %v, want ErrPartialStem", err)
		}
	})

	t.Run("without any request", func(t *testing.T) {
		// A proof over no requests collapses the whole tree to one hash, which then
		// verifies against any root it is offered. The prover will emit it; the
		// decoder is what refuses it, which is why the recorder seeds the root path
		// rather than relying on a block having touched something.
		tr, err := sdb.db.OpenTrie(sdb.originalRoot)
		if err != nil {
			t.Fatal(err)
		}
		mp, err := tr.(*bintrie.BinaryTrie).ProveRequests(bintrie.ProofRequests{})
		if err != nil {
			return // refused at the prover, which is also fine
		}
		// Decoding is a structural parse and accepts the token; verification is what
		// refuses it, and MakePathDB runs both.
		decoded, err := bintrie.DecodeMultiproof(mp.Encode())
		if err != nil {
			return
		}
		if _, err := bintrie.VerifyMultiproof(sdb.originalRoot, decoded); err == nil {
			t.Fatal("a proof covering nothing verified against the root")
		}
	})
}

// TestBuildStateProofRefusals pins the checks that stop a proof being built over
// the wrong cover, each of which would otherwise ship a witness that looks
// well-formed and replays to the wrong root.
func TestBuildStateProofRefusals(t *testing.T) {
	newWitnessed := func(t *testing.T) *StateDB {
		t.Helper()
		sdb, _, _ := proofState(t)
		sdb.witness = &stateless.Witness{Headers: []*types.Header{{Root: sdb.originalRoot}}}
		sdb.proofReqs = bintrie.NewProofRecorder()
		return sdb
	}
	t.Run("a latched read error", func(t *testing.T) {
		sdb := newWitnessed(t)
		sdb.setError(errors.New("a node was missing"))
		if err := sdb.BuildStateProof(); err == nil {
			t.Fatal("a proof was built over a request set a failed read left short")
		}
	})
	t.Run("a witness for another root", func(t *testing.T) {
		sdb := newWitnessed(t)
		sdb.witness.Headers[0].Root = common.Hash{0xbb}
		if err := sdb.BuildStateProof(); err == nil {
			t.Fatal("a proof was built against a root the witness does not claim")
		}
	})
	t.Run("no headers", func(t *testing.T) {
		sdb := newWitnessed(t)
		sdb.witness.Headers = nil
		if err := sdb.BuildStateProof(); err == nil {
			t.Fatal("a proof was built for a witness with no pre-state root")
		}
	})
	t.Run("no recorder", func(t *testing.T) {
		sdb := newWitnessed(t)
		sdb.proofReqs = nil
		if err := sdb.BuildStateProof(); err == nil {
			t.Fatal("a proof was built with nothing recorded")
		}
	})
}
