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

package stateless

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/ethereum/go-ethereum/triedb"
)

// proofFixture builds a small binary tree in memory, proves one whole stem out
// of it, and returns the root, the encoded proof and a key the proof covers.
//
// No database backs the tree: writes materialise every node, so the prover never
// resolves anything.
func proofFixture(t *testing.T) (common.Hash, []byte, []byte) {
	t.Helper()

	tr, err := bintrie.NewBinaryTrie(types.EmptyBinaryHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	value := bytes.Repeat([]byte{0xaa}, 32)
	for i := 1; i <= 8; i++ {
		stem := bintrie.HeaderStem(common.Address{byte(i)})
		if err := tr.UpdateStem(stem, []byte{0, 1}, [][]byte{value, value}); err != nil {
			t.Fatal(err)
		}
	}
	var (
		root = tr.Hash()
		stem = bintrie.HeaderStem(common.Address{1})
		key  = append(bytes.Clone(stem), 0)
	)
	mp, err := tr.ProveRequests(bintrie.ProofRequests{Stems: [][]byte{stem}})
	if err != nil {
		t.Fatal(err)
	}
	return root, mp.Encode(), key
}

// witnessFor returns a witness whose root is the given one, which is what
// MakePathDB checks a proof against.
func witnessFor(root common.Hash) *Witness {
	header := testHeader(1)
	header.Root = root
	return &Witness{Headers: []*types.Header{header}}
}

// TestMakePathDBServesAProof pins the consume path end to end: a proof verified
// and written out as records answers what it covered, through the same database
// stack a stateless block runs on.
func TestMakePathDBServesAProof(t *testing.T) {
	root, proof, key := proofFixture(t)

	w := witnessFor(root)
	w.AddProof(proof)
	memdb, err := w.MakePathDB()
	if err != nil {
		t.Fatalf("building the database: %v", err)
	}
	db := triedb.NewDatabase(memdb, triedb.PBTWitnessDefaults)
	defer db.Close()

	tr, err := bintrie.NewBinaryTrie(root, db)
	if err != nil {
		t.Fatalf("opening the rebuilt tree: %v", err)
	}
	if got := tr.Hash(); got != root {
		t.Fatalf("the rebuilt tree roots at %x, want %x", got, root)
	}
	got, err := tr.GetStemValue(key)
	if err != nil {
		t.Fatalf("reading a proved key: %v", err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0xaa}, 32)) {
		t.Fatalf("proved key reads back as %x", got)
	}
	// A stem the proof did not carry has to fault, not read as absent: answering
	// zero would let the replay root state that was never there.
	if _, err := tr.GetStemValue(append(bintrie.HeaderStem(common.Address{9}), 0)); err == nil {
		t.Fatal("an unproved stem read back without error")
	}
}

// TestMakePathDBRefusesBadWitnesses pins that a witness which cannot describe
// its own root is refused before execution.
//
// This is the only place that check can live. pathdb skips the node-hash
// comparison for this tree, so nothing downstream re-validates a record: without
// a refusal here every one of these surfaces as a root that cannot match, and
// the producer looks at fault instead of its own witness.
func TestMakePathDBRefusesBadWitnesses(t *testing.T) {
	root, proof, _ := proofFixture(t)

	for _, tc := range []struct {
		name    string
		witness func() *Witness
	}{
		{"no state at all", func() *Witness {
			return witnessFor(root)
		}},
		{"a truncated proof", func() *Witness {
			w := witnessFor(root)
			w.AddProof(proof[:len(proof)/2])
			return w
		}},
		{"a proof for another root", func() *Witness {
			w := witnessFor(common.Hash{0xbb})
			w.AddProof(proof)
			return w
		}},
		{"a proof over the empty root", func() *Witness {
			w := witnessFor(types.EmptyBinaryHash)
			w.AddProof(proof)
			return w
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.witness().MakePathDB(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// TestMakePathDBAcceptsAnEmptyPreState pins the one witness that legitimately
// carries no state. Both sentinels denote a fresh tree, which the reader answers
// without asking the database.
func TestMakePathDBAcceptsAnEmptyPreState(t *testing.T) {
	for _, root := range []common.Hash{types.EmptyBinaryHash, types.EmptyRootHash} {
		if _, err := witnessFor(root).MakePathDB(); err != nil {
			t.Fatalf("root %x: %v", root, err)
		}
	}
}
