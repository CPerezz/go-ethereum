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

package bintrie_test

// Measures what it costs to witness a contract's code under the binary tree,
// against the claim in execution-specs #3286 that it runs ~4.35x the merkle
// cost, converging on (67 + 68) / 31 bytes per 31 bytes of code.
//
// The claim is conditioned on "a witness carrying every chunk of a contract
// whose code is read", each chunk paying for its own leaf and branch path. This
// measures two formats this tree actually has, because they answer differently:
//
//   - path proofs (BinaryTrie.Prove), which expand a stem into its canonical
//     leaf/branch structure - the shape the claim assumes;
//   - resolved database records (BinaryTrie.Witness), which are per-stem group
//     blobs holding every sub-value of a stem at once.
//
// Nothing here asserts a ratio. The numbers are reported and the structural
// predictions around them are what pass or fail, so a change in the encoding
// shows up as a changed number rather than a red test with no explanation.

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb"
)

// distinctCode returns code of the requested length that is unique to seed, so
// content-addressed overflow stems are never shared between two contracts in a
// measurement. Sharing would report a cost no real workload sees.
func distinctCode(seed byte, length int) []byte {
	code := bytes.Repeat([]byte{0x5b}, length) // JUMPDEST: no PUSH swallows the next byte
	for i := 0; i < len(code) && i < 8; i++ {
		code[i] = seed
	}
	return code
}

// codeWitness is what one measurement produced.
type codeWitness struct {
	codeLen     int
	chunks      int
	proofBytes  int // path-proof format: every chunk key proved
	proofNodes  int
	recordBytes int // resolved database records: per-stem group blobs
	recordNodes int
}

func (c codeWitness) proofRatio() float64  { return float64(c.proofBytes) / float64(c.codeLen) }
func (c codeWitness) recordRatio() float64 { return float64(c.recordBytes) / float64(c.codeLen) }

// measureCodeWitness builds a binary tree holding `filler` ordinary accounts
// plus one contract with code of the given length, and measures both formats.
func measureCodeWitness(t *testing.T, codeLen, filler int) codeWitness {
	t.Helper()

	disk := rawdb.NewMemoryDatabase()
	db := triedb.NewDatabase(disk, triedb.PBTDefaults)
	defer db.Close()

	var (
		target   = common.Address{0xc0, 0xde, 0x01}
		code     = distinctCode(0xc0, codeLen)
		codeHash = crypto.Keccak256Hash(code)
	)
	tr := openTrie(t, db, types.EmptyBinaryHash)

	// Filler accounts, so the tree has a realistic depth above the stems the
	// code lives in rather than a handful of levels.
	for i := 0; i < filler; i++ {
		var addr common.Address
		addr[0], addr[1], addr[2] = byte(i), byte(i>>8), byte(i>>16)
		if err := tr.UpdateAccount(addr, testAccount(uint64(i+1)), 0); err != nil {
			t.Fatal(err)
		}
	}
	acct := testAccount(1)
	acct.CodeHash = codeHash[:]
	if err := tr.UpdateAccount(target, acct, len(code)); err != nil {
		t.Fatal(err)
	}
	if err := tr.UpdateContractCode(target, codeHash, code); err != nil {
		t.Fatal(err)
	}
	root := commitTrie(t, db, tr, types.EmptyBinaryHash, 1)

	chunks := (codeLen + 30) / 31

	// Format 1: prove every chunk key. The proof store is hash-keyed, so nodes
	// shared between chunk paths are counted once - which is the honest measure
	// for a witness that ships preimages.
	proofDb := memorydb.New()
	reopened := openTrie(t, db, root)
	for i := 0; i < chunks; i++ {
		key := bintrie.CodeChunkKey(target, codeHash, uint64(i))
		if err := reopened.Prove(key, proofDb); err != nil {
			t.Fatalf("proving chunk %d: %v", i, err)
		}
	}
	proofBytes, proofNodes := 0, 0
	it := proofDb.NewIterator(nil, nil)
	for it.Next() {
		proofBytes += len(it.Value()) // preimages only; the key is its hash
		proofNodes++
	}
	it.Release()

	// Format 2: the records a read actually resolves. Reading every chunk walks
	// the stems the code lives in, and the tracer keeps the raw database record
	// for each node touched.
	fresh := openTrie(t, db, root)
	for i := 0; i < chunks; i++ {
		key := bintrie.CodeChunkKey(target, codeHash, uint64(i))
		if _, err := fresh.GetStemValue(key); err != nil {
			t.Fatalf("reading chunk %d: %v", i, err)
		}
	}
	recordBytes, recordNodes := 0, 0
	for _, blob := range fresh.Witness() {
		recordBytes += len(blob)
		recordNodes++
	}
	return codeWitness{
		codeLen: codeLen, chunks: chunks,
		proofBytes: proofBytes, proofNodes: proofNodes,
		recordBytes: recordBytes, recordNodes: recordNodes,
	}
}

// measureMPTCodeWitness is the baseline the claim is stated against: what a
// merkle-patricia client ships to witness reading a contract's code. That is
// the account proof plus the bytecode itself, since the MPT commits to code by
// hash and carries the blob beside the proof rather than inside it.
func measureMPTCodeWitness(t *testing.T, codeLen, filler int) (int, int) {
	t.Helper()

	disk := rawdb.NewMemoryDatabase()
	db := triedb.NewDatabase(disk, triedb.HashDefaults)
	defer db.Close()

	tr, err := trie.NewStateTrie(trie.StateTrieID(types.EmptyRootHash), db)
	if err != nil {
		t.Fatal(err)
	}
	var (
		target   = common.Address{0xc0, 0xde, 0x01}
		code     = distinctCode(0xc0, codeLen)
		codeHash = crypto.Keccak256Hash(code)
	)
	for i := 0; i < filler; i++ {
		var addr common.Address
		addr[0], addr[1], addr[2] = byte(i), byte(i>>8), byte(i>>16)
		if err := tr.UpdateAccount(addr, testAccount(uint64(i+1)), 0); err != nil {
			t.Fatal(err)
		}
	}
	acct := testAccount(1)
	acct.CodeHash = codeHash[:]
	if err := tr.UpdateAccount(target, acct, len(code)); err != nil {
		t.Fatal(err)
	}
	root, nodes := tr.Commit(false)
	if err := db.Update(root, types.EmptyRootHash, 0, trienode.NewWithNodeSet(nodes), nil); err != nil {
		t.Fatal(err)
	}
	reopened, err := trie.NewStateTrie(trie.StateTrieID(root), db)
	if err != nil {
		t.Fatal(err)
	}
	proofDb := memorydb.New()
	if err := reopened.Prove(crypto.Keccak256(target[:]), proofDb); err != nil {
		t.Fatal(err)
	}
	bytes, count := 0, 0
	it := proofDb.NewIterator(nil, nil)
	for it.Next() {
		bytes += len(it.Value())
		count++
	}
	it.Release()
	// The bytecode travels with the proof; the trie only commits to its hash.
	return bytes + codeLen, count
}

// TestCodeWitnessCost reports the cost of witnessing contract code across the
// sizes where the tree's structure changes, and checks the structural claims
// the numbers rest on.
func TestCodeWitnessCost(t *testing.T) {
	sizes := []int{
		31,    // one chunk
		3937,  // 127 chunks: last size wholly inside the account header stem
		3968,  // 128 chunks: the header stem exactly full
		4000,  // 129 chunks: first overflow stem opens
		12000, // spans two overflow stems
		24576, // max contract size
	}
	var results []codeWitness
	for _, size := range sizes {
		got := measureCodeWitness(t, size, 64)
		results = append(results, got)
	}

	t.Log("code witness cost, 64 filler accounts. ratios are against the MPT baseline,")
	t.Log("which is the account proof plus the bytecode - the comparison #3286 makes.")
	t.Log("   code  chunks |     MPT B | path-proof B  xMPT | record B  xMPT")
	for _, r := range results {
		mptBytes, _ := measureMPTCodeWitness(t, r.codeLen, 64)
		t.Log(fmt.Sprintf("%7d %7d | %9d | %12d %5.2f | %8d %5.2f",
			r.codeLen, r.chunks, mptBytes,
			r.proofBytes, float64(r.proofBytes)/float64(mptBytes),
			r.recordBytes, float64(r.recordBytes)/float64(mptBytes)))
	}

	// The structural claims, checked rather than the ratios themselves.
	last := results[len(results)-1]

	// Proving every chunk expands each into its own leaf, so the node count is
	// at least one per chunk. This is the shape #3286 assumes.
	if last.proofNodes < last.chunks {
		t.Errorf("path proof has %d nodes for %d chunks; expected at least one leaf each", last.proofNodes, last.chunks)
	}
	// The record format is per-stem: max code is one account header stem plus
	// ceil(665/256)=3 overflow stems, so the node count must stay far below the
	// chunk count. This is what makes the two formats differ.
	if last.recordNodes >= last.chunks {
		t.Errorf("record format has %d nodes for %d chunks; expected per-stem, not per-chunk", last.recordNodes, last.chunks)
	}
	// And therefore the record format must be the cheaper of the two.
	if last.recordBytes >= last.proofBytes {
		t.Errorf("record format (%d B) is not cheaper than the expanded path proof (%d B)", last.recordBytes, last.proofBytes)
	}
}

// TestCodeWitnessPartialRead measures the case the two formats disagree about
// most: a large contract of which only a little is executed.
//
// #3286 notes that "a client that proves only the executed chunks will see the
// parametrisation flatten". That cuts both ways here. Expanding a stem into
// leaves is expensive when every chunk is wanted and cheap when one is; shipping
// the stem's record is the reverse, because the record carries all 128 header
// chunks whether or not they were read. Neither format dominates.
func TestCodeWitnessPartialRead(t *testing.T) {
	disk := rawdb.NewMemoryDatabase()
	db := triedb.NewDatabase(disk, triedb.PBTDefaults)
	defer db.Close()

	var (
		target   = common.Address{0xc0, 0xde, 0x01}
		code     = distinctCode(0xc0, 24576)
		codeHash = crypto.Keccak256Hash(code)
	)
	tr := openTrie(t, db, types.EmptyBinaryHash)
	for i := 0; i < 64; i++ {
		var addr common.Address
		addr[0], addr[1], addr[2] = byte(i), byte(i>>8), byte(i>>16)
		if err := tr.UpdateAccount(addr, testAccount(uint64(i+1)), 0); err != nil {
			t.Fatal(err)
		}
	}
	acct := testAccount(1)
	acct.CodeHash = codeHash[:]
	if err := tr.UpdateAccount(target, acct, len(code)); err != nil {
		t.Fatal(err)
	}
	if err := tr.UpdateContractCode(target, codeHash, code); err != nil {
		t.Fatal(err)
	}
	root := commitTrie(t, db, tr, types.EmptyBinaryHash, 1)

	t.Log("max-size contract, reading only the first N chunks")
	t.Log("  chunks read | path-proof B | record B")
	for _, n := range []int{1, 4, 16, 128, 793} {
		proofDb := memorydb.New()
		p := openTrie(t, db, root)
		for i := 0; i < n; i++ {
			if err := p.Prove(bintrie.CodeChunkKey(target, codeHash, uint64(i)), proofDb); err != nil {
				t.Fatal(err)
			}
		}
		pb := 0
		it := proofDb.NewIterator(nil, nil)
		for it.Next() {
			pb += len(it.Value())
		}
		it.Release()

		r := openTrie(t, db, root)
		for i := 0; i < n; i++ {
			if _, err := r.GetStemValue(bintrie.CodeChunkKey(target, codeHash, uint64(i))); err != nil {
				t.Fatal(err)
			}
		}
		rb := 0
		for _, blob := range r.Witness() {
			rb += len(blob)
		}
		t.Log(fmt.Sprintf("%13d | %12d | %8d", n, pb, rb))
	}
}

// TestCodeWitnessCostVsStateSize checks how much of the cost depends on the
// size of the surrounding state, which is where a benchmark on a toy fixture
// would flatter itself.
func TestCodeWitnessCostVsStateSize(t *testing.T) {
	t.Log("max-size contract, varying filler accounts")
	t.Log("  filler | path-proof bytes  x code | record bytes  x code")
	for _, filler := range []int{8, 64, 512, 4096} {
		r := measureCodeWitness(t, 24576, filler)
		t.Log(fmt.Sprintf("%8d | %16d %8.2f | %12d %8.2f",
			filler, r.proofBytes, r.proofRatio(), r.recordBytes, r.recordRatio()))
	}
}
