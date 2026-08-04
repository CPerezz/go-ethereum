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

// Measures the two EIP-8297 layout changes being proposed upstream:
//
//	PR 1 - every code chunk lives in CODE_ZONE, none in the account header.
//	PR 2 - a code stem is CODE_ZONE ‖ code_hash[0:29] ‖ tree_index, so a
//	       contract's stems are adjacent instead of scattered by a hash.
//
// Both change only where code stems land in key space, so the proof-size
// effect is a property of the tree's shape. That is what is measured here.
//
// PR 2's real key is 32 bytes, which this engine's validateStem rejects
// (CodeKeyLength is 34). The adjacent layout below therefore pads its stem to
// the legal 33 bytes with two constant trailing bytes. Padding cannot change
// the branch structure - the four stems still diverge after the same 240
// shared bits, and constant tails add no branch nodes - so the measured
// branch counts are PR 2's. The leaf-size effect of the shorter key is a
// separate, exact term (-2 B per leaf) and is reported as such rather than
// measured, so nothing here depends on the padding being free.

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/ethereum/go-ethereum/triedb"
)

// adjacentCodeStem is PR 2's derivation: no hash, the code hash truncated to
// 29 bytes followed by the tree index, so a contract's stems differ only in
// their last meaningful byte. Padded to the 33 bytes this engine requires.
func adjacentCodeStem(codeHash common.Hash, treeIndex uint64) []byte {
	stem := make([]byte, 0, bintrie.CodeKeyLength-1)
	stem = append(stem, bintrie.CodeZone)
	stem = append(stem, codeHash[:29]...)
	stem = append(stem, byte(treeIndex))
	return append(stem, 0x00, 0x00) // pad only; see the note at the top
}

// codeLayout maps a chunk index to the key it occupies.
type codeLayout struct {
	name string
	key  func(addr common.Address, codeHash common.Hash, chunk uint64) []byte
}

var (
	// layoutToday is the EIP as written: chunks 0..127 in the account
	// header keyed by address, the rest content-addressed and scattered.
	layoutToday = codeLayout{"today", bintrie.CodeChunkKey}

	// layoutPR1 moves the header chunks into the code zone, keeping the
	// hashed derivation, so a contract's stems stay scattered.
	layoutPR1 = codeLayout{"PR1-all-in-code-zone", func(_ common.Address, codeHash common.Hash, chunk uint64) []byte {
		stem := bintrie.CodeChunkStem(codeHash, chunk/bintrie.StemSubtreeWidth)
		return append(stem, byte(chunk%bintrie.StemSubtreeWidth))
	}}

	// layoutPR2 additionally drops the hash, making those stems adjacent.
	layoutPR2 = codeLayout{"PR2-adjacent-stems", func(_ common.Address, codeHash common.Hash, chunk uint64) []byte {
		stem := adjacentCodeStem(codeHash, chunk/bintrie.StemSubtreeWidth)
		return append(stem, byte(chunk%bintrie.StemSubtreeWidth))
	}}
)

// layoutResult is one layout's cost for one contract, in both encodings this
// tree has: expanded path proofs, and the per-stem group records a read
// actually resolves. They answer differently, and the difference is the point:
// a path proof ships every internal branch of the stems it covers, a record
// does not, so the root-path term this change acts on is a rounding error in
// one and the dominant cost in the other.
type layoutResult struct {
	stems                int
	leafBytes, leafN     int
	branchBytes, branchN int
	recordBytes          int
	recordNodes          int
	recordBranches       int
}

func (r layoutResult) total() int { return r.leafBytes + r.branchBytes }

// measureLayout builds a tree of `filler` accounts plus one contract whose
// code is placed by `lay`, then proves the account and every chunk of it.
func measureLayout(t *testing.T, lay codeLayout, codeLen, filler int) layoutResult {
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

	// Place the code by hand rather than through UpdateContractCode, so every
	// layout is inserted the same way and the comparison isolates placement.
	chunks := bintrie.ChunkifyCode(code)
	n := len(chunks) / 32
	type group struct {
		stem []byte
		subs []byte
		vals [][]byte
	}
	var (
		order []*group
		byRef = map[string]*group{}
	)
	for i := 0; i < n; i++ {
		key := lay.key(target, codeHash, uint64(i))
		stem, sub := key[:len(key)-1], key[len(key)-1]
		g, ok := byRef[string(stem)]
		if !ok {
			g = &group{stem: stem}
			byRef[string(stem)] = g
			order = append(order, g)
		}
		g.subs = append(g.subs, sub)
		g.vals = append(g.vals, chunks[32*i:32*(i+1)])
	}
	for _, g := range order {
		if err := tr.UpdateStem(g.stem, g.subs, g.vals); err != nil {
			t.Fatalf("%s: inserting stem %x: %v", lay.name, g.stem, err)
		}
	}
	root := commitTrie(t, db, tr, types.EmptyBinaryHash, 1)

	// The proof a client ships to execute this contract: the account's own
	// leaves plus every code chunk.
	proofDb := memorydb.New()
	p := openTrie(t, db, root)
	keys := [][]byte{bintrie.BasicDataKey(target), bintrie.CodeHashKey(target)}
	for i := 0; i < n; i++ {
		keys = append(keys, lay.key(target, codeHash, uint64(i)))
	}
	for _, key := range keys {
		if err := p.Prove(key, proofDb); err != nil {
			t.Fatalf("%s: proving %x: %v", lay.name, key, err)
		}
	}
	res := layoutResult{stems: len(order)}
	it := proofDb.NewIterator(nil, nil)
	for it.Next() {
		v := it.Value()
		switch v[0] {
		case 0x00: // tagLeaf
			res.leafBytes += len(v)
			res.leafN++
		case 0x01: // tagBranch
			res.branchBytes += len(v)
			res.branchN++
		default:
			t.Fatalf("%s: unknown node tag %#x", lay.name, v[0])
		}
	}
	it.Release()

	// The other encoding: read the same keys and keep the database records the
	// walk resolved. Internal branches inside a stem never appear here, so what
	// remains is the group blobs plus the branch nodes on the way to them.
	fresh := openTrie(t, db, root)
	for _, key := range keys {
		if _, err := fresh.GetStemValue(key); err != nil {
			t.Fatalf("%s: reading %x: %v", lay.name, key, err)
		}
	}
	for _, blob := range fresh.Witness() {
		res.recordBytes += len(blob)
		res.recordNodes++
		if len(blob) > 0 && blob[0] == 0x01 { // tagBranch
			res.recordBranches++
		}
	}
	return res
}

// commonPrefixBits returns how many leading bits every one of these stems
// shares. It is the check that the adjacent layout is really adjacent: a
// measurement showing no gain would otherwise be indistinguishable from a
// measurement of a layout that was never built.
func commonPrefixBits(stems [][]byte) int {
	if len(stems) < 2 {
		return 0
	}
	bits := 0
	for i := 0; i < 8*len(stems[0]); i++ {
		b, mask := i/8, byte(1)<<(7-i%8)
		want := stems[0][b] & mask
		for _, s := range stems[1:] {
			if s[b]&mask != want {
				return bits
			}
		}
		bits++
	}
	return bits
}

// TestStemAdjacencyLayouts is the measurement behind the two EIP PRs: what
// each layout costs to witness a max-size contract's whole code.
//
// The prediction being checked is structural rather than numeric. PR 1 should
// cost one extra root path, because the header chunks stop riding the stem the
// account read already pays for. PR 2 should then collapse the contract's
// stems into one shared prefix, because they now differ only in one byte.
func TestStemAdjacencyLayouts(t *testing.T) {
	const codeLen = 24576 // EIP-7954 pre-7907 max, and #3286's worst case

	for _, filler := range []int{64, 4096} {
		today := measureLayout(t, layoutToday, codeLen, filler)
		pr1 := measureLayout(t, layoutPR1, codeLen, filler)
		pr2 := measureLayout(t, layoutPR2, codeLen, filler)

		t.Logf("=== %d B contract, %d filler accounts ===", codeLen, filler)
		for _, r := range []struct {
			name string
			res  layoutResult
		}{{"today", today}, {"PR1", pr1}, {"PR2", pr2}} {
			t.Logf("  %-6s path %7d B (%4d leaves, %4d branches)   record %6d B (%2d nodes: %d branches + %d groups)   code stems %d",
				r.name, r.res.total(), r.res.leafN, r.res.branchN,
				r.res.recordBytes, r.res.recordNodes, r.res.recordBranches,
				r.res.recordNodes-r.res.recordBranches, r.res.stems)
		}
		t.Logf("  path proof   PR1 vs today %+6d B (%+d branches) | PR2 vs today %+6d B (%+d branches)",
			pr1.total()-today.total(), pr1.branchN-today.branchN,
			pr2.total()-today.total(), pr2.branchN-today.branchN)
		t.Logf("  record       PR1 vs today %+6d B (%+d nodes)     | PR2 vs today %+6d B (%+d nodes)",
			pr1.recordBytes-today.recordBytes, pr1.recordNodes-today.recordNodes,
			pr2.recordBytes-today.recordBytes, pr2.recordNodes-today.recordNodes)
		t.Logf("  adjacency alone (PR2 vs PR1): path %+d B, record %+d B (%+d nodes)",
			pr2.total()-pr1.total(), pr2.recordBytes-pr1.recordBytes, pr2.recordNodes-pr1.recordNodes)

		// The 32-byte key is a separate, exact term the padded stems above do
		// not carry: two bytes off every code leaf's preimage. It applies to the
		// path proof, which ships a key per leaf, and not to the records, which
		// carry one stem per group.
		t.Logf("  PR2's 32-byte key would also shorten each of the %d leaves by 2 B: %+d B path total vs today",
			pr2.leafN, pr2.total()-pr2.leafN*2-today.total())

		// The structural claim worth pinning is the one that came out opposite
		// to the proposal's own model: a path proof covering every leaf of a
		// contract is a Steiner tree over those leaves, whose internal nodes
		// exist wherever the stems sit, so moving the stems cannot remove them.
		if pr2.branchN != pr1.branchN {
			t.Errorf("adjacency changed the path proof's branch count (%d -> %d); "+
				"it was measured not to, and the PR argument depends on knowing that",
				pr1.branchN, pr2.branchN)
		}
		if steiner := pr2.leafN - 1; pr2.branchN < steiner {
			t.Errorf("path proof has %d branches, fewer than the %d a Steiner tree over %d leaves needs",
				pr2.branchN, steiner, pr2.leafN)
		}
	}
}

// TestCodeStemCount pins how many stems each layout puts a max-size contract
// in, which is what the root-path arithmetic in the PR descriptions rests on.
func TestCodeStemCount(t *testing.T) {
	const codeLen = 24576
	var (
		code     = distinctCode(0xc0, codeLen)
		codeHash = crypto.Keccak256Hash(code)
		target   = common.Address{0xc0, 0xde, 0x01}
		chunks   = (codeLen + 30) / 31
	)
	for _, lay := range []codeLayout{layoutToday, layoutPR1, layoutPR2} {
		var (
			seen   = map[string]bool{}
			code   [][]byte
			header int
		)
		for i := 0; i < chunks; i++ {
			key := lay.key(target, codeHash, uint64(i))
			stem := key[:len(key)-1]
			if key[0] == bintrie.AccountZone {
				header++
			}
			if !seen[string(stem)] {
				seen[string(stem)] = true
				if key[0] == bintrie.CodeZone {
					code = append(code, stem)
				}
			}
		}
		t.Logf("%-22s %d chunks -> %d stems (%d chunks in the account header), "+
			"%d code stems sharing %d leading bits",
			lay.name, chunks, len(seen), header, len(code), commonPrefixBits(code))
		for _, s := range code {
			t.Logf("      %x", s)
		}
	}
}

// TestTreeDepthVsStateSize measures the depth a root-to-leaf path actually
// has, since both PRs' effects scale linearly in it and every projection to
// mainnet is a projection of this number.
func TestTreeDepthVsStateSize(t *testing.T) {
	for _, accounts := range []int{64, 1024, 16384, 262144} {
		disk := rawdb.NewMemoryDatabase()
		db := triedb.NewDatabase(disk, triedb.PBTDefaults)

		tr := openTrie(t, db, types.EmptyBinaryHash)
		for i := 0; i < accounts; i++ {
			var addr common.Address
			addr[0], addr[1], addr[2] = byte(i), byte(i>>8), byte(i>>16)
			if err := tr.UpdateAccount(addr, testAccount(uint64(i+1)), 0); err != nil {
				t.Fatal(err)
			}
		}
		root := commitTrie(t, db, tr, types.EmptyBinaryHash, 1)

		// One key, so the proof is exactly its root-to-leaf path: the branch
		// count is the depth.
		var probe common.Address
		probe[0], probe[1], probe[2] = byte(0), byte(0), byte(0)
		proofDb := memorydb.New()
		p := openTrie(t, db, root)
		if err := p.Prove(bintrie.BasicDataKey(probe), proofDb); err != nil {
			t.Fatal(err)
		}
		depth, branchBytes := 0, 0
		it := proofDb.NewIterator(nil, nil)
		for it.Next() {
			if it.Value()[0] == 0x01 { // tagBranch
				depth++
				branchBytes += len(it.Value())
			}
		}
		it.Release()
		db.Close()

		t.Logf("%7d accounts: depth %2d, %d branch bytes on the path (%.1f B/branch)",
			accounts, depth, branchBytes, float64(branchBytes)/float64(depth))
	}
}
