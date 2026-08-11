// Copyright 2024 The go-ethereum Authors
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
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie/bintrie"
)

// MakeHashDB imports tries, codes and block hashes from a witness into a new
// hash-based memory db. We could eventually rewrite this into a pathdb, but
// simple is better for now.
//
// Note, this hashdb approach is quite strictly self-validating:
//   - Headers are persisted keyed by hash, so blockhash will error on junk
//   - Codes are persisted keyed by hash, so bytecode lookup will error on junk
//   - Trie nodes are persisted keyed by hash, so trie expansion will error on junk
//
// Acceleration structures built would need to explicitly validate the witness.
func (w *Witness) MakeHashDB() ethdb.Database {
	var (
		memdb  = rawdb.NewMemoryDatabase()
		hasher = crypto.NewKeccakState()
		hash   = make([]byte, 32)
	)
	// Inject all the "block hashes" (i.e. headers) into the ephemeral database
	for _, header := range w.Headers {
		rawdb.WriteHeader(memdb, header)
	}
	// Inject all the bytecodes into the ephemeral database
	for code := range w.Codes {
		blob := []byte(code)

		hasher.Reset()
		hasher.Write(blob)
		hasher.Read(hash)

		rawdb.WriteCode(memdb, common.BytesToHash(hash), blob)
	}
	// Inject all the MPT trie nodes into the ephemeral database
	for node := range w.State {
		blob := []byte(node)

		hasher.Reset()
		hasher.Write(blob)
		hasher.Read(hash)

		rawdb.WriteLegacyTrieNode(memdb, common.BytesToHash(hash), blob)
	}
	return memdb
}

// MakePathDB imports nodes, codes and block hashes from a binary-tree witness
// into a new path-based memory db.
//
// The binary tree cannot use MakeHashDB. A merkle node is named by the hash of
// its own bytes, so a bag of blobs is a complete description; a binary group
// record folds at a depth stored inside it, so its hash depends on where it
// sits and the blob alone cannot be re-keyed. Nodes are therefore addressed by
// path here, which is what pathdb wants anyway.
//
// Headers and codes are still keyed by hash and so validate themselves. State
// records do not: pathdb skips the node-hash comparison for this tree, since a
// binary node's hash is not the hash of its own bytes. A proof is therefore
// checked against the witness root here, before anything is written, which is
// the only point a malformed witness is refused rather than surfacing later as a
// root that cannot match.
func (w *Witness) MakePathDB() (ethdb.Database, error) {
	var (
		memdb  = rawdb.NewMemoryDatabase()
		hasher = crypto.NewKeccakState()
		hash   = make([]byte, 32)
	)
	for _, header := range w.Headers {
		rawdb.WriteHeader(memdb, header)
	}
	// Code is still content-addressed by keccak in the binary tree; only the
	// state nodes change shape.
	for code := range w.Codes {
		blob := []byte(code)

		hasher.Reset()
		hasher.Write(blob)
		hasher.Read(hash)

		rawdb.WriteCode(memdb, common.BytesToHash(hash), blob)
	}
	// Binary-tree data lives under its own namespace, the same one pathdb
	// rebinds itself to when opened in binary mode.
	tbl := rawdb.NewTable(memdb, string(rawdb.PBTPrefix))
	if err := w.writeStateRecords(tbl); err != nil {
		return nil, err
	}
	// pathdb resolves the disk layer's root from this marker when it opens in
	// binary mode; without it the layer would come up empty and every lookup
	// would miss.
	rawdb.WriteSnapshotRoot(tbl, w.Root())
	return memdb, nil
}

// writeStateRecords fills the state records from the witness: out of its proof
// where it carries one, otherwise out of the node set it shipped.
func (w *Witness) writeStateRecords(tbl ethdb.Database) error {
	root := w.Root()
	// Both sentinels denote a fresh tree, which trie.NewReader answers without
	// asking the database, so an empty pre-state legitimately has no records - and
	// a proof over one cannot exist, since the walk emits no token for it.
	blank := root == types.EmptyBinaryHash || root == types.EmptyRootHash
	switch {
	case len(w.Proof) > 0 && blank:
		return fmt.Errorf("stateless: witness carries a proof over the empty root")
	case len(w.Proof) > 0:
		return w.writeProofRecords(tbl, root)
	case blank:
		return nil
	case len(w.Nodes) > 0:
		for path, blob := range w.Nodes {
			rawdb.WriteAccountTrieNode(tbl, []byte(path), blob)
		}
		return nil
	}
	// Silent otherwise: every read would miss, the block would be refused on its
	// root, and the producer would look at fault instead of its own witness.
	return fmt.Errorf("stateless: witness for root %x carries no state", root)
}

// writeProofRecords verifies the proof against root and writes the tree it
// rebuilds out as database records.
func (w *Witness) writeProofRecords(tbl ethdb.Database, root common.Hash) error {
	mp, err := bintrie.DecodeMultiproof(w.Proof)
	if err != nil {
		return fmt.Errorf("stateless: decoding the witness proof: %w", err)
	}
	tr, err := bintrie.VerifyMultiproof(root, mp)
	if err != nil {
		return fmt.Errorf("stateless: verifying the witness proof against %x: %w", root, err)
	}
	return tr.WriteRecords(func(path []byte, _ common.Hash, blob []byte) {
		rawdb.WriteAccountTrieNode(tbl, path, blob)
	})
}
