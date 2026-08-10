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
	"fmt"
	"slices"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

// The binary tree's half of the witness encoding. It lives apart so encoding.go
// stays close to upstream across merges.

// toExtPBT fills the binary-tree half of ext and reports whether it applied.
//
// A proof and a node set are alternatives, so at most one of them is written and
// the merkle fields are left to the caller when neither is.
func (w *Witness) toExtPBT(ext *ExtWitness) bool {
	if len(w.Proof) > 0 {
		ext.Proof = slices.Clone(w.Proof)
		return true
	}
	// A node set travels as parallel arrays ordered by path, because a group
	// record folds at a depth stored inside it and cannot be re-keyed from its
	// own bytes the way a merkle node can.
	if len(w.Nodes) == 0 {
		return false
	}
	paths := make([]string, 0, len(w.Nodes))
	for path := range w.Nodes {
		paths = append(paths, path)
	}
	slices.Sort(paths)

	ext.Keys = make([]hexutil.Bytes, 0, len(paths))
	ext.State = make([]hexutil.Bytes, 0, len(paths))
	for _, path := range paths {
		ext.Keys = append(ext.Keys, []byte(path))
		ext.State = append(ext.State, w.Nodes[path])
	}
	return true
}

// fromExtPBT decodes the binary-tree half of ext and reports whether it applied.
func (w *Witness) fromExtPBT(ext *ExtWitness) (bool, error) {
	if len(ext.Proof) > 0 {
		// A proof and a node set are two descriptions of one tree. Accepting both
		// would leave the sender to decide which one the reader believed.
		if len(ext.Keys) > 0 {
			return false, fmt.Errorf("witness carries a %d-byte proof alongside %d path-keyed nodes", len(ext.Proof), len(ext.Keys))
		}
		if len(ext.State) > 0 {
			return false, fmt.Errorf("witness carries a %d-byte proof alongside %d state nodes", len(ext.Proof), len(ext.State))
		}
		w.Proof = slices.Clone(ext.Proof)
		w.Nodes = make(map[string][]byte)
		w.State = make(map[string]struct{})
		return true, nil
	}
	// Keys present means a node set: State is path-addressed, and the two arrays
	// must line up exactly, so a mismatch is rejected rather than silently
	// truncated to the shorter one.
	if len(ext.Keys) == 0 {
		return false, nil
	}
	if len(ext.Keys) != len(ext.State) {
		return false, fmt.Errorf("witness has %d keys for %d nodes", len(ext.Keys), len(ext.State))
	}
	w.Nodes = make(map[string][]byte, len(ext.Keys))
	for i, path := range ext.Keys {
		if _, dup := w.Nodes[string(path)]; dup {
			return false, fmt.Errorf("witness repeats the node at path %x", []byte(path))
		}
		w.Nodes[string(path)] = ext.State[i]
	}
	w.State = make(map[string]struct{})
	return true, nil
}
