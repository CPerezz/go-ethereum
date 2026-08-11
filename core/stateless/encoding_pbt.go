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
// State and Keys are allocated empty rather than left nil: they have no
// omitempty, so a nil slice marshals to JSON null and every reader of
// debug_executionWitness expecting an array breaks on it. RLP encodes nil and
// empty alike, so the merkle byte-identity the Proof field preserves is
// untouched either way.
func (w *Witness) toExtPBT(ext *ExtWitness) bool {
	if len(w.Proof) == 0 {
		return false
	}
	ext.Proof = slices.Clone(w.Proof)
	ext.State = make([]hexutil.Bytes, 0)
	ext.Keys = make([]hexutil.Bytes, 0)
	return true
}

// fromExtPBT decodes the binary-tree half of ext and reports whether it applied.
func (w *Witness) fromExtPBT(ext *ExtWitness) (bool, error) {
	// Keys only ever carried the paths of a node set, which this tree no longer
	// ships. Ignoring them would decode such a witness as an empty merkle one and
	// replay it against nothing, so it is refused by name.
	if len(ext.Keys) > 0 {
		return false, fmt.Errorf("witness carries %d path-keyed nodes, which are no longer a witness format", len(ext.Keys))
	}
	if len(ext.Proof) == 0 {
		return false, nil
	}
	// A proof and a merkle node set are two descriptions of one tree. Accepting
	// both would leave the sender to decide which one the reader believed.
	if len(ext.State) > 0 {
		return false, fmt.Errorf("witness carries a %d-byte proof alongside %d state nodes", len(ext.Proof), len(ext.State))
	}
	w.Proof = slices.Clone(ext.Proof)
	w.State = make(map[string]struct{})
	return true, nil
}
