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

package bintrie

import (
	"bytes"
	"slices"
	"sync"
)

// ProofRecorder accumulates what a proof over a tree's opening root has to
// cover, so that a block can be replayed against the proof alone.
//
// The three kinds are not interchangeable, and which one an access needs is
// decided by what the replay does with it rather than by what the producer
// happened to resolve: a value read walks one key, an account read and every
// write need the whole group, and a structural change needs a node no key
// names. See ProofRequests.
//
// Every method is a no-op on a nil receiver, so the call sites inside the trie
// need no guard.
type ProofRecorder struct {
	lock  sync.Mutex
	keys  map[string]struct{}
	stems map[string]struct{}
	paths map[string]struct{} // encodeBitPrefix form
}

// NewProofRecorder returns an empty recorder.
//
// It starts out holding the root, because a proof of nothing is not a proof: a
// request set with no targets collapses the whole tree to one hash, which
// verifies against any root and is refused. A block that reads and writes
// nothing - no transactions, no withdrawals, no reward - records nothing else.
func NewProofRecorder() *ProofRecorder {
	r := &ProofRecorder{
		keys:  make(map[string]struct{}),
		stems: make(map[string]struct{}),
		paths: make(map[string]struct{}),
	}
	r.AddPath(nil, 0)
	return r
}

// AddKey records that one leaf must be readable, present or absent.
func (r *ProofRecorder) AddKey(key []byte) {
	if r == nil {
		return
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	r.keys[string(key)] = struct{}{}
}

// AddStem records that a whole group must ship. Anything that writes to a stem
// or reads it as a group needs this: a group the proof opened only part of
// rebuilds as branches and leaves, which those operations refuse.
func (r *ProofRecorder) AddStem(stem []byte) {
	if r == nil {
		return
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	r.stems[string(stem)] = struct{}{}
}

// AddPath records that whatever node sits at the first bits bits of key must be
// materialised, its children as hashes.
func (r *ProofRecorder) AddPath(key []byte, bits int) {
	if r == nil {
		return
	}
	r.addWalk(slice(key, 0, bits))
}

// addWalk is AddPath over a walk the trie already holds.
func (r *ProofRecorder) addWalk(w bitstr) {
	if r == nil {
		return
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	r.paths[string(encodeBitPrefix(w))] = struct{}{}
}

// Len reports how many requests are held.
func (r *ProofRecorder) Len() int {
	if r == nil {
		return 0
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	return len(r.keys) + len(r.stems) + len(r.paths)
}

// Requests returns the accumulated set, sorted, so that the same accesses
// always produce the same proof bytes.
func (r *ProofRecorder) Requests() ProofRequests {
	if r == nil {
		return ProofRequests{}
	}
	r.lock.Lock()
	defer r.lock.Unlock()

	req := ProofRequests{
		Keys:  sortedBytes(r.keys),
		Stems: sortedBytes(r.stems),
	}
	for _, encoded := range sortedBytes(r.paths) {
		p, _, err := decodeBitPrefix(encoded)
		if err != nil {
			continue // written by addWalk, so unreachable
		}
		req.Paths = append(req.Paths, ProofPath{Key: p.b, Bits: p.n})
	}
	return req
}

// Copy returns an independent recorder holding the same set.
func (r *ProofRecorder) Copy() *ProofRecorder {
	if r == nil {
		return nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	cp := &ProofRecorder{
		keys:  make(map[string]struct{}, len(r.keys)),
		stems: make(map[string]struct{}, len(r.stems)),
		paths: make(map[string]struct{}, len(r.paths)),
	}
	for k := range r.keys {
		cp.keys[k] = struct{}{}
	}
	for k := range r.stems {
		cp.stems[k] = struct{}{}
	}
	for k := range r.paths {
		cp.paths[k] = struct{}{}
	}
	return cp
}

func sortedBytes(set map[string]struct{}) [][]byte {
	if len(set) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(set))
	for s := range set {
		out = append(out, []byte(s))
	}
	slices.SortFunc(out, bytes.Compare)
	return out
}
