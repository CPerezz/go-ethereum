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
	"errors"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// OnNode receives every record the builder emits: its database path, hash
// and blob. Records arrive children before parents. path and blob are only
// valid for the call: the builder reuses their backing arrays for the next
// record, so a callback that needs one past its return must copy it.
type OnNode func(path []byte, hash common.Hash, blob []byte)

// StackBuilder constructs a binary tree from a strictly-ascending stream of
// key/value pairs in one bottom-up pass with O(depth) memory, emitting each
// database record exactly once as its key range closes. It is the
// stack-trie analogue for the EIP-8297 tree: the ingester for sorted bulk
// loads (state conversion, flat-state verification), where incremental
// insertion would mean billions of random walks.
//
// Invariant: the right spine holds one frame per pending branch, each
// carrying the split bit it branches on and the hash of its completed left
// child. A node's own position is not known when it is built - it depends
// on the divergence bit with the key that comes next - so positions are
// resolved as max(deepest open frame, that divergence) + 1 at close time.
type StackBuilder struct {
	onNode OnNode

	// Pending group: the stem currently being filled.
	stem     []byte
	subs     []byte
	valArena []byte // pending group's 32-byte values, packed back to back

	frames  []builderFrame
	lastKey []byte
	root    common.Hash
	done    bool

	// Scratch reused across every emitted record: each node is built,
	// hashed and handed to onNode once, so one instance of each serves the
	// whole build, marked dirty before every use; prefix, path and blob back
	// a branch's prefix and the record handed to onNode.
	groupScratch       groupNode
	prefix, path, blob []byte

	par *buildPipeline // hashing on goroutines of its own, if set
}

type builderFrame struct {
	split int         // bit position this branch splits on
	left  common.Hash // hash of the completed left subtree; unset when pipelined
}

// NewStackBuilder creates a builder streaming records into onNode, which may
// be nil for a hash-only run.
func NewStackBuilder(onNode OnNode) *StackBuilder {
	return &StackBuilder{onNode: onNode}
}

// NewParallelStackBuilder creates a builder that hashes the stem groups on
// workers goroutines and folds the branches above them on one more, calling
// onNode from it in the order NewStackBuilder would. Add only places each
// stem; the caller is left the ordering checks and copies. Call Finish, or
// Stop when abandoning the build.
func NewParallelStackBuilder(onNode OnNode, workers int) *StackBuilder {
	b := &StackBuilder{onNode: onNode}
	b.par = newBuildPipeline(b, max(workers, 1))
	return b
}

// Add appends the next key/value pair. Keys must be zone-conformant,
// strictly ascending, with 32-byte values. Add copies the value into its own
// arena; the caller's slices are free to reuse the moment Add returns.
func (b *StackBuilder) Add(key, value []byte) error {
	if b.done {
		return errors.New("bintrie: builder already finished")
	}
	if err := validateKey(key); err != nil {
		return err
	}
	if len(value) != 32 {
		return errors.New("bintrie: builder values must be 32 bytes")
	}
	if isZeroValue(value) {
		// Zero values resolve to absence; folding one would bless corruption.
		return errors.New("bintrie: builder values must not be 32 zero bytes")
	}
	if b.lastKey != nil && bytes.Compare(key, b.lastKey) <= 0 {
		return errors.New("bintrie: builder keys must be strictly ascending")
	}
	stem, sub := key[:len(key)-1], key[len(key)-1]

	if b.stem == nil {
		b.stem = append([]byte{}, stem...)
	} else if !bytes.Equal(b.stem, stem) {
		// The pending stem is complete. Everything below the divergence bit
		// closes; the result becomes the left child of a new frame at that
		// bit, whose right child is the stem starting now.
		div := commonPrefixLen(b.lastKey, key, 0)
		left := b.closeBelow(div)
		b.frames = append(b.frames, builderFrame{split: div, left: left})
		if b.par != nil {
			b.par.push()
		}
		b.stem = append(b.stem[:0], stem...)
		b.subs, b.valArena = b.subs[:0], b.valArena[:0]
	}
	b.subs = append(b.subs, sub)
	b.valArena = append(b.valArena, value...)
	b.lastKey = append(b.lastKey[:0], key...)
	return nil
}

// deepestSplit returns the split bit of the deepest open frame, or -1 when
// the spine is empty.
func (b *StackBuilder) deepestSplit() int {
	if n := len(b.frames); n > 0 {
		return b.frames[n-1].split
	}
	return -1
}

// posBelow returns the position a node occupies given the deepest open
// frame and div, the split of the branch about to be created above it
// (-1 while finishing). A node's parent is whichever of the two is deeper:
// the group closing at div becomes that branch's left child, while a group
// under an already-open deeper frame is that frame's right child.
func (b *StackBuilder) posBelow(div int) int {
	return max(b.deepestSplit(), div) + 1
}

// closeBelow finishes the pending stem and folds every frame deeper than
// div, returning the hash of the resulting subtree, or nothing when the
// pipeline hashes. The branch prefixes are reconstructed from the last key,
// which shares every bit above each fold's split with the subtree below it.
// b.lastKey is stable for the duration of this call - Add only overwrites it
// once closeBelow has returned - so the fold reads it directly rather than
// through a defensive copy.
func (b *StackBuilder) closeBelow(div int) common.Hash {
	pos := b.posBelow(div)
	var right common.Hash
	if b.par != nil {
		b.par.group(b.stem, b.subs, b.valArena, pos, b.lastKey)
	} else {
		right = b.emitGroup(&b.groupScratch, b.stem, b.subs, b.valArena, pos)
	}
	for len(b.frames) > 0 && b.frames[len(b.frames)-1].split > div {
		frame := b.frames[len(b.frames)-1]
		b.frames = b.frames[:len(b.frames)-1]
		parentPos := b.posBelow(div)
		if b.par != nil {
			b.par.branch(parentPos, frame.split)
		} else {
			right = b.emitBranch(b.lastKey, parentPos, frame.split, frame.left, right)
		}
	}
	return right
}

// emitGroup hashes the stem group of subs and their values at position pos
// with g as scratch, and hands it to onNode.
func (b *StackBuilder) emitGroup(g *groupNode, stem, subs, vals []byte, pos int) common.Hash {
	h := hashGroup(g, stem, subs, vals, pos)
	if b.onNode != nil {
		b.path = appendPath(b.path[:0], stem, pos)
		b.blob = appendNode(b.blob[:0], g, pos)
		b.onNode(b.path, h, b.blob)
	}
	return h
}

// hashGroup hashes the stem group of subs and their values at position pos,
// with g as scratch.
func hashGroup(g *groupNode, stem, subs, vals []byte, pos int) common.Hash {
	g.vals = g.vals[:0]
	for i := range subs {
		g.vals = append(g.vals, vals[i*32:i*32+32])
	}
	g.stem, g.subs, g.dirty = stem, subs, true
	return g.hashAt(pos)
}

// emitBranch hashes the branch at position pos splitting on bit split, whose
// prefix is key's bits in between, and hands it to onNode: what a branchNode
// over two hashed children hashes and serializes to.
func (b *StackBuilder) emitBranch(key []byte, pos, split int, left, right common.Hash) common.Hash {
	prefix := sliceInto(b.prefix, key, pos, split-pos)
	b.prefix = prefix.b
	h := branchHash(prefix, left, right)
	if b.onNode != nil {
		b.path = appendPath(b.path[:0], key, pos)
		b.blob = appendBranchBlob(b.blob[:0], prefix, left, right)
		b.onNode(b.path, h, b.blob)
	}
	return h
}

// Finish closes every open frame and returns the root hash. The builder is
// unusable afterwards.
func (b *StackBuilder) Finish() common.Hash {
	if b.done {
		return b.root
	}
	b.done = true
	if b.stem == nil {
		b.Stop()
		return common.Hash{} // nothing added: the empty tree
	}
	b.root = b.closeBelow(-1)
	if b.par != nil {
		b.root = b.par.finish()
	}
	return b.root
}

// Stop ends a parallel builder's goroutines once whatever it was handed has
// been folded. Finish does; a caller giving up on the build must. It does
// nothing on a builder hashing inline, or a second time.
func (b *StackBuilder) Stop() {
	b.done = true
	if b.par != nil {
		b.par.finish()
	}
}

// buildPipeline runs a StackBuilder's hashing on goroutines of its own. A
// stem group's hash needs only the group and its position, so workers hash
// the groups of a batch in parallel; a branch needs its children's hashes,
// so one more goroutine replays the batch's folds in order, over a stack
// mirroring the builder's frames.
type buildPipeline struct {
	b          *StackBuilder
	cur        *buildBatch
	hash, fold chan *buildBatch
	free       chan *buildBatch
	done       chan struct{}
	root       common.Hash
	stopped    bool
	lastKey    int // where the cur batch's arena holds the last key queued
}

// buildBatch is a run of the builder's steps: the groups to hash and the
// folds to replay, with their bytes packed in arena.
type buildBatch struct {
	arena  []byte
	groups []buildGroup
	ops    []buildOp
	out    []byte // the workers' serialized groups
	hashed sync.WaitGroup
}

// span locates bytes in a batch's arena or out.
type span struct{ lo, hi int }

func (s span) of(b []byte) []byte { return b[s.lo:s.hi] }

type buildGroup struct {
	stem, subs, vals span
	pos              int
	hash             common.Hash
	path, blob       span // in out
}

// buildOp is one fold step: take the next group's hash; fold a branch at pos
// splitting on split, the prefix bits taken from key; or push the subtree so
// far as the left child of a new frame.
type buildOp struct {
	kind       byte
	pos, split int
	key        span
}

const (
	opGroup byte = iota
	opBranch
	opPush
)

// buildBatchGroups is how many groups a batch hashes, and buildBatches how
// many batches each worker may have in flight.
const (
	buildBatchGroups = 1024
	buildBatches     = 2
)

func newBuildPipeline(b *StackBuilder, workers int) *buildPipeline {
	n := buildBatches*workers + 2
	p := &buildPipeline{
		b:    b,
		hash: make(chan *buildBatch, n),
		fold: make(chan *buildBatch, n),
		free: make(chan *buildBatch, n),
		done: make(chan struct{}),
	}
	for range n {
		p.free <- new(buildBatch)
	}
	p.cur = <-p.free
	for range workers {
		go p.hashGroups()
	}
	go p.replay()
	return p
}

// group queues the pending stem's group, at pos, and the last key its folds
// read.
func (p *buildPipeline) group(stem, subs, vals []byte, pos int, lastKey []byte) {
	c := p.cur
	g := buildGroup{pos: pos}
	g.stem = p.put(stem)
	g.subs = p.put(subs)
	g.vals = p.put(vals)
	k := p.put(lastKey)
	p.lastKey = k.lo
	c.groups = append(c.groups, g)
	c.ops = append(c.ops, buildOp{kind: opGroup})
}

// put appends b to the batch's arena.
func (p *buildPipeline) put(b []byte) span {
	lo := len(p.cur.arena)
	p.cur.arena = append(p.cur.arena, b...)
	return span{lo, len(p.cur.arena)}
}

// branch queues a fold over the last key group queued.
func (p *buildPipeline) branch(pos, split int) {
	lo := p.lastKey
	p.cur.ops = append(p.cur.ops, buildOp{kind: opBranch, pos: pos, split: split,
		key: span{lo, lo + len(p.b.lastKey)}})
}

// push queues a new frame, and sends the batch once it is full: a batch
// ends between closes, so a group and its folds share one.
func (p *buildPipeline) push() {
	p.cur.ops = append(p.cur.ops, buildOp{kind: opPush})
	if len(p.cur.groups) >= buildBatchGroups {
		p.send()
	}
}

func (p *buildPipeline) send() {
	p.cur.hashed.Add(1)
	p.hash <- p.cur
	p.fold <- p.cur
	p.cur = <-p.free
}

// hashGroups hashes and serializes the groups of the batches it takes.
func (p *buildPipeline) hashGroups() {
	var g groupNode
	serialize := p.b.onNode != nil
	for c := range p.hash {
		c.out = c.out[:0]
		for i := range c.groups {
			j := &c.groups[i]
			stem := j.stem.of(c.arena)
			j.hash = hashGroup(&g, stem, j.subs.of(c.arena), j.vals.of(c.arena), j.pos)
			if serialize {
				lo := len(c.out)
				c.out = appendPath(c.out, stem, j.pos)
				j.path = span{lo, len(c.out)}
				c.out = appendNode(c.out, &g, j.pos)
				j.blob = span{j.path.hi, len(c.out)}
			}
		}
		c.hashed.Done()
	}
}

// replay folds the batches in order, handing every node to onNode.
func (p *buildPipeline) replay() {
	defer close(p.done)
	var (
		cur   common.Hash
		stack []common.Hash
	)
	for c := range p.fold {
		c.hashed.Wait()
		next := 0
		for _, op := range c.ops {
			switch op.kind {
			case opGroup:
				g := &c.groups[next]
				next++
				cur = g.hash
				if p.b.onNode != nil {
					p.b.onNode(g.path.of(c.out), g.hash, g.blob.of(c.out))
				}
			case opBranch:
				left := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				cur = p.b.emitBranch(op.key.of(c.arena), op.pos, op.split, left, cur)
			case opPush:
				stack = append(stack, cur)
			}
		}
		c.arena, c.groups, c.ops = c.arena[:0], c.groups[:0], c.ops[:0]
		p.free <- c
	}
	p.root = cur
}

// finish sends what is queued, waits for every fold and returns the root.
// Later calls return the same.
func (p *buildPipeline) finish() common.Hash {
	if !p.stopped {
		p.stopped = true
		if len(p.cur.ops) > 0 {
			p.send()
		}
		close(p.hash)
		close(p.fold)
		<-p.done
	}
	return p.root
}
