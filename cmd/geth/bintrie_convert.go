// Copyright 2026 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
	"github.com/holiman/uint256"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"
)

// sortBudget is the bytes of records the sorters hold, together, before they
// spill sorted runs to disk: 4 GB, or what a 32-bit int holds.
const sortBudget = min(4096<<20, math.MaxInt)

var (
	tmpDirFlag = &cli.StringFlag{
		Name:  "tmpdir",
		Usage: "Directory for scratch files, the sort spills and a copy of every tree node; needs disk, not tmpfs (default: the OS temp dir)",
	}
	forceFlag = &cli.BoolFlag{
		Name:  "force",
		Usage: "Wipe any existing binary tree state before importing",
	}
	snapshotOutFlag = &cli.StringFlag{
		Name:  "snapshot-out",
		Usage: "File to write the byte-canonical PBT snapshot artifact to (required)",
	}
	preimagesOutFlag = &cli.StringFlag{
		Name:  "preimages-out",
		Usage: "File to write the EIP-8347 preimage file to (required)",
	}
	preimagesInFlag = &cli.StringFlag{
		Name:  "preimages",
		Usage: "EIP-8347 preimage file to take the state's keys from instead of the node's preimage store; it must hold exactly the state's keys",
	}
	workersFlag = &cli.IntFlag{
		Name:  "workers",
		Usage: "Parallel workers: export splits its scan among them by account hash, import its candidate key derivation; the 4 GB sort budget is split among them",
		Value: 4,
	}

	bintrieCommand = &cli.Command{
		Name:        "bintrie",
		Usage:       "A set of commands for binary trie operations",
		Description: "",
		Subcommands: []*cli.Command{
			bintrieImportCommand,
			{
				Name:      "export",
				Usage:     "Write the EIP-8347 distribution artifacts of the MPT state (producers only)",
				ArgsUsage: "[state-root]",
				Action:    exportBinaryTrie,
				Flags: slices.Concat([]cli.Flag{
					tmpDirFlag,
					snapshotOutFlag,
					preimagesOutFlag,
					preimagesInFlag,
					workersFlag,
				}, utils.NetworkFlags, utils.DatabaseFlags),
				Description: `
geth bintrie export --snapshot-out <file> --preimages-out <file> [flags] [state-root]

Writes the EIP-8347 distribution artifacts of the MPT state - the PBT snapshot
and the preimage file - for a producer to publish, and checks them the way a
downloading node will before keeping them. It does not migrate this node: it
writes nothing to the database. A node migrates with "geth bintrie import" or
online with --pbt.import.*.

Defaults to the head root. The addresses and slot keys behind the state's
hashes come from the node's preimage store (--cache.preimages) or from an
EIP-8347 preimage file of the same state (--preimages). The scan runs on
--workers workers.
`,
			},
		},
	}
)

func exportBinaryTrie(ctx *cli.Context) error {
	if ctx.NArg() > 1 {
		return errors.New("too many arguments")
	}
	snapshotPath, preimagePath := ctx.String(snapshotOutFlag.Name), ctx.String(preimagesOutFlag.Name)
	if snapshotPath == "" || preimagePath == "" {
		return errors.New("--snapshot-out and --preimages-out are required")
	}
	if snapshotPath == preimagePath {
		return errors.New("--snapshot-out and --preimages-out must name different files")
	}
	workers := ctx.Int(workersFlag.Name)
	if workers < 1 {
		return errors.New("--workers must be at least 1")
	}
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chaindb := utils.MakeChainDatabase(ctx, stack, true)
	defer chaindb.Close()

	headBlock := rawdb.ReadHeadBlock(chaindb)
	if headBlock == nil {
		return errors.New("no head block found")
	}
	// Past the fork the head commits the binary tree: no merkle state exists
	// at its root.
	if past, err := headCommitsBinaryTree(chaindb, headBlock); err != nil {
		return err
	} else if past {
		return errors.New("the head block commits the binary tree; nothing to export")
	}
	root := headBlock.Root()
	if ctx.NArg() == 1 {
		var err error
		if root, err = parseRoot(ctx.Args().First()); err != nil {
			return fmt.Errorf("invalid state root: %w", err)
		}
	}
	// An empty state has nothing to resolve.
	preimageIn := ctx.String(preimagesInFlag.Name)
	if preimageIn != "" {
		in, err := os.Stat(preimageIn)
		if err != nil {
			return fmt.Errorf("--preimages: %w", err)
		}
		// The outputs are created, and truncated, before the input is read.
		for _, out := range []string{snapshotPath, preimagePath} {
			if fi, err := os.Stat(out); err == nil && os.SameFile(in, fi) {
				return errors.New("--preimages must not name an output file")
			}
		}
	} else if root != types.EmptyRootHash && !hasPreimages(chaindb) {
		return errors.New("no preimages to export from; the source must sync with --cache.preimages, or pass an EIP-8347 preimage file with --preimages")
	}
	log.Info("Exporting EIP-8347 artifacts", "root", root, "block", headBlock.NumberU64())

	srcTriedb := utils.MakeTrieDatabase(ctx, stack, chaindb, true, true, false)
	defer srcTriedb.Close()

	binRoot, err := exportArtifacts(context.Background(), chaindb, srcTriedb, root, conversionOptions{
		sortBudget:   sortBudget,
		tmpDir:       ctx.String(tmpDirFlag.Name),
		snapshotPath: snapshotPath,
		preimagePath: preimagePath,
		workers:      workers,
		preimageIn:   preimageIn,
	})
	if err != nil {
		return err
	}
	log.Info("Export complete", "block", headBlock.NumberU64(), "root", root, "binaryRoot", binRoot)
	return nil
}

// conversionOptions carries the tunables of a conversion run.
type conversionOptions struct {
	sortBudget   int           // total bytes of buffered records before the sorts spill
	tmpDir       string        // spill directory; empty means the OS temp dir
	snapshotPath string        // export: PBT snapshot artifact destination
	preimagePath string        // export: preimage file destination
	anchor       *types.Header // conversion: block committing the converted root, attested with it
	workers      int           // parallel workers; below 1 means one
	preimageIn   string        // EIP-8347 preimage file to resolve keys from; empty reads the node's store
	// beforeAttest, when set, runs once everything is written and verified,
	// right before the attestation: an error leaves the state unattested.
	beforeAttest func() error
}

// conversionStats tracks progress for the periodic report. The message names
// the work, since the converter and the importer share the counters. Every
// method is safe for concurrent use: the converter's scan workers share it.
type conversionStats struct {
	what                           string
	accounts, slots, codes, leaves atomic.Uint64
	start                          time.Time
	lastReport                     atomic.Int64 // unix nanoseconds
}

func newStats(what string) *conversionStats {
	s := &conversionStats{what: what, start: time.Now()}
	s.lastReport.Store(s.start.UnixNano())
	return s
}

// report logs progress, unforced at most every 8 seconds across callers.
func (s *conversionStats) report(force bool) {
	now, last := time.Now().UnixNano(), s.lastReport.Load()
	if !force && (now-last < int64(8*time.Second) || !s.lastReport.CompareAndSwap(last, now)) {
		return
	}
	s.lastReport.Store(now)
	log.Info(s.what, "accounts", s.accounts.Load(), "slots", s.slots.Load(),
		"codes", s.codes.Load(), "leaves", s.leaves.Load(), "elapsed", common.PrettyDuration(time.Since(s.start)))
}

// progressInterval is how often a running phase reports.
var progressInterval = 8 * time.Second

// progress reports one phase of a long command: a line when it starts, then
// its share of a known total and the time left every progressInterval. done
// is called from the reporting goroutine.
type progress struct {
	what   string
	unit   string // the log key for done; "bytes" prints as a size
	total  uint64 // zero when not known up front
	done   func() uint64
	start  time.Time
	quit   chan struct{}
	exited chan struct{}
}

func startProgress(what, unit string, total uint64, done func() uint64) *progress {
	p := &progress{what: what, unit: unit, total: total, done: done, start: time.Now(),
		quit: make(chan struct{}), exited: make(chan struct{})}
	p.report()
	go func() {
		defer close(p.exited)
		tick := time.NewTicker(progressInterval)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				p.report()
			case <-p.quit:
				return
			}
		}
	}()
	return p
}

func (p *progress) report() {
	done, elapsed := p.done(), time.Since(p.start)
	ctx := []any{p.unit, p.amount(done)}
	if p.total > 0 {
		ctx = append(ctx, "total", p.amount(p.total), "progress", fmt.Sprintf("%.2f%%", 100*float64(done)/float64(p.total)))
		if done > 0 && done < p.total {
			ctx = append(ctx, "eta", common.PrettyDuration(time.Duration(float64(elapsed)*float64(p.total-done)/float64(done))))
		}
	}
	log.Info(p.what, append(ctx, "elapsed", common.PrettyDuration(elapsed))...)
}

func (p *progress) amount(n uint64) any {
	if p.unit == "bytes" {
		return common.StorageSize(n)
	}
	return n
}

// stop ends the reports. Later calls do nothing.
func (p *progress) stop() {
	if p.quit != nil {
		close(p.quit)
		<-p.exited
		p.quit = nil
	}
}

// finish ends the reports and logs msg with ctx and the phase's duration.
func (p *progress) finish(msg string, ctx ...any) {
	p.stop()
	log.Info(msg, append(ctx, "elapsed", common.PrettyDuration(time.Since(p.start)))...)
}

// triedbPlan plans a scan of the MPT state at root through a trie database:
// each worker scans its own range of account hashes, resolving keys from the
// node's preimage store or from its own piece of a preimage file. Close the
// returned file, if any, once the scan is done.
func triedbPlan(srcTriedb *triedb.Database, root common.Hash, opts conversionOptions) (scanPlan, io.Closer, error) {
	workers := max(opts.workers, 1)
	plan := scanPlan{ranges: splitHashSpace(workers)}
	var file io.Closer = io.NopCloser(nil)
	if opts.preimageIn != "" {
		f, ranges, pieces, err := splitPreimages(opts.preimageIn, workers)
		if err != nil {
			return scanPlan{}, nil, err
		}
		file, plan.ranges = f, ranges
		for _, piece := range pieces {
			plan.keys = append(plan.keys, &fileKeys{r: piece})
		}
	} else {
		for range plan.ranges {
			plan.keys = append(plan.keys, storeKeys{srcTriedb})
		}
	}
	src := triedbSource{srcTriedb, root, srcTriedb.Scheme() == rawdb.PathScheme && srcTriedb.SnapshotCompleted()}
	for range plan.ranges {
		plan.sources = append(plan.sources, src)
	}
	return plan, file, nil
}

// scanPlan is what a conversion scans: per worker, a range of account
// hashes, the source to read it from and the keys behind its hashes.
type scanPlan struct {
	ranges  []hashRange
	sources []leafSource
	keys    []keySource
	release func() // frees the sources once the scan is done, if they hold anything
}

// splitPreimages opens a preimage file and cuts it into at most n pieces of
// about equal bytes on record boundaries, returning each piece's reader and
// the range of account hashes it covers: the work splits by data volume, and
// a small file may make fewer pieces than workers.
func splitPreimages(path string, n int) (*os.File, []hashRange, []*preimageReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	offsets, starts, err := splitPreimageFile(f, info.Size(), n)
	if err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	ranges, pieces := make([]hashRange, len(offsets)), make([]*preimageReader, len(offsets))
	for i := range offsets {
		end := info.Size()
		if i+1 < len(offsets) {
			end = offsets[i+1]
			ranges[i].end = starts[i+1]
		}
		ranges[i].start = starts[i]
		pieces[i] = preimagePiece(f, offsets[i], end-offsets[i])
	}
	return f, ranges, pieces, nil
}

// exportArtifacts writes the EIP-8347 distribution artifacts of the MPT state
// at root, the PBT snapshot and the preimage file, for a producer to publish,
// and checks them as a downloading node does: a verify-only import, check 1
// and check 2 over the bytes written. It writes nothing to the database; the
// node it runs on is not migrated.
func exportArtifacts(ctx context.Context, chaindb ethdb.Database, srcTriedb *triedb.Database, root common.Hash, opts conversionOptions) (common.Hash, error) {
	plan, file, err := triedbPlan(srcTriedb, root, opts)
	if err != nil {
		return common.Hash{}, err
	}
	defer file.Close()
	snapshot, err := newSnapshotWriter(opts.snapshotPath)
	if err != nil {
		return common.Hash{}, err
	}
	defer func() {
		if snapshot != nil {
			snapshot.abort()
		}
	}()
	preimages, err := newPreimageFile(opts.preimagePath)
	if err != nil {
		return common.Hash{}, err
	}
	defer func() {
		if preimages != nil {
			preimages.abort()
		}
	}()
	stats := newStats("Exporting state")
	stream, closeScan, err := scanState(ctx, chaindb, plan, preimages, nil, opts, stats)
	if err != nil {
		return common.Hash{}, err
	}
	defer closeScan()

	// The snapshot is the sorted leaves, and its trailer commits the root
	// they build to; no tree node is kept.
	var written atomic.Uint64
	prog := startProgress("Writing PBT snapshot", "leaves", stats.leaves.Load(), written.Load)
	defer prog.stop()
	builder := bintrie.NewParallelStackBuilder(nil, opts.workers)
	defer builder.Stop()
	for {
		key, value, err := stream.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return common.Hash{}, err
		}
		if err := snapshot.add(key, value); err != nil {
			return common.Hash{}, err
		}
		if err := builder.Add(key, value); err != nil {
			return common.Hash{}, err
		}
		written.Add(1)
	}
	binRoot := builder.Finish()
	prog.finish("Wrote PBT snapshot leaves", "leaves", written.Load(), "binaryRoot", binRoot)
	snapDigest, err := snapshot.finalize(binRoot)
	if err != nil {
		return common.Hash{}, err
	}
	preDigest, err := preimages.finalize()
	if err != nil {
		return common.Hash{}, err
	}
	if _, err := importState(ctx, chaindb, importOptions{snapshot: opts.snapshotPath, preimages: opts.preimagePath,
		anchor: &types.Header{Root: root}, verifyOnly: true, conversionOptions: opts}); err != nil {
		return common.Hash{}, err
	}
	log.Info("Wrote PBT snapshot artifact", "path", opts.snapshotPath, "leaves", snapshot.count, "digest", snapDigest)
	log.Info("Wrote preimage file", "path", opts.preimagePath, "accounts", preimages.accounts, "digest", preDigest)
	snapshot, preimages = nil, nil // verified: keep them
	return binRoot, nil
}

// convertPlan converts the state at opts.anchor's root over plan into the
// binary tree namespace per EIP-8347, the self-converter's way: one scan,
// split by account hash across workers, derives every leaf, folds the merkle
// state back from those leaves and writes the flat state (see selfCheck); an
// external sort orders the leaves in tree-key order, the tree is built
// bottom-up from them in one pass, and it must hold exactly the leaves the
// scan derived. Check 1 has no claim to check: the build is the tree. The
// attestation lands last, so an interrupted run refuses to open. Cancelling
// ctx stops it between batches, before anything is attested.
func convertPlan(ctx context.Context, chaindb ethdb.Database, plan scanPlan, opts conversionOptions) (common.Hash, error) {
	if plan.release != nil {
		defer plan.release()
	}
	// A non-virgin namespace, completed or debris, is wiped first by whoever
	// owns it.
	if dirty, err := hasBinaryTrieState(chaindb); err != nil {
		return common.Hash{}, err
	} else if dirty {
		return common.Hash{}, errors.New("binary tree namespace is not empty")
	}
	// The flat state is digested per scan range, which its writers fill
	// side by side.
	written := newWrittenState()
	var starts [][]byte
	for _, r := range plan.ranges[1:] {
		starts = append(starts, r.start[:])
	}
	written.accounts, written.storage = newFamilyDigest(starts...), newFamilyDigest(starts...)
	checks := make([]*selfCheck, len(plan.ranges))
	defer func() {
		for _, c := range checks {
			if c != nil {
				c.close()
			}
		}
	}()
	for i := range checks {
		var err error
		if checks[i], err = newSelfCheck(chaindb, opts.tmpDir, written, i); err != nil {
			return common.Hash{}, err
		}
	}
	stats := newStats("Converting state")
	stream, closeScan, err := scanState(ctx, chaindb, plan, nil, checks, opts, stats)
	if err != nil {
		return common.Hash{}, err
	}
	defer closeScan()
	var emitted leafSum
	for _, c := range checks {
		if err := c.finish(); err != nil {
			return common.Hash{}, err
		}
		emitted.merge(&c.sum)
	}
	// The account trie folds while the tree builds.
	var (
		folded          common.Hash
		fold, readNodes errgroup.Group
	)
	// Background work ends with this call, however it ends.
	bctx, cancel := context.WithCancel(ctx)
	defer fold.Wait()
	defer readNodes.Wait()
	defer cancel()
	fold.Go(func() (err error) {
		folded, err = foldSpilledAccounts(bctx, checks, stats.accounts.Load())
		return err
	})
	root, nodes, err := buildOwnTree(ctx, chaindb, streamLeaves{stream}, &emitted, opts)
	if err != nil {
		return common.Hash{}, err
	}
	written.nodes = nodes
	pbtdb := rawdb.NewTable(chaindb, string(rawdb.PBTPrefix))
	readNodes.Go(func() error { return verifyWritten(bctx, pbtdb, opts.workers, written.families()[0]) })
	if err := fold.Wait(); err != nil {
		return common.Hash{}, err
	}
	if folded != opts.anchor.Root {
		return common.Hash{}, fmt.Errorf("the leaves re-derive merkle root %x, the anchor commits %x", folded, opts.anchor.Root)
	}
	log.Info("Verified consensus anchoring", "stateRoot", folded, "accounts", stats.accounts.Load(), "slots", stats.slots.Load())
	if err := verifyWritten(ctx, pbtdb, opts.workers, written.families()[1:]...); err != nil {
		return common.Hash{}, err
	}
	if err := readNodes.Wait(); err != nil {
		return common.Hash{}, err
	}
	logWritten(written)
	if err := attestTree(ctx, pbtdb, root, opts.anchor, opts.beforeAttest); err != nil {
		return common.Hash{}, err
	}
	return root, nil
}

// scanState runs plan's scan, each worker over its range into a sorter of its
// own, and merges the leaves they derived in tree-key order. preimages, when
// set, receives the preimage file in scan order; checks, when set, each run
// the matching worker's share of a self-converter's dual-check. closeAll
// releases the sorters once the stream is drained.
func scanState(ctx context.Context, chaindb ethdb.Database, plan scanPlan, preimages *preimageFile, checks []*selfCheck, opts conversionOptions, stats *conversionStats) (stream *bintrie.RecordStream, closeAll func(), err error) {
	workers := len(plan.ranges)
	// A worker's sorter is alive throughout, and a sealed one keeps its
	// buffer while its stream drains, so the budget is split rather than
	// reused.
	share := splitBudget(opts.sortBudget, workers)
	parts := make([]scanPart, workers)
	closeParts := func() {
		for _, p := range parts {
			if p.leaves != nil {
				p.leaves.Close()
			}
		}
	}
	defer func() {
		if err != nil {
			closeParts()
		}
	}()
	for i, r := range plan.ranges {
		parts[i] = scanPart{hashRange: r, leaves: bintrie.NewLeafSorter(opts.tmpDir, share)}
		if checks != nil {
			parts[i].check = checks[i]
		}
	}
	// Every worker writes its range of the preimage file: the first straight
	// into it, the others into fragments joined after it.
	writers := make([]*preimageFile, workers)
	writers[0] = preimages
	if preimages != nil {
		for i := 1; i < workers; i++ {
			frag, err := newPreimageFragment(opts.tmpDir)
			if err != nil {
				return nil, nil, err
			}
			defer frag.abort()
			writers[i] = frag
		}
	}
	codes := newCodeSet()
	g, gctx := errgroup.WithContext(ctx)
	for i := range parts {
		g.Go(func() error {
			return deriveLeaves(gctx, chaindb, plan.sources[i], &parts[i], plan.keys[i], codes, writers[i], stats)
		})
	}
	if err := g.Wait(); err != nil {
		return nil, nil, err
	}
	// Nothing reads the source past the scan.
	if plan.release != nil {
		plan.release()
	}
	if preimages != nil {
		if err := preimages.join(writers[1:]); err != nil {
			return nil, nil, err
		}
	}
	stats.report(true)

	// One merge serves every worker's records.
	sorter := parts[0].leaves
	for _, p := range parts[1:] {
		if err := sorter.Absorb(p.leaves); err != nil {
			return nil, nil, err
		}
	}
	if stream, err = sorter.Sort(); err != nil {
		return nil, nil, err
	}
	return stream, closeParts, nil
}

// leafSource yields the source state's accounts from a seek hash on, then
// each account's storage, in keccak order, as RLP the way the state stores
// it. Whatever the source, check 2 authenticates the leaves derived from the
// scan against the root.
type leafSource interface {
	accounts(seek common.Hash) (pathdb.AccountIterator, error)
	storage(accountHash, storageRoot common.Hash) (pathdb.StorageIterator, error)
}

// triedbSource reads the state at root through a trie database. flat reads
// pathdb's flat state, which its iterators allow only once complete;
// otherwise the trie nodes are walked: a hash-scheme source, or a pathdb
// still syncing or generating.
type triedbSource struct {
	db   *triedb.Database
	root common.Hash
	flat bool // flat accounts are slim RLP, trie leaves full RLP
}

func (s triedbSource) accounts(seek common.Hash) (pathdb.AccountIterator, error) {
	if s.flat {
		return s.db.AccountIterator(s.root, seek)
	}
	return s.walk(trie.StateTrieID(s.root), seek[:])
}

func (s triedbSource) storage(accountHash, storageRoot common.Hash) (pathdb.StorageIterator, error) {
	if s.flat {
		return s.db.StorageIterator(s.root, accountHash, common.Hash{})
	}
	return s.walk(trie.StorageTrieID(s.root, accountHash, storageRoot), nil)
}

func (s triedbSource) walk(id *trie.ID, start []byte) (*trieLeafIterator, error) {
	tr, err := trie.New(id, s.db)
	if err != nil {
		return nil, err
	}
	it, err := tr.NodeIterator(start)
	if err != nil {
		return nil, err
	}
	return &trieLeafIterator{trie.NewIterator(it)}, nil
}

// trieLeafIterator adapts a trie leaf iterator to both flat iterator shapes.
type trieLeafIterator struct{ it *trie.Iterator }

func (t *trieLeafIterator) Next() bool        { return t.it.Next() }
func (t *trieLeafIterator) Error() error      { return t.it.Err }
func (t *trieLeafIterator) Hash() common.Hash { return common.BytesToHash(t.it.Key) }
func (t *trieLeafIterator) Release()          {}
func (t *trieLeafIterator) Account() []byte   { return t.it.Value }
func (t *trieLeafIterator) Slot() []byte      { return t.it.Value }

// hashRange is one worker's share of the account hashes, [start, end); the
// zero end stands for the top of the hash space.
type hashRange struct {
	start, end common.Hash
}

// past reports whether hash lies beyond the range, in the next one.
func (r hashRange) past(hash common.Hash) bool {
	return r.end != (common.Hash{}) && hash.Cmp(r.end) >= 0
}

// splitHashSpace splits the account hashes into n ascending ranges of equal
// width. Hashes are uniform, so the ranges hold about equal state, bar one
// outsized contract's storage.
func splitHashSpace(n int) []hashRange {
	width := new(uint256.Int).Div(new(uint256.Int).SetAllOne(), uint256.NewInt(uint64(n)))
	ranges := make([]hashRange, n)
	for i := range ranges {
		ranges[i].start = new(uint256.Int).Mul(width, uint256.NewInt(uint64(i))).Bytes32()
		if i > 0 {
			ranges[i-1].end = ranges[i].start
		}
	}
	return ranges
}

// splitBudget divides a sort budget among n sorters. A positive budget stays
// positive: a non-positive one never spills.
func splitBudget(budget, n int) int {
	if budget <= 0 {
		return budget
	}
	return max(budget/n, 1)
}

// scanPart is one scan worker's share: its range of account hashes, the
// sorter it derives into and, for a self-converter, its share of the check.
type scanPart struct {
	hashRange
	leaves *bintrie.RecordSorter
	check  *selfCheck
}

// codeInfo is what an account header needs of its code: the size, and the
// designator when the code is an EIP-7702 delegation.
type codeInfo struct {
	size       uint32
	delegation []byte
}

// codeSet caches each distinct code's info across the scan workers, so the
// store is read once per code, and lets one worker emit its chunks: a chunk
// emitted twice is a duplicate key.
type codeSet struct {
	mu   sync.Mutex
	seen map[common.Hash]codeInfo
}

func newCodeSet() *codeSet {
	return &codeSet{seen: make(map[common.Hash]codeInfo)}
}

// lookup returns the info of a code already met.
func (s *codeSet) lookup(hash common.Hash) (codeInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.seen[hash]
	return info, ok
}

// claim records hash and its info and reports whether it was new: of all
// callers claiming one hash, exactly one wins.
func (s *codeSet) claim(hash common.Hash, info codeInfo) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[hash]; ok {
		return false
	}
	s.seen[hash] = info
	return true
}

// keySource resolves one scan worker's hashed keys to the addresses and slot
// keys behind them, in scan order.
type keySource interface {
	account(hash common.Hash) (common.Address, error)
	slot(addr common.Address, hash common.Hash) (common.Hash, error)
	// done rejects anything the source holds for addr beyond the slots the
	// scan resolved; close, anything left once the worker's range is done.
	done(addr common.Address) error
	close() error
}

// storeKeys looks keys up in the node's preimage store, which may hold more
// than the state, as EIP-8347 allows.
type storeKeys struct{ db *triedb.Database }

func (s storeKeys) account(hash common.Hash) (common.Address, error) {
	preimage := s.db.Preimage(hash)
	if preimage == nil {
		return common.Address{}, fmt.Errorf("missing preimage for account hash %x (the source node must have synced with --cache.preimages, or pass --preimages)", hash)
	}
	if err := checkPreimage(preimage, hash, common.AddressLength); err != nil {
		return common.Address{}, err
	}
	return common.BytesToAddress(preimage), nil
}

func (s storeKeys) slot(addr common.Address, hash common.Hash) (common.Hash, error) {
	preimage := s.db.Preimage(hash)
	if preimage == nil {
		return common.Hash{}, fmt.Errorf("missing preimage for storage key %x (account %x)", hash, addr)
	}
	if err := checkPreimage(preimage, hash, common.HashLength); err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(preimage), nil
}

func (storeKeys) done(common.Address) error { return nil }
func (storeKeys) close() error              { return nil }

// fileKeys merges one piece of an EIP-8347 preimage file against the
// worker's scan range, as the EIP's converter step 2 does: both run in keccak
// order, so each record must match the next account and each slot key the
// next slot. The reader hashes every key, which proves the preimages.
type fileKeys struct {
	r     *preimageReader
	slots []common.Hash
	next  int
}

func (f *fileKeys) account(hash common.Hash) (common.Address, error) {
	addr, addrHash, slots, err := f.r.next()
	switch {
	case err == io.EOF:
		return common.Address{}, fmt.Errorf("missing preimage for account hash %x: the preimage file holds no record for it", hash)
	case err != nil:
		return common.Address{}, err
	case addrHash == hash:
		f.slots, f.next = slots, 0
		return addr, nil
	case bytes.Compare(addrHash[:], hash[:]) < 0:
		return common.Address{}, fmt.Errorf("preimage file names address %x, which the state does not hold", addr)
	default:
		return common.Address{}, fmt.Errorf("missing preimage for account hash %x: the preimage file holds no record for it", hash)
	}
}

func (f *fileKeys) slot(addr common.Address, hash common.Hash) (common.Hash, error) {
	if f.next < len(f.slots) && f.r.slotHashes[f.next] == hash {
		f.next++
		return f.slots[f.next-1], nil
	}
	if f.next < len(f.slots) && bytes.Compare(f.r.slotHashes[f.next][:], hash[:]) < 0 {
		return common.Hash{}, fmt.Errorf("preimage file names slot %x of %x, which the state does not hold", f.slots[f.next], addr)
	}
	return common.Hash{}, fmt.Errorf("missing preimage for storage key %x (account %x)", hash, addr)
}

func (f *fileKeys) done(addr common.Address) error {
	if f.next < len(f.slots) {
		return fmt.Errorf("preimage file names slot %x of %x, which the state does not hold", f.slots[f.next], addr)
	}
	return nil
}

func (f *fileKeys) close() error {
	addr, _, _, err := f.r.next()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("preimage file names address %x, which the state does not hold", addr)
}

// deriveLeaves scans part's range of the source state at root, deriving
// every tree leaf into the part's sorter and handing it to the part's check,
// if any. It gives up once ctx is cancelled, by another worker failing.
func deriveLeaves(ctx context.Context, chaindb ethdb.Database, src leafSource, part *scanPart, keys keySource, codes *codeSet, preimages *preimageFile, stats *conversionStats) error {
	// ponytail: an export's flat scan holds one pebble read snapshot per
	// worker throughout, pinning a memtable and every table compacted
	// meanwhile. Reopen from the last hash every 30s, as pathdb's index pruner
	// does, if producer RAM or disk gets tight.
	accIter, err := src.accounts(part.start)
	if err != nil {
		return fmt.Errorf("failed to open source accounts: %w", err)
	}
	defer accIter.Release()
	// The current account's counts, published to stats with it.
	var leaves, slots uint64
	emit := func(key []byte, value [32]byte) error {
		// Zero values resolve to absence and are never written.
		if value == ([32]byte{}) {
			return nil
		}
		leaves++
		if part.check != nil {
			part.check.leaf(key, value)
		}
		return part.leaves.Add(key, value[:])
	}
	// scanStorage derives one account's slots; the deferred release keeps
	// the iterator from leaking on any error path.
	scanStorage := func(accountHash common.Hash, addr common.Address, storageRoot common.Hash) error {
		storageIter, err := src.storage(accountHash, storageRoot)
		if err != nil {
			return fmt.Errorf("failed to open storage for %x: %w", addr, err)
		}
		defer storageIter.Release()
		for storageIter.Next() {
			slotHash := storageIter.Hash()
			slotKey, err := keys.slot(addr, slotHash)
			if err != nil {
				return err
			}
			if preimages != nil {
				if err := preimages.addSlot(slotKey, slotHash); err != nil {
					return err
				}
			}
			slotVal := storageIter.Slot()
			_, content, rest, err := rlp.Split(slotVal)
			if err != nil {
				return fmt.Errorf("invalid storage RLP for key %x (account %x): %w", slotKey, addr, err)
			}
			if len(rest) != 0 || len(content) > 32 {
				return fmt.Errorf("malformed storage value for key %x (account %x)", slotKey, addr)
			}
			var padded [32]byte
			copy(padded[32-len(content):], content)
			if err := emit(bintrie.StorageSlotKey(addr, slotKey[:]), padded); err != nil {
				return err
			}
			// A zero slot emits no leaf, so the merkle state folds none.
			if part.check != nil && padded != ([32]byte{}) {
				part.check.slot(accountHash, slotHash, padded)
			}
			slots++
		}
		if err := storageIter.Error(); err != nil {
			return fmt.Errorf("storage iteration failed for %x: %w", addr, err)
		}
		return nil
	}
	for accIter.Next() {
		accountHash := accIter.Hash()
		if part.past(accountHash) {
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// Full and slim account RLP both decode here.
		acc, err := types.FullAccount(accIter.Account())
		if err != nil {
			return fmt.Errorf("invalid account RLP: %w", err)
		}
		addr, err := keys.account(accountHash)
		if err != nil {
			return err
		}
		if preimages != nil {
			if err := preimages.beginAccount(addr, accountHash); err != nil {
				return err
			}
		}

		if err := emitAccountHeader(chaindb, addr, acc.Nonce, acc.Balance, common.BytesToHash(acc.CodeHash), codes, stats, emit); err != nil {
			return err
		}
		if acc.Root != types.EmptyRootHash {
			if err := scanStorage(accountHash, addr, acc.Root); err != nil {
				return err
			}
		}
		if part.check != nil {
			part.check.account(accountHash)
		}
		if err := keys.done(addr); err != nil {
			return err
		}
		stats.accounts.Add(1)
		stats.slots.Add(slots)
		stats.leaves.Add(leaves)
		leaves, slots = 0, 0
		stats.report(false)
	}
	if err := accIter.Error(); err != nil {
		return fmt.Errorf("account iteration failed: %w", err)
	}
	return keys.close()
}

// checkPreimage rejects a preimage of the wrong length or one that does not
// hash back to its key: the store has no integrity of its own, and a corrupt
// entry would convert into a wrong-stem tree.
func checkPreimage(preimage []byte, hash common.Hash, wantLen int) error {
	if len(preimage) != wantLen {
		return fmt.Errorf("corrupt preimage for %x: %d bytes, want %d", hash, len(preimage), wantLen)
	}
	if crypto.Keccak256Hash(preimage) != hash {
		return fmt.Errorf("corrupt preimage for %x: value hashes to %x", hash, crypto.Keccak256(preimage))
	}
	return nil
}

// emitAccountHeader derives an account's header and code-zone leaves; the
// derivation rules stay pinned by the reference-vector parity tests.
func emitAccountHeader(chaindb ethdb.Database, addr common.Address, nonce uint64, balance *uint256.Int, codeHash common.Hash, codes *codeSet, stats *conversionStats, emit func([]byte, [32]byte) error) error {
	var (
		info  codeInfo
		code  []byte
		first bool // this account's code is new to the scan, and its chunks this worker's to emit
	)
	if codeHash != types.EmptyCodeHash {
		var known bool
		if info, known = codes.lookup(codeHash); !known {
			code = rawdb.ReadCode(chaindb, codeHash)
			if code == nil {
				return fmt.Errorf("missing code for hash %x (account %x)", codeHash, addr)
			}
			info.size = uint32(len(code))
			if _, isDelegation := types.ParseDelegation(code); isDelegation {
				info.delegation = code
			}
			first = codes.claim(codeHash, info)
		}
	}
	basic, err := bintrie.EncodeBasicData(info.size, nonce, balance)
	if err != nil {
		return fmt.Errorf("account %x: %w", addr, err)
	}
	if err := emit(bintrie.BasicDataKey(addr), basic); err != nil {
		return err
	}
	// A delegation replaces the code-hash leaf and has no code-zone leaves.
	if info.delegation != nil {
		return emit(bintrie.DelegationKey(addr), [32]byte(bintrie.EncodeDelegation(info.delegation)))
	}
	if err := emit(bintrie.CodeHashKey(addr), codeHash); err != nil {
		return err
	}
	// Code once per distinct hash: the leaves are content-addressed.
	if first && info.size > 0 {
		stats.codes.Add(1)
		return emitCodeChunks(codeHash, code, emit)
	}
	return nil
}

// emitCodeChunks derives one bytecode's code-zone leaves; all-zero chunks
// resolve to absence and are skipped. The code store has no integrity of its
// own, so the leaves must reassemble into code that hashes to codeHash: the
// code limb of the dual-check, on the leaves as they are emitted.
func emitCodeChunks(codeHash common.Hash, code []byte, emit func([]byte, [32]byte) error) error {
	var (
		chunks  = bintrie.ChunkifyCode(code)
		emitted []bintrie.IndexedChunk
	)
	for i := range len(chunks) / 32 {
		var chunk [32]byte
		copy(chunk[:], chunks[32*i:32*(i+1)])
		if chunk != ([32]byte{}) {
			emitted = append(emitted, bintrie.IndexedChunk{Index: uint64(i), Chunk: chunk})
		}
		if err := emit(bintrie.CodeChunkKey(codeHash, uint64(i)), chunk); err != nil {
			return err
		}
	}
	_, err := bintrie.AssembleCode(codeHash, uint32(len(code)), emitted)
	return err
}

// hasBinaryTrieState reports whether anything sits in the binary tree
// namespace. Probed per key family: the bare prefix is shared with block
// bodies.
func hasBinaryTrieState(chaindb ethdb.Database) (bool, error) {
	pbtdb := rawdb.NewTable(chaindb, string(rawdb.PBTPrefix))
	for _, family := range rawdb.PBTKeyFamilies {
		it := pbtdb.NewIterator(family, nil)
		found := it.Next()
		err := it.Error()
		it.Release()
		if err != nil {
			// Unreadable is not clean.
			return false, fmt.Errorf("failed to probe the binary tree namespace: %w", err)
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}

// wipeBinaryTrieState clears the binary tree state: the key families (the
// bare prefix is shared with block bodies), the PBT history freezers, and
// the journal file in triedbDir. Nothing may hold the namespace open.
func wipeBinaryTrieState(chaindb ethdb.Database, triedbDir string) error {
	// Anchor, then bookkeeping, then state: any crash prefix leaves state the
	// follower refuses, never an anchor or a position it would bind to it.
	rawdb.DeletePBTAnchor(rawdb.NewTable(chaindb, string(rawdb.PBTPrefix)))
	if err := rawdb.WipeMigrationState(chaindb); err != nil {
		return err
	}
	if err := rawdb.DeletePBTState(chaindb, nil); err != nil {
		return err
	}
	if ancient, err := chaindb.AncientDatadir(); err == nil {
		for _, open := range []func(string, bool, bool) (ethdb.ResettableAncientStore, error){
			rawdb.NewStateFreezer,
			rawdb.NewTrienodeFreezer,
		} {
			store, err := open(ancient, true, false)
			if err != nil {
				return err
			}
			err = store.Reset()
			store.Close()
			if err != nil {
				return err
			}
		}
	}
	if triedbDir != "" {
		if err := os.Remove(filepath.Join(triedbDir, "pbt.journal")); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	log.Info("Wiped binary tree state")
	return nil
}

// headCommitsBinaryTree reports whether head is past the fork, where the
// binary tree namespace holds the node's live state.
func headCommitsBinaryTree(chaindb ethdb.Database, head *types.Block) (bool, error) {
	stored := rawdb.ReadChainConfig(chaindb, rawdb.ReadCanonicalHash(chaindb, 0))
	if stored == nil {
		return false, errors.New("no chain config stored for the genesis block")
	}
	return stored.IsBinaryTrie(head.Number(), head.Time()), nil
}

// hasPreimages reports whether the preimage store holds anything.
func hasPreimages(chaindb ethdb.Database) bool {
	it := preimageKeys(chaindb)
	defer it.Release()
	return it.Next()
}

// preimageKeys iterates the preimage store: hash-length keys under its prefix.
func preimageKeys(chaindb ethdb.Database) ethdb.Iterator {
	return rawdb.NewKeyLengthIterator(chaindb.NewIterator(rawdb.PreimagePrefix, nil), len(rawdb.PreimagePrefix)+common.HashLength)
}
