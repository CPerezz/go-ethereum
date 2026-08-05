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

package core

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"maps"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/program"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/trie/bintrie"
)

// The witness pins in pbt_capabilities_test.go all cover blocks that read and
// write. None of them delete, and deletion is where the tree does its most
// shape-dependent work:
//
//   - DeleteAccount drops the whole overflow bucket through DeletePrefix, whose
//     deleteSubtree recurses into both children of every branch and resolves
//     every hashed node it meets, with no early exit.
//   - Emptying a branch makes collapse resolve its sibling, and a multi-value
//     group sibling has to be re-folded at its new stored depth, which needs
//     all of its values rather than a stub.
//
// Neither set of nodes is predictable from the keys a block touched: they
// follow the shape of the state that was already there. A witness whose
// coverage were derived from a key set would lose them. The node-set witness
// that shipped should not, because it records what execution actually
// resolved, and the prover walks the same nodes the verifier will. These tests
// exist to make that argument testable rather than merely plausible.
//
// What is covered, and what is not:
//
//   - Collapse with a single-value group or a branch as the survivor is
//     covered below. Those are the cheap arms - a single-value group hashes
//     the same wherever it sits, so a collapse just moves it.
//   - Collapse with a *multi-value* group as the survivor, the second bullet
//     above and the more interesting half, is NOT covered. Building it needs
//     slots sharing one stem, and doing so trips a bug in the deletion path
//     that predates this file: an emptied group can stay reachable and the
//     replay panics folding it. See TODO.md; the fixture is written and lands
//     with the fix.
//   - A subtree walk over a populated bucket is never needed by a block that
//     is valid. See TestPBTBucketDeletionIsUnreachableFromBlocks: StateDB
//     refuses to wipe storage from Cancun onwards. The walk itself does run -
//     deletion happens in IntermediateRoot and the refusal comes later, in
//     commit - but the block carrying it is rejected.
//   - A standalone HasPrefix emptiness probe is never reached: EIP-7610
//     rejects deployments from a hardcoded per-chain address list rather than
//     by asking whether an account holds storage (core/vm/eip7610.go, and the
//     note on StateDB.HasStorage). DeleteAccount does consult a bucket
//     locator, but through delPrefix rather than findPrefix, and in the one
//     test that reaches it the locator diverges immediately and resolves
//     nothing.

// pbtStorageSlots is a spread of slot numbers at and above HeaderStorageOffset
// (64), so they land in the overflow bucket rather than in the account's
// header stem. The spread is wide enough that they occupy several stems.
func pbtStorageSlots(n int) []uint64 {
	slots := make([]uint64, n)
	for i := range slots {
		slots[i] = bintrie.HeaderStorageOffset + uint64(i)*0x10001
	}
	return slots
}

// pbtZeroingCode returns runtime code that stores zero into every listed slot,
// which is how a slot is deleted: the tree keeps no distinction between a slot
// holding zero and a slot that is absent.
func pbtZeroingCode(slots []uint64) []byte {
	p := program.New()
	for _, slot := range slots {
		p.Sstore(slot, 0)
	}
	return p.Bytes()
}

// pbtPadGenesis adds accounts so the tree has branches for a deletion to walk
// through. Without it a one-transaction test chain holds barely more than the
// sender and the coinbase, the whole state folds into a single group record,
// and a test that means to exercise the deletion path resolves one node and
// proves nothing.
func pbtPadGenesis(genesis *Genesis, n int) {
	for i := range n {
		var addr common.Address
		binary.BigEndian.PutUint64(addr[:8], uint64(i)+1)
		addr[19] = 0xad
		genesis.Alloc[addr] = types.Account{Balance: big.NewInt(int64(i) + 1)}
	}
}

// pbtPrefilledStorage turns slot numbers into a genesis storage map.
func pbtPrefilledStorage(slots []uint64) map[common.Hash]common.Hash {
	storage := make(map[common.Hash]common.Hash, len(slots))
	for i, slot := range slots {
		storage[common.BigToHash(new(big.Int).SetUint64(slot))] = common.BigToHash(big.NewInt(int64(i) + 1))
	}
	return storage
}

// pbtWitnessedBlock generates a one-block binary tree chain over the given
// genesis, processes it with witness gathering, and returns the chain, the
// block and the witness.
func pbtWitnessedBlock(t *testing.T, genesis *Genesis, gen func(int, *BlockGen)) (*BlockChain, *types.Block, *stateless.Witness) {
	t.Helper()

	engine := beacon.New(ethash.NewFaker())
	db, blocks, _ := GenerateChainWithGenesis(genesis, engine, 1, gen)
	chain, err := NewBlockChain(db, genesis, engine, DefaultConfig().WithStateScheme(rawdb.PathScheme))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)

	parent := chain.GetHeaderByNumber(0)
	res, err := chain.ProcessBlock(context.Background(), parent.Root, blocks[0], ExecuteConfig{MakeWitness: true})
	if err != nil {
		t.Fatalf("processing the block: %v", err)
	}
	witness := res.Witness()
	if witness == nil || len(witness.Nodes) == 0 {
		t.Fatal("the witness holds no nodes")
	}
	return chain, blocks[0], witness
}

// assertPBTWitnessSufficient replays the block from the witness alone and
// requires the state root to match. It then drops each node in turn and
// requires the replay to be refused, which is what separates "the witness
// happened to contain enough" from "nothing in it was spare".
//
// minNodes guards against the fixture quietly going trivial: a one-transaction
// chain over a bare genesis folds into a single group record, and every
// assertion below still passes over it. It says nothing about whether any
// deletion ran - each caller pins that separately, by asserting on the state
// the block was supposed to change.
func assertPBTWitnessSufficient(t *testing.T, chain *BlockChain, block *types.Block, witness *stateless.Witness, minNodes int) {
	t.Helper()

	if len(witness.Nodes) < minNodes {
		t.Fatalf("witness holds %d nodes, want at least %d: the fixture is too small to exercise anything",
			len(witness.Nodes), minNodes)
	}
	header := types.CopyHeader(block.Header())
	header.Root, header.ReceiptHash = common.Hash{}, common.Hash{}
	task := types.NewBlockWithHeader(header).WithBody(*block.Body())

	stateRoot, _, err := ExecuteStateless(context.Background(), chain.Config(), vm.Config{}, task, witness)
	if err != nil {
		t.Fatalf("stateless execution failed: %v", err)
	}
	if stateRoot != block.Root() {
		t.Fatalf("stateless state root mismatch: got %x, want %x", stateRoot, block.Root())
	}
	if testing.Short() {
		return
	}
	for _, path := range slices.Sorted(maps.Keys(witness.Nodes)) {
		holed := witness.Copy()
		delete(holed.Nodes, path)

		root, _, err := ExecuteStateless(context.Background(), chain.Config(), vm.Config{}, task, holed)
		if err == nil {
			t.Fatalf("witness without the node at path %x still executed, returning root %x", path, root)
		}
	}
}

// pbtCallTx returns a generator sending a zero-value call to target, which is
// enough to touch it without changing its balance.
func pbtCallTx(t *testing.T, key *ecdsa.PrivateKey, sender, target common.Address) func(int, *BlockGen) {
	t.Helper()

	return func(i int, gen *BlockGen) {
		signer := gen.Signer()
		tx, err := types.SignTx(types.NewTransaction(
			gen.TxNonce(sender), target, new(big.Int), pbtCodeBlockGas/2,
			new(big.Int).Add(gen.BaseFee(), common.Big1), nil,
		), signer, key)
		if err != nil {
			t.Fatal(err)
		}
		gen.AddTx(tx)
	}
}

// TestPBTBucketDeletionIsUnreachableFromBlocks records why the hard case this
// file was written for cannot be built, which is a better answer than a test
// that skips.
//
// deleteSubtree walking a populated overflow bucket needs an account that owns
// committed storage and then gets deleted. After EIP-6780 a selfdestruct only
// destroys an account created in the same transaction, whose storage was never
// committed. The one route left is EIP-161, whose emptiness test is nonce,
// balance and code and says nothing about storage -- but StateDB refuses that
// outright from Cancun onwards, on the grounds that no such account survives
// (see the noStorageWiping argument to Commit).
//
// The walk is not skipped, only wasted: deletion runs in IntermediateRoot and
// the refusal comes later, in commit. But the block carrying it is rejected,
// so no witness for a *valid* block ever has to cover a subtree walk, and the
// concern that a key-set-derived witness could not express one does not apply
// to consensus. This asserts the refusal rather than the walk. The check
// matters more here than under the merkle trie: there prev.Root is empty for a
// storage-free account and the wiping branch is skipped on that basis, while
// the binary tree has no per-account storage root at all, so it has to probe
// the flat store to notice the storage is there.
func TestPBTBucketDeletionIsUnreachableFromBlocks(t *testing.T) {
	genesis, key, sender, _ := pbtChainGenesis(t)
	genesis.GasLimit = pbtCodeBlockGas

	victim := common.Address{0xde, 0xad}
	genesis.Alloc[victim] = types.Account{
		Balance: new(big.Int),
		Storage: pbtPrefilledStorage(pbtStorageSlots(48)),
	}
	// A zero-value call touches the account without funding it, so EIP-161
	// wants to sweep it and its bucket would go too.
	engine := beacon.New(ethash.NewFaker())
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("deleting an account that owns storage was allowed; this file's premise needs revisiting")
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, "unexpected storage wiping") {
			t.Fatalf("refused for the wrong reason: %v", r)
		}
	}()
	GenerateChainWithGenesis(genesis, engine, 1, pbtCallTx(t, key, sender, victim))
}

// TestPBTWitnessCoversCollapse zeroes storage slots, which is what makes a
// branch lose a child and collapse into its sibling. The sibling is resolved
// during that collapse, and which node it is depends on the shape of the state
// rather than on anything the block named.
func TestPBTWitnessCoversCollapse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		slots      int
		zeroFirstN int
		minNodes   int
	}{
		// One slot in the bucket, then zeroed: the bucket empties entirely.
		// The storage zone is a single group under the root, so this is one
		// collapse against a branch sibling, not a cascade.
		{"last slot of the only stem", 1, 1, 30},
		// A handful left behind, so the collapse stops partway and its sibling
		// is a live subtree rather than empty.
		{"some slots left behind", 24, 12, 50},
		// Everything at once: cascading collapses, and enough stems that the
		// siblings met on the way up cover groups and branches both.
		{"whole bucket at once", 48, 48, 90},
	} {
		t.Run(tc.name, func(t *testing.T) {
			genesis, key, sender, _ := pbtChainGenesis(t)
			genesis.GasLimit = pbtCodeBlockGas
			pbtPadGenesis(genesis, 64)

			slots := pbtStorageSlots(tc.slots)
			contract := common.Address{0xc0, 0xde}
			genesis.Alloc[contract] = types.Account{
				Balance: big.NewInt(1),
				Code:    pbtZeroingCode(slots[:tc.zeroFirstN]),
				Storage: pbtPrefilledStorage(slots),
			}
			chain, block, witness := pbtWitnessedBlock(t, genesis, pbtCallTx(t, key, sender, contract))
			assertPBTWitnessSufficient(t, chain, block, witness, tc.minNodes)

			// The slots have to have actually gone, or the collapse never ran.
			if _, err := chain.InsertChain([]*types.Block{block}); err != nil {
				t.Fatal(err)
			}
			state, err := chain.State()
			if err != nil {
				t.Fatal(err)
			}
			for _, slot := range slots[:tc.zeroFirstN] {
				key := common.BigToHash(new(big.Int).SetUint64(slot))
				if got := state.GetState(contract, key); got != (common.Hash{}) {
					t.Fatalf("slot %d still holds %x, so nothing was deleted", slot, got)
				}
			}
			for _, slot := range slots[tc.zeroFirstN:] {
				key := common.BigToHash(new(big.Int).SetUint64(slot))
				if got := state.GetState(contract, key); got == (common.Hash{}) {
					t.Fatalf("slot %d was cleared but should have survived", slot)
				}
			}
		})
	}
}

// TestPBTWitnessCoversSelfdestructInCreatingTx covers the one destruction
// EIP-6780 still permits: an account created and destroyed inside the same
// transaction.
//
// Nothing is actually removed from the tree - the account was never committed,
// so removeStem finds no group and the bucket locator diverges at once. What
// the witness has to carry is the walk: delStem descends five levels through
// hashed nodes and terminates on a *different* account's group. That neighbour
// is not in anything the block read or wrote, so it is exactly the kind of
// node a key-set-derived witness would omit.
func TestPBTWitnessCoversSelfdestructInCreatingTx(t *testing.T) {
	genesis, key, sender, _ := pbtChainGenesis(t)
	genesis.GasLimit = pbtCodeBlockGas
	pbtPadGenesis(genesis, 64)

	// Init code that fills some slots and then destroys the account it is
	// building, all inside the creating transaction.
	init := program.New()
	for _, slot := range pbtStorageSlots(16) {
		init.Sstore(slot, 1)
	}
	initCode := init.Selfdestruct(sender).Bytes()

	chain, block, witness := pbtWitnessedBlock(t, genesis, func(i int, gen *BlockGen) {
		signer := gen.Signer()
		tx, err := types.SignTx(types.NewContractCreation(
			gen.TxNonce(sender), big.NewInt(0), pbtCodeDeployGas,
			new(big.Int).Add(gen.BaseFee(), common.Big1), initCode,
		), signer, key)
		if err != nil {
			t.Fatal(err)
		}
		gen.AddTx(tx)
	})
	assertPBTWitnessSufficient(t, chain, block, witness, 30)
	assertPBTAbsent(t, chain, block, crypto.CreateAddress(sender, 0))

	// The creation has to have succeeded, or there was nothing to destroy and
	// the absence above would hold for the wrong reason. This is the assertion
	// that would notice a gas repricing quietly emptying the fixture.
	receipts := chain.GetReceiptsByHash(block.Hash())
	if len(receipts) != 1 {
		t.Fatalf("expected one receipt, got %d", len(receipts))
	}
	if got := receipts[0].Status; got != types.ReceiptStatusSuccessful {
		t.Fatalf("the creating transaction failed (status %d), so no selfdestruct ran", got)
	}
}

// assertPBTAbsent imports the block and requires the address to be gone.
func assertPBTAbsent(t *testing.T, chain *BlockChain, block *types.Block, addr common.Address) {
	t.Helper()

	if _, err := chain.InsertChain([]*types.Block{block}); err != nil {
		t.Fatal(err)
	}
	state, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if state.Exist(addr) {
		t.Fatalf("%x survived, so no deletion ran and this proves nothing", addr)
	}
}
