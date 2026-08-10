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
//     every hashed node it meets. Only the producer pays that: the enumeration
//     feeds the commit, and a witness-backed database skips it.
//   - Emptying a branch makes collapse resolve its sibling, and a multi-value
//     group sibling has to be re-folded at its new stored depth, which needs
//     all of its values rather than a stub.
//
// Neither set of nodes is predictable from the keys a block touched: they
// follow the shape of the state that was already there. A witness whose
// coverage were derived from a key set would lose them, which is what these
// fixtures exist to catch when the witness becomes a proof over recorded
// requests rather than the set of nodes execution happened to resolve.
//
// Both collapse survivors are covered: a single-value group, which hashes the
// same wherever it sits, and a multi-value group, which has to be re-folded at
// its new stored depth and therefore needs all of its values rather than a
// stub.
//
// Two shapes are deliberately absent:
//
//   - A subtree walk over a populated bucket. It needs an account that owns
//     committed storage and is then deleted, which after EIP-6780 leaves only
//     EIP-161 sweeping an empty account - and an empty account owning storage
//     is a state a block cannot reach a valid root through: generation and
//     import disagree on the clearing, so the block is refused on its root. The
//     disagreement is worth fixing on its own merits, so no fixture here pins
//     it as behaviour.
//   - A standalone HasPrefix emptiness probe. EIP-7610 rejects deployments from
//     a hardcoded per-chain address set (core/vm/eip7610.go) rather than by
//     asking whether an account holds storage, and StateDB.HasStorage has no
//     caller outside tests. DeleteAccount does consult a bucket locator, but
//     through delPrefix rather than findPrefix.

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

// TestPBTWitnessCoversMultiValueCollapse is the collapse arm the spread fixtures
// above cannot build: slots inside one tree index share a stem, so the survivor
// is a group holding several values.
//
// It is the arm that matters most to a proof. A single-value group is a bare
// leaf and hashes the same at any depth, so a stub of it would do; a multi-value
// group folds against its stored depth, which the collapse changes, so the proof
// has to carry every value it holds.
func TestPBTWitnessCoversMultiValueCollapse(t *testing.T) {
	// One stem with three values, and a spread of single-value stems to zero.
	shared := []uint64{bintrie.HeaderStorageOffset, bintrie.HeaderStorageOffset + 1, bintrie.HeaderStorageOffset + 2}
	spread := pbtStorageSlots(25)[1:] // drop the first: it shares shared's stem

	genesis, key, sender, _ := pbtChainGenesis(t)
	genesis.GasLimit = pbtCodeBlockGas
	pbtPadGenesis(genesis, 64)

	contract := common.Address{0xc0, 0xde}
	genesis.Alloc[contract] = types.Account{
		Balance: big.NewInt(1),
		Code:    pbtZeroingCode(spread),
		Storage: pbtPrefilledStorage(append(slices.Clone(shared), spread...)),
	}
	chain, block, witness := pbtWitnessedBlock(t, genesis, pbtCallTx(t, key, sender, contract))
	assertPBTWitnessSufficient(t, chain, block, witness, 30)

	if _, err := chain.InsertChain([]*types.Block{block}); err != nil {
		t.Fatal(err)
	}
	state, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	// The zeroed stems have to have gone, and the shared one has to have kept all
	// three values: a survivor re-folded from a stub would lose them silently.
	for _, slot := range spread {
		key := common.BigToHash(new(big.Int).SetUint64(slot))
		if got := state.GetState(contract, key); got != (common.Hash{}) {
			t.Fatalf("slot %d still holds %x, so no collapse ran", slot, got)
		}
	}
	for _, slot := range shared {
		key := common.BigToHash(new(big.Int).SetUint64(slot))
		if got := state.GetState(contract, key); got == (common.Hash{}) {
			t.Fatalf("survivor slot %d was cleared", slot)
		}
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
