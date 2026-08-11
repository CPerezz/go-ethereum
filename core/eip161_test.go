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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// EIP-161 removes an account that is touched while empty. A touch changes no
// value, so it cannot be stated in a block access list - and the parallel
// processor derives the post-state root from that list alone, concurrently with
// execution. So the two executors disagree, and the fixtures here drive both.
//
// Execution cannot leave an empty account behind: a zero-value call to a fresh
// address returns before touching anything, a 7702 delegation leaves code, and
// spending a balance to zero bumps the nonce. The trigger is state that predates
// the rule - a genesis allocation, or the accounts a network carries from before
// it adopted EIP-158 (core/vm/eip7610.go lists 28 of them on mainnet). Note that
// emptiness does not consider storage, so those accounts qualify.

// eip161Genesis returns a genesis holding a funded sender and an EIP-161-empty
// victim: zero nonce, zero balance, no code, and slots storage slots.
func eip161Genesis(t *testing.T, config params.ChainConfig, slots int) (*Genesis, *ecdsa.PrivateKey, common.Address, common.Address) {
	t.Helper()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatal(err)
	}
	config.Ethash = nil

	var (
		sender = crypto.PubkeyToAddress(key.PublicKey)
		victim = common.Address{0xde, 0xad}
		acct   = types.Account{Balance: new(big.Int)}
	)
	if slots > 0 {
		acct.Storage = pbtPrefilledStorage(pbtStorageSlots(slots))
	}
	genesis := &Genesis{
		Config:     &config,
		Difficulty: big.NewInt(0),
		BaseFee:    big.NewInt(params.InitialBaseFee),
		GasLimit:   pbtCodeBlockGas,
		Alloc: types.GenesisAlloc{
			sender: {Balance: new(big.Int).Mul(big.NewInt(1000), big.NewInt(params.Ether))},
			victim: acct,
		},
	}
	// Padding, so the deletion has branches to collapse rather than folding the
	// whole state into one record.
	pbtPadGenesis(genesis, 64)
	return genesis, key, sender, victim
}

// eip161ChainConfig returns a blockchain config whose state scheme follows the
// tree, optionally pinned to the sequential processor.
func eip161ChainConfig(config *params.ChainConfig, sequential bool) *BlockChainConfig {
	cfg := DefaultConfig()
	if config.IsPBT() {
		cfg = cfg.WithStateScheme(rawdb.PathScheme)
	}
	cfg.VmConfig.DisableParallelExecution = sequential
	return cfg
}

// TestEIP161ClearingAgreesAcrossExecutors pins that a block clearing a touched
// empty account imports the same way through both processors.
//
// Both arms import the block generated from the same state, and generation
// computes the header root sequentially, so ValidateState succeeding on each is
// what proves the three agree. The merkle arm is the evidence this is not a
// binary-tree problem: the binary tree requires Amsterdam but Amsterdam does not
// require the tree, so merkle-at-Amsterdam reaches the same processor.
func TestEIP161ClearingAgreesAcrossExecutors(t *testing.T) {
	merkle := *testPBTChainConfig
	merkle.PBT = false

	for _, tc := range []struct {
		name   string
		config params.ChainConfig
		slots  int
	}{
		{"pbt/victim owns storage", *testPBTChainConfig, 48},
		{"pbt/victim owns nothing", *testPBTChainConfig, 0},
		{"merkle/victim owns storage", merkle, 48},
		{"merkle/victim owns nothing", merkle, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, sequential := range []bool{false, true} {
				name := "parallel"
				if sequential {
					name = "sequential"
				}
				t.Run(name, func(t *testing.T) {
					eip161Clearing(t, tc.config, tc.slots, sequential)
				})
			}
		})
	}
}

func eip161Clearing(t *testing.T, config params.ChainConfig, slots int, sequential bool) {
	t.Helper()

	genesis, key, sender, victim := eip161Genesis(t, config, slots)
	engine := beacon.New(ethash.NewFaker())

	// A zero-value call touches the victim without funding it, which is what
	// makes EIP-161 sweep it.
	db, blocks, _ := GenerateChainWithGenesis(genesis, engine, 1, pbtCallTx(t, key, sender, victim))

	chain, err := NewBlockChain(db, genesis, engine, eip161ChainConfig(genesis.Config, sequential))
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()

	// Pin which processor ran, or a fixture whose block lost its access list
	// would quietly test the sequential path twice.
	if got := chain.useBALExecution(blocks[0], false); got == sequential {
		t.Fatalf("expected BAL execution to be %v, got %v", !sequential, got)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("importing a block that clears a touched empty account: %v", err)
	}
	state, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if state.Exist(victim) {
		t.Fatal("the touched empty account survived the import")
	}
	// Its storage has to have gone with it, or the account is absent while the
	// slots it owned are still readable.
	for _, slot := range pbtStorageSlots(slots) {
		key := common.BigToHash(new(big.Int).SetUint64(slot))
		if got := state.GetState(victim, key); got != (common.Hash{}) {
			t.Fatalf("slot %d of a deleted account still holds %x", slot, got)
		}
	}
}

// TestEIP161TouchOfAbsentAccountLeavesBALAlone pins the other half: an account
// that never existed must not enter the access list when it is touched and
// dropped, because the removal changes nothing.
//
// A transaction priced exactly at the base fee earns the fee recipient a zero
// tip, and AddBalance has no zero guard (core/state_transition.go), so a
// coinbase that does not pre-exist is touched, found empty and dropped. That is
// an ordinary block. Recording it would change BlockAccessListHash for a shape
// that works today, which is what the origin check in finaliseAmsterdam avoids.
func TestEIP161TouchOfAbsentAccountLeavesBALAlone(t *testing.T) {
	genesis, key, sender, _ := eip161Genesis(t, *testPBTChainConfig, 0)
	delete(genesis.Alloc, common.Address{0xde, 0xad}) // no pre-existing empty account here
	engine := beacon.New(ethash.NewFaker())

	coinbase := common.Address{0xc0, 0x1b} // absent from the alloc above
	_, blocks, _ := GenerateChainWithGenesis(genesis, engine, 1, func(i int, gen *BlockGen) {
		gen.SetCoinbase(coinbase)
		// Exactly the base fee, so the effective tip - and the fee - is zero.
		tx, err := types.SignTx(types.NewTransaction(
			gen.TxNonce(sender), common.Address{0x0f, 0xf1}, big.NewInt(1),
			pbtTestTxGas, gen.BaseFee(), nil,
		), gen.Signer(), key)
		if err != nil {
			t.Fatal(err)
		}
		gen.AddTx(tx)
	})
	list := blocks[0].AccessList()
	if list == nil {
		t.Fatal("the generated block carries no access list")
	}
	for _, account := range *list {
		if account.Address != coinbase {
			continue
		}
		if len(account.BalanceChanges) != 0 {
			t.Fatalf("an account that never existed recorded %d balance changes when it was touched and dropped",
				len(account.BalanceChanges))
		}
	}
}

// TestEIP161ClearingSurvivesStatelessReplay closes the loop with the witness
// path, which is the third way this block's root gets computed.
//
// Replay runs sequentially, so it agreed with generation even before the access
// list learned to state the removal - what this pins is that the witness carries
// enough to perform it. The deleted account's header stem has to be covered whole
// and, when it owns storage, the walk that drops its bucket has to be covered
// too; neither is named by a key the block read.
func TestEIP161ClearingSurvivesStatelessReplay(t *testing.T) {
	for _, slots := range []int{48, 0} {
		name := "victim owns storage"
		if slots == 0 {
			name = "victim owns nothing"
		}
		t.Run(name, func(t *testing.T) {
			genesis, key, sender, victim := eip161Genesis(t, *testPBTChainConfig, slots)
			engine := beacon.New(ethash.NewFaker())
			db, blocks, _ := GenerateChainWithGenesis(genesis, engine, 1, pbtCallTx(t, key, sender, victim))

			chain, err := NewBlockChain(db, genesis, engine, eip161ChainConfig(genesis.Config, false))
			if err != nil {
				t.Fatal(err)
			}
			defer chain.Stop()

			parent := chain.GetHeaderByNumber(0)
			res, err := chain.ProcessBlock(context.Background(), parent.Root, blocks[0], ExecuteConfig{MakeWitness: true})
			if err != nil {
				t.Fatalf("processing the block for a witness: %v", err)
			}
			witness := res.Witness()
			if witness == nil || len(witness.Proof) == 0 {
				t.Fatal("the witness holds no proof")
			}
			header := types.CopyHeader(blocks[0].Header())
			header.Root, header.ReceiptHash = common.Hash{}, common.Hash{}
			task := types.NewBlockWithHeader(header).WithBody(*blocks[0].Body())

			root, _, err := ExecuteStateless(context.Background(), chain.Config(), vm.Config{}, task, witness)
			if err != nil {
				t.Fatalf("replaying from the witness: %v", err)
			}
			if root != blocks[0].Root() {
				t.Fatalf("stateless root %x, want %x", root, blocks[0].Root())
			}
		})
	}
}
