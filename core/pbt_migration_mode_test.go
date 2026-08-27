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
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
)

// TestResolvePBTMode pins the pure mode decision over every reachable shape
// of (config, genesis time, head). The head==nil rows are the fresh-datadir
// case; the head rows are reopens.
func TestResolvePBTMode(t *testing.T) {
	mkcfg := func(tree *uint64) *params.ChainConfig {
		c := *testPBTChainConfig
		c.BinaryTrieTime = tree
		return &c
	}
	hdr := func(num, time uint64) *types.Header {
		return &types.Header{Number: new(big.Int).SetUint64(num), Time: time}
	}
	for _, tc := range []struct {
		name        string
		cfg         *params.ChainConfig
		genesisTime uint64
		head        *types.Header
		want        PBTMode
	}{
		{"nil config", nil, 0, nil, PBTModeNone},
		{"unscheduled", mkcfg(nil), 0, hdr(9, 90), PBTModeNone},
		{"at genesis, fresh", mkcfg(u64(0)), 0, nil, PBTModeGenesis},
		{"at genesis, reopen", mkcfg(u64(0)), 0, hdr(5, 50), PBTModeGenesis},
		{"at a nonzero genesis time", mkcfg(u64(7)), 7, nil, PBTModeGenesis},
		{"future, fresh", mkcfg(u64(100)), 0, nil, PBTModeMigrationPre},
		{"future, head before", mkcfg(u64(100)), 0, hdr(9, 99), PBTModeMigrationPre},
		{"future, head exactly at", mkcfg(u64(100)), 0, hdr(10, 100), PBTModeMigrationPost},
		{"future, head past", mkcfg(u64(100)), 0, hdr(20, 200), PBTModeMigrationPost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolvePBTMode(tc.cfg, tc.genesisTime, tc.head); got != tc.want {
				t.Fatalf("resolvePBTMode = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPBTModeWireNames pins the frozen phase strings the devnet monitor keys
// on through debug_pbtMigrationStatus. Renaming one is a breaking API change.
func TestPBTModeWireNames(t *testing.T) {
	for mode, want := range map[PBTMode]string{
		PBTModeNone:          "mpt",
		PBTModeGenesis:       "pbtGenesis",
		PBTModeMigrationPre:  "migrationPre",
		PBTModeMigrationPost: "migrationPost",
	} {
		if got := mode.String(); got != want {
			t.Fatalf("mode %d reads %q, the frozen name is %q", mode, got, want)
		}
	}
}

// migrationChainGenesis reschedules the pbtChainGenesis fixture: the tree at
// genesis time + offset. A nil offset removes the schedule entirely.
func migrationChainGenesis(t *testing.T, treeTime *uint64) *Genesis {
	t.Helper()
	base, _, _, _ := pbtChainGenesis(t)
	cfg := *base.Config
	cfg.BinaryTrieTime = treeTime
	g := *base
	g.Config = &cfg
	return &g
}

// commitMerkleGenesis writes a merkle-patricia genesis the way geth init
// does: through an MPT-shaped path trie database.
func commitMerkleGenesis(t *testing.T, db ethdb.Database, genesis *Genesis) common.Hash {
	t.Helper()
	tdb := triedb.NewDatabase(db, &triedb.Config{PathDB: pathdb.Defaults})
	defer tdb.Close()
	block, err := genesis.Commit(db, tdb, nil)
	if err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	return block.Hash()
}

// seedShadowMarkers plants the markers an offline `bintrie import` leaves
// behind, without building an actual tree: the guards under test read markers
// only, and pathdb's own attestation check is exercised one layer down.
func seedShadowMarkers(db ethdb.Database, withAnchor bool, anchor uint64, hash common.Hash) {
	pbtdb := rawdb.NewTable(db, string(rawdb.PBTPrefix))
	rawdb.WritePBTFlatState(pbtdb)
	if withAnchor {
		rawdb.WritePBTAnchor(pbtdb, anchor, hash)
	}
}

// TestMigrationModeGuards drives the open-time guard matrix: every refusal
// names its recovery, and the one legal migration-pre shape opens with the
// merkle trie canonical.
func TestMigrationModeGuards(t *testing.T) {
	var (
		engine  = beacon.New(ethash.NewFaker())
		future  = u64(1_000_000)
		pathCfg = func() *BlockChainConfig { return DefaultConfig().WithStateScheme(rawdb.PathScheme) }
	)
	expectRefusal := func(t *testing.T, genesis *Genesis, cfg *BlockChainConfig, prep func(ethdb.Database, common.Hash), fragment string) {
		t.Helper()
		db := rawdb.NewMemoryDatabase()
		ghash := commitMerkleGenesis(t, db, genesis)
		if prep != nil {
			prep(db, ghash)
		}
		chain, err := NewBlockChain(db, genesis, engine, cfg)
		if err == nil {
			chain.Stop()
			t.Fatalf("the chain opened; want a refusal mentioning %q", fragment)
		}
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("refused with %q, want a mention of %q", err, fragment)
		}
	}

	t.Run("mpt config refuses stray shadow state", func(t *testing.T) {
		expectRefusal(t, migrationChainGenesis(t, nil), pathCfg(), func(db ethdb.Database, ghash common.Hash) {
			seedShadowMarkers(db, true, 0, ghash)
		}, "does not schedule it")
	})
	t.Run("migration without an import refuses", func(t *testing.T) {
		expectRefusal(t, migrationChainGenesis(t, future), pathCfg(), nil, "requires an imported shadow")
	})
	t.Run("shadow without an anchor refuses", func(t *testing.T) {
		expectRefusal(t, migrationChainGenesis(t, future), pathCfg(), func(db ethdb.Database, ghash common.Hash) {
			seedShadowMarkers(db, false, 0, common.Hash{})
		}, "carries no anchor")
	})
	t.Run("head behind the anchor refuses", func(t *testing.T) {
		expectRefusal(t, migrationChainGenesis(t, future), pathCfg(), func(db ethdb.Database, ghash common.Hash) {
			seedShadowMarkers(db, true, 5, ghash)
		}, "behind the shadow anchor")
	})
	t.Run("migration is path-scheme only", func(t *testing.T) {
		hashCfg := DefaultConfig().WithStateScheme(rawdb.HashScheme)
		expectRefusal(t, migrationChainGenesis(t, future), hashCfg, func(db ethdb.Database, ghash common.Hash) {
			seedShadowMarkers(db, true, 0, ghash)
		}, "path state scheme")
	})
	t.Run("crossed fork without shadow state refuses", func(t *testing.T) {
		genesis := migrationChainGenesis(t, future)
		db := rawdb.NewMemoryDatabase()
		ghash := commitMerkleGenesis(t, db, genesis)
		// Plant a head beyond the schedule, the way a crashed post-switchover
		// node would look; the mode must resolve to migration-post and demand
		// the tree.
		head := &types.Header{
			ParentHash: ghash,
			Number:     big.NewInt(1),
			Time:       *future + 1,
		}
		rawdb.WriteHeader(db, head)
		rawdb.WriteHeadHeaderHash(db, head.Hash())
		if _, err := NewBlockChain(db, genesis, engine, pathCfg()); err == nil || !strings.Contains(err.Error(), "crossed binaryTrieTime") {
			t.Fatalf("refused with %v, want a mention of %q", err, "crossed binaryTrieTime")
		}
	})
	t.Run("the legal migration-pre shape opens on the merkle trie", func(t *testing.T) {
		genesis := migrationChainGenesis(t, future)
		db := rawdb.NewMemoryDatabase()
		ghash := commitMerkleGenesis(t, db, genesis)
		seedShadowMarkers(db, true, 0, ghash)

		chain, err := NewBlockChain(db, genesis, engine, pathCfg())
		if err != nil {
			t.Fatalf("the legal shape refused to open: %v", err)
		}
		defer chain.Stop()
		if chain.PBTMode() != PBTModeMigrationPre {
			t.Fatalf("mode is %v, want %v", chain.PBTMode(), PBTModeMigrationPre)
		}
		if chain.TrieDB().IsPBT() {
			t.Fatal("migration-pre opened the binary tree as canonical; the merkle trie is")
		}
		if shadow := chain.ShadowTrieDB(); shadow == nil || !shadow.IsPBT() {
			t.Fatal("migration-pre opened without its shadow binary tree")
		}
		if head := chain.CurrentBlock(); head.Number.Uint64() != 0 {
			t.Fatalf("head is block %d, want the genesis", head.Number)
		}
	})
}

// TestMigrationPreRefusesCrossingBlocks pins the switchover seam: a
// migrating node imports right up to the schedule and refuses the first
// block that reaches it, loudly, instead of committing a root from the wrong
// tree. Blocks are generated under a schedule-free copy of the config —
// identical genesis block, so they chain — which also keeps the deferred
// chain-maker tree semantics out of this test.
func TestMigrationPreRefusesCrossingBlocks(t *testing.T) {
	base, key, sender, recipient := pbtChainGenesis(t)
	plainCfg := *base.Config
	plainCfg.BinaryTrieTime = nil
	plain := *base
	plain.Config = &plainCfg

	var (
		engine = beacon.New(ethash.NewFaker())
		signer = types.LatestSigner(plain.Config)
	)
	_, blocks, _ := GenerateChainWithGenesis(&plain, engine, 4, func(i int, gen *BlockGen) {
		tx, err := types.SignTx(types.NewTransaction(
			gen.TxNonce(sender), recipient, big.NewInt(1000), pbtTestTxGas,
			new(big.Int).Add(gen.BaseFee(), common.Big1), nil,
		), signer, key)
		if err != nil {
			t.Fatal(err)
		}
		gen.AddTx(tx)
	})
	if len(blocks) != 4 {
		t.Fatalf("generated %d blocks, want 4", len(blocks))
	}
	// Schedule the fork on the third block's timestamp, after generation:
	// the genesis block commits the same merkle root for every future
	// schedule, so the choice of T cannot desynchronize the two configs.
	T := blocks[2].Time()
	genesis := migrationChainGenesis(t, u64(T))
	if genesis.ToBlock().Hash() != plain.ToBlock().Hash() {
		t.Fatal("the migration and schedule-free genesis blocks diverged; the generated chain cannot apply")
	}

	db := rawdb.NewMemoryDatabase()
	ghash := commitMerkleGenesis(t, db, genesis)
	seedShadowMarkers(db, true, 0, ghash)
	chain, err := NewBlockChain(db, genesis, engine, DefaultConfig().WithStateScheme(rawdb.PathScheme))
	if err != nil {
		t.Fatalf("migration-pre chain refused to open: %v", err)
	}
	defer chain.Stop()

	// Everything before the schedule imports and executes on the merkle trie.
	if _, err := chain.InsertChain(blocks[:2]); err != nil {
		t.Fatalf("pre-fork blocks refused: %v", err)
	}
	if got := chain.GetBlockByHash(blocks[1].Hash()); got == nil {
		t.Fatal("pre-fork block 2 did not import")
	}
	// The first block whose time reaches the schedule is the seam.
	_, err = chain.InsertChain(blocks[2:3])
	if !errors.Is(err, errPBTSwitchoverNotImplemented) {
		t.Fatalf("the crossing block failed with %v, want errPBTSwitchoverNotImplemented", err)
	}
}

// TestMigrationPostStateAtRefusal pins the named error for pre-fork headers
// after the switchover, without opening a post-switchover chain: the branch
// fires before any database is touched, so a minimal chain shell is enough.
func TestMigrationPostStateAtRefusal(t *testing.T) {
	cfg := *testPBTChainConfig
	cfg.BinaryTrieTime = u64(100)
	bc := &BlockChain{chainConfig: &cfg, pbtMode: PBTModeMigrationPost}

	preFork := &types.Header{Number: big.NewInt(3), Time: 99}
	if _, err := bc.StateAt(preFork); err == nil || !strings.Contains(err.Error(), "pre-transition block") {
		t.Fatalf("StateAt(pre-fork header) = %v, want the named pre-transition refusal", err)
	}
}
