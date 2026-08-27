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
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

// PBTMode places a chain relative to the binary tree fork (EIP-8297): which
// tree carries the canonical state commitment, and whether an EIP-8347
// migration lies in front of or behind the head. It is resolved once at open
// time from configuration and headers alone — never from state — because it
// decides how state may be opened at all.
type PBTMode int

const (
	// PBTModeNone: no binary tree scheduled; merkle-patricia, forever.
	PBTModeNone PBTMode = iota
	// PBTModeGenesis: the tree from block zero. The only mode that existed
	// before migration support, and byte-for-byte what it always was.
	PBTModeGenesis
	// PBTModeMigrationPre: the tree is scheduled after genesis and the head
	// has not reached it. Merkle-patricia is canonical; an imported shadow
	// tree is required to be present, because EIP-8347 catch-up has to start
	// from one.
	PBTModeMigrationPre
	// PBTModeMigrationPost: the head crossed the schedule; the tree is
	// canonical and the merkle-patricia side is dormant.
	PBTModeMigrationPost
)

// String returns the wire name of the mode. These names are FROZEN: the
// devnet monitor keys on them through debug_pbtMigrationStatus, so renaming
// one is a breaking API change, not a refactor.
func (m PBTMode) String() string {
	switch m {
	case PBTModeGenesis:
		return "pbtGenesis"
	case PBTModeMigrationPre:
		return "migrationPre"
	case PBTModeMigrationPost:
		return "migrationPost"
	default:
		return "mpt"
	}
}

// canonicalPBT reports whether the binary tree carries the canonical state
// commitment in this mode.
func (m PBTMode) canonicalPBT() bool {
	return m == PBTModeGenesis || m == PBTModeMigrationPost
}

// errPBTSwitchoverNotImplemented refuses the block that would cross
// binaryTrieTime. This is deliberately the switchover seam: implementing the
// switchover means replacing exactly this refusal with execution that takes
// the shadow tree as its pre-state. Until then a migrating node must stall
// loudly at the fork rather than execute the boundary block against the
// wrong tree and diverge silently.
var errPBTSwitchoverNotImplemented = errors.New("the PBT switchover is not implemented in this build; refusing to import a block that crosses binaryTrieTime")

// resolvePBTMode is the pure mode decision: the config and block zero's
// timestamp place the schedule, the head header places the chain against it.
// It expects effective (post-override) configuration — safe today because
// ChainOverrides carries no binaryTrieTime field, so a pre-merge read cannot
// disagree with the post-merge config; whoever adds such an override must
// thread it through here first.
func resolvePBTMode(config *params.ChainConfig, genesisTime uint64, head *types.Header) PBTMode {
	if config == nil || !config.IsPBT() {
		return PBTModeNone
	}
	if config.PBTActive(common.Big0, genesisTime) {
		return PBTModeGenesis
	}
	if head != nil && config.PBTActive(head.Number, head.Time) {
		return PBTModeMigrationPost
	}
	return PBTModeMigrationPre
}

// pbtMode resolves the mode from the supplied genesis or, failing that, from
// what is already stored on disk. It runs before the trie database exists,
// so everything is read raw — the config, block zero's timestamp and the
// head header — which is enough to answer without touching state. The head
// is returned alongside: the caller's guards need one, and it must be the
// same header the decision was made from.
func pbtMode(db ethdb.Database, genesis *Genesis) (PBTMode, *types.Header, error) {
	var (
		config      *params.ChainConfig
		genesisTime uint64
	)
	if genesis != nil {
		if genesis.Config == nil {
			return PBTModeNone, nil, errGenesisNoConfig
		}
		config, genesisTime = genesis.Config, genesis.Timestamp
	} else if ghash := rawdb.ReadCanonicalHash(db, 0); ghash != (common.Hash{}) {
		if stored := rawdb.ReadChainConfig(db, ghash); stored != nil {
			config = stored
			if h := rawdb.ReadHeader(db, ghash, 0); h != nil {
				genesisTime = h.Time
			}
		}
	}
	var head *types.Header
	if hash := rawdb.ReadHeadHeaderHash(db); hash != (common.Hash{}) {
		if number, ok := rawdb.ReadHeaderNumber(db, hash); ok {
			head = rawdb.ReadHeader(db, hash, number)
		}
	}
	return resolvePBTMode(config, genesisTime, head), head, nil
}

// checkPBTMode holds the on-disk markers to the resolved mode before anything
// opens. It reads markers only — the flat-state attestation, the anchor and
// the head — never state itself: the shadow tree is opened later, and
// pathdb's own attestation check remains the integrity backstop below this.
// Offline tooling (geth init, bintrie convert/import, geth db) constructs no
// BlockChain and is deliberately outside these guards, so the recovery the
// error messages prescribe stays runnable.
func checkPBTMode(db ethdb.Database, mode PBTMode, head *types.Header) error {
	pbtdb := rawdb.NewTable(db, string(rawdb.PBTPrefix))
	hasShadow := rawdb.ReadPBTFlatState(pbtdb)
	switch mode {
	case PBTModeNone:
		// A binary tree database must never be reopened as merkle: a stored
		// config that lost the fork (e.g. written when the key was "pbt")
		// would silently point the node at an empty merkle namespace.
		if hasShadow {
			return errors.New("database holds binary tree state but the chain configuration does not schedule it (the genesis config key is \"binaryTrieTime\"); re-run init with an updated genesis, or resync")
		}
	case PBTModeMigrationPre:
		if !hasShadow {
			return errors.New("migration mode requires an imported shadow binary tree; run 'geth bintrie import <snapshot> <preimages> <anchor>' (or 'geth bintrie convert') before starting the node")
		}
		anchor, _, ok := rawdb.ReadPBTAnchor(pbtdb)
		if !ok {
			return errors.New("binary tree state carries no anchor: the datadir looks like a from-genesis binary tree or an interrupted conversion, neither of which can serve as a migration shadow; wipe it and re-import ('geth bintrie import --force')")
		}
		if head != nil && head.Number.Uint64() < anchor {
			return fmt.Errorf("canonical head %d is behind the shadow anchor %d: the shadow claims state this chain has not reached", head.Number.Uint64(), anchor)
		}
	case PBTModeMigrationPost:
		if !hasShadow {
			return errors.New("the chain crossed binaryTrieTime but the database holds no binary tree state; re-import the tree or resync")
		}
	}
	return nil
}
