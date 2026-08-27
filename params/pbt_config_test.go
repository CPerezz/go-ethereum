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

package params

import (
	"math/big"
	"testing"
)

// TestPBTActive pins the migration-mode predicate: the binary tree is the
// canonical commitment only once the schedule exists AND the block context has
// reached it. IsPBT keeps answering the older, whole-chain question — "is the
// tree scheduled at all" — and the two must not be conflated: conflating them
// is exactly what made a future binaryTrieTime commit a binary-tree genesis.
func TestPBTActive(t *testing.T) {
	num := big.NewInt(0)
	for _, tc := range []struct {
		name      string
		amsterdam *uint64
		tree      *uint64
		time      uint64
		want      bool
	}{
		{"unscheduled stays inactive forever", u64ptr(0), nil, 1 << 40, false},
		{"at-genesis schedule is active at genesis", u64ptr(0), u64ptr(0), 0, true},
		{"at-genesis schedule stays active", u64ptr(0), u64ptr(0), 1, true},
		{"future schedule is inactive before T", u64ptr(0), u64ptr(100), 99, false},
		{"future schedule activates exactly at T", u64ptr(0), u64ptr(100), 100, true},
		{"future schedule stays active after T", u64ptr(0), u64ptr(100), 101, true},
		{"amsterdam active, tree still pending", u64ptr(50), u64ptr(100), 75, false},
		{"shared amsterdam+tree time, before", u64ptr(100), u64ptr(100), 99, false},
		{"shared amsterdam+tree time, at", u64ptr(100), u64ptr(100), 100, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pbtRulesBase()
			cfg.AmsterdamTime = tc.amsterdam
			cfg.BinaryTrieTime = tc.tree
			if got := cfg.PBTActive(num, tc.time); got != tc.want {
				t.Fatalf("PBTActive(%v, %d) = %v, want %v", num, tc.time, got, tc.want)
			}
			// The whole-chain question must keep its own answer: scheduled at
			// all, regardless of the context's position.
			if got, want := cfg.IsPBT(), tc.tree != nil; got != want {
				t.Fatalf("IsPBT() = %v, want %v — the predicates drifted together", got, want)
			}
		})
	}
}
