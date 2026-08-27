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

package eth

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

// TestPBTMigrationStatusWireShape pins the frozen JSON contract of
// debug_pbtMigrationStatus: the devnet monitor keys on these exact field
// names, and the phase strings are pinned one layer down in core. Losing or
// renaming a key is a breaking API change dressed as a refactor.
func TestPBTMigrationStatusWireShape(t *testing.T) {
	tt := hexutil.Uint64(1800)
	blob, err := json.Marshal(PBTMigrationStatusResult{Phase: "migrationPre", BinaryTrieTime: &tt})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"phase"`, `"headNumber"`, `"headTimestamp"`, `"binaryTrieTime"`, `"canonicalRoot"`} {
		if !strings.Contains(string(blob), key) {
			t.Fatalf("the wire shape lost %s: %s", key, blob)
		}
	}
	// An unscheduled chain reports a null schedule, not a missing key.
	blob, err = json.Marshal(PBTMigrationStatusResult{Phase: "mpt"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), `"binaryTrieTime":null`) {
		t.Fatalf("an absent schedule must serialize as null: %s", blob)
	}
}
