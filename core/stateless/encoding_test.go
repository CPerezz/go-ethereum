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

package stateless

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

func TestWitnessToExtWitnessOrdersFields(t *testing.T) {
	witness := &Witness{
		Headers: []*types.Header{testHeader(3), testHeader(2), testHeader(1)},
		Codes: map[string]struct{}{
			string([]byte{0x02}):       {},
			string([]byte{0x01, 0xff}): {},
			string([]byte{0x01}):       {},
		},
		State: map[string]struct{}{
			string([]byte{0xff}): {},
			string([]byte{0x00}): {},
			string([]byte{0x7f}): {},
		},
	}
	ext := witness.ToExtWitness()

	checkHeaderNumbers(t, ext.Headers, []uint64{1, 2, 3})
	checkBytes(t, "codes", ext.Codes, [][]byte{
		{0x01},
		{0x01, 0xff},
		{0x02},
	})
	checkBytes(t, "state", ext.State, [][]byte{
		{0x00},
		{0x7f},
		{0xff},
	})
}

func TestWitnessFromExtWitnessNormalizesHeaderOrder(t *testing.T) {
	tests := []struct {
		name    string
		headers []*types.Header
	}{
		{
			name:    "spec ordered",
			headers: []*types.Header{testHeader(1), testHeader(2), testHeader(3)},
		},
		{
			name:    "not ordered",
			headers: []*types.Header{testHeader(2), testHeader(3), testHeader(1)},
		},
		{
			name:    "internal ordered",
			headers: []*types.Header{testHeader(3), testHeader(2), testHeader(1)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var witness Witness
			if err := witness.FromExtWitness(&ExtWitness{Headers: tt.headers}); err != nil {
				t.Fatalf("FromExtWitness returned error: %v", err)
			}
			checkHeaderNumbers(t, witness.Headers, []uint64{3, 2, 1})
			if root := witness.Root(); root != testHeaderRoot(3) {
				t.Fatalf("root mismatch: have %s, want %s", root, testHeaderRoot(3))
			}
		})
	}
}

func TestWitnessFromExtWitnessRejectsEmptyHeaders(t *testing.T) {
	var witness Witness
	if err := witness.FromExtWitness(&ExtWitness{}); err == nil {
		t.Fatal("expected empty witness error")
	}
}

// TestWitnessProofEncoding covers the field the binary tree's proof travels in.
//
// The load-bearing property is what a witness *without* a proof encodes to: the
// field is optional and trails the ones upstream has, so a merkle witness has to
// come out byte-for-byte as it did before the field existed. rlp decides that by
// looking for a zero value, which an allocated-but-empty slice is not, so the
// nil handling is part of the format rather than tidiness.
func TestWitnessProofEncoding(t *testing.T) {
	merkle := &Witness{
		Headers: []*types.Header{testHeader(1)},
		Codes:   map[string]struct{}{string([]byte{0x01}): {}},
		State:   map[string]struct{}{string([]byte{0x02}): {}},
	}
	before, err := rlp.EncodeToBytes(merkle)
	if err != nil {
		t.Fatal(err)
	}
	// Four elements: headers, codes, state, and the empty keys list. A fifth would
	// mean every merkle witness on the wire changed shape.
	var elems []rlp.RawValue
	if err := rlp.DecodeBytes(before, &elems); err != nil {
		t.Fatal(err)
	}
	if len(elems) != 4 {
		t.Fatalf("a witness with no proof encodes to %d elements, want 4", len(elems))
	}
	// An empty proof is the same statement as no proof, and must not add one.
	merkle.AddProof(nil)
	merkle.AddProof([]byte{})
	after, err := rlp.EncodeToBytes(merkle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("an empty proof changed the encoding:\n before %x\n after  %x", before, after)
	}
	// A real proof round-trips, and lands in Proof rather than in the node set.
	proof := []byte{0x03, 0x21, 0xaa}
	merkle.AddProof(proof)
	blob, err := rlp.EncodeToBytes(merkle)
	if err != nil {
		t.Fatal(err)
	}
	var got Witness
	if err := rlp.DecodeBytes(blob, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Proof, proof) {
		t.Fatalf("decoded proof is %x, want %x", got.Proof, proof)
	}
	if len(got.State) != 0 {
		t.Fatalf("a proof witness decoded %d merkle state nodes", len(got.State))
	}
}

// TestWitnessFromExtWitnessRejectsTwoDescriptions pins that a witness cannot
// describe its state twice. A proof beside a merkle node set would leave the
// sender to decide which one the reader believed; Keys carried the paths of the
// node-set format the binary tree no longer ships, and ignoring them would
// decode such a witness as an empty merkle one and replay it against nothing.
func TestWitnessFromExtWitnessRejectsTwoDescriptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		ext  *ExtWitness
	}{
		{"proof and keys", &ExtWitness{
			Headers: []*types.Header{testHeader(1)},
			Keys:    []hexutil.Bytes{{0x00, 0x01}},
			State:   []hexutil.Bytes{{0xaa}},
			Proof:   hexutil.Bytes{0x03},
		}},
		{"keys without a proof", &ExtWitness{
			Headers: []*types.Header{testHeader(1)},
			Keys:    []hexutil.Bytes{{0x00, 0x01}},
			State:   []hexutil.Bytes{{0xaa}},
		}},
		{"proof and state", &ExtWitness{
			Headers: []*types.Header{testHeader(1)},
			State:   []hexutil.Bytes{{0xaa}},
			Proof:   hexutil.Bytes{0x03},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var w Witness
			if err := w.FromExtWitness(tc.ext); err == nil {
				t.Fatal("a witness describing its state twice was accepted")
			}
		})
	}
}

func testHeader(number uint64) *types.Header {
	return &types.Header{
		Number: new(big.Int).SetUint64(number),
		Root:   testHeaderRoot(number),
	}
}

func testHeaderRoot(number uint64) common.Hash {
	return common.Hash{byte(number)}
}

func checkHeaderNumbers(t *testing.T, headers []*types.Header, want []uint64) {
	t.Helper()
	if len(headers) != len(want) {
		t.Fatalf("header count mismatch: have %d, want %d", len(headers), len(want))
	}
	for i, header := range headers {
		if header.Number.Uint64() != want[i] {
			t.Fatalf("header %d number mismatch: have %d, want %d", i, header.Number.Uint64(), want[i])
		}
	}
}

func checkBytes(t *testing.T, name string, got []hexutil.Bytes, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s count mismatch: have %d, want %d", name, len(got), len(want))
	}
	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("%s %d mismatch: have %x, want %x", name, i, got[i], want[i])
		}
	}
}
