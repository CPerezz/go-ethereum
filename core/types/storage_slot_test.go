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

package types

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
)

// Pre-8188 the leaf must be a plain RLP bytestring and round-trip with lwb=0.
func TestStorageSlotCodecLegacyRoundtrip(t *testing.T) {
	value := []byte{0x01, 0x02, 0x03}
	enc := EncodeStorageSlot(value, 0, false)
	if enc[0] >= 0xc0 {
		t.Fatalf("legacy slot must encode as a bytestring, got list prefix 0x%x", enc[0])
	}
	got, lwb, err := DecodeStorageSlot(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("value mismatch: got %x want %x", got, value)
	}
	if lwb != 0 {
		t.Fatalf("legacy lwb must be 0, got %d", lwb)
	}
}

// With EIP-8188 active the leaf is an RLP list [value, lwb] and round-trips.
func TestStorageSlotCodec8188Roundtrip(t *testing.T) {
	value := []byte{0xde, 0xad, 0xbe, 0xef}
	const block = uint64(24402727)
	enc := EncodeStorageSlot(value, block, true)
	if enc[0] < 0xc0 {
		t.Fatalf("8188 slot must encode as a list, got string prefix 0x%x", enc[0])
	}
	got, lwb, err := DecodeStorageSlot(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("value mismatch: got %x want %x", got, value)
	}
	if lwb != block {
		t.Fatalf("lwb mismatch: got %d want %d", lwb, block)
	}
}

// A value written by a pre-8188 client (a bare RLP bytestring) must decode with lwb=0.
func TestStorageSlotCodecToleratesLegacyBytestring(t *testing.T) {
	value := bytes.Repeat([]byte{0xab}, 32)
	legacy, err := rlp.EncodeToBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	got, lwb, err := DecodeStorageSlot(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("value mismatch: got %x want %x", got, value)
	}
	if lwb != 0 {
		t.Fatalf("legacy bytestring lwb must be 0, got %d", lwb)
	}
}

// The fork-off encoding must be byte-identical to the historical encoding so
// that pre-fork state roots are unchanged.
func TestStorageSlotLegacyByteIdentical(t *testing.T) {
	for _, value := range [][]byte{
		{0x05},                      // single byte < 0x80 (self-encoded)
		{0xff},                      // single byte >= 0x80
		bytes.Repeat([]byte{0x9a}, 32), // full 32-byte value
	} {
		old, err := rlp.EncodeToBytes(value)
		if err != nil {
			t.Fatal(err)
		}
		// lwb is ignored when the fork is inactive.
		neu := EncodeStorageSlot(value, 12345, false)
		if !bytes.Equal(old, neu) {
			t.Fatalf("fork-off encoding diverged for %x: old %x new %x", value, old, neu)
		}
	}
}
