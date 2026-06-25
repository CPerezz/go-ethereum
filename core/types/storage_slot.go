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

import "github.com/ethereum/go-ethereum/rlp"

// storageSlot8188 is the EIP-8188 storage-slot leaf form: the (already trimmed)
// slot value wrapped together with the block at which it was last written.
type storageSlot8188 struct {
	Value       []byte
	LastWritten uint32
}

// EncodeStorageSlot encodes a trimmed storage-slot value into its trie-leaf form.
// Before EIP-8188 the leaf is the plain RLP bytestring of the value. With the
// fork active the leaf becomes the RLP list [value, lastWritten]. The lastWritten
// argument is ignored when eip8188 is false, so the fork-off output is always
// byte-identical to the historical encoding.
func EncodeStorageSlot(value []byte, lastWritten uint64, eip8188 bool) []byte {
	if !eip8188 {
		enc, _ := rlp.EncodeToBytes(value)
		return enc
	}
	enc, _ := rlp.EncodeToBytes(&storageSlot8188{Value: value, LastWritten: uint32(lastWritten)})
	return enc
}

// DecodeStorageSlot decodes a leaf produced by EncodeStorageSlot. It tolerates
// both the legacy bare-bytestring form (lastWritten defaults to 0) and the
// EIP-8188 list form, distinguished by the RLP prefix: a bytestring has a prefix
// below 0xc0 while a list has 0xc0+. Storage values are at most 32 bytes, so the
// legacy form is never itself a list and the discrimination is unambiguous.
func DecodeStorageSlot(enc []byte) (value []byte, lastWritten uint64, err error) {
	if len(enc) == 0 {
		return nil, 0, nil
	}
	if enc[0] >= 0xc0 {
		var slot storageSlot8188
		if err := rlp.DecodeBytes(enc, &slot); err != nil {
			return nil, 0, err
		}
		return slot.Value, uint64(slot.LastWritten), nil
	}
	_, content, _, err := rlp.Split(enc)
	if err != nil {
		return nil, 0, err
	}
	return content, 0, nil
}
