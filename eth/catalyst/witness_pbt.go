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

package catalyst

import (
	"context"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/forks"
)

// The Amsterdam witness endpoints. They live apart from witness.go so that file
// stays close to upstream across merges.

var statelessInvalidStatus = engine.StatelessPayloadStatusV1{Status: engine.INVALID}

// NewPayloadWithWitnessV5 is analogous to NewPayloadV5, only it also generates
// and returns a stateless witness after running the payload.
func (api *ConsensusAPI) NewPayloadWithWitnessV5(ctx context.Context, params engine.ExecutableData, versionedHashes []common.Hash, beaconRoot *common.Hash, executionRequests []hexutil.Bytes) (engine.PayloadStatusV1, error) {
	switch {
	case params.Withdrawals == nil:
		return invalidStatus, paramsErr("nil withdrawals post-shanghai")
	case params.ExcessBlobGas == nil:
		return invalidStatus, paramsErr("nil excessBlobGas post-cancun")
	case params.BlobGasUsed == nil:
		return invalidStatus, paramsErr("nil blobGasUsed post-cancun")
	case versionedHashes == nil:
		return invalidStatus, paramsErr("nil versionedHashes post-cancun")
	case beaconRoot == nil:
		return invalidStatus, paramsErr("nil beaconRoot post-cancun")
	case executionRequests == nil:
		return invalidStatus, paramsErr("nil executionRequests post-prague")
	case params.BlockAccessList == nil:
		return invalidStatus, paramsErr("nil block access list post-amsterdam")
	case params.SlotNumber == nil:
		return invalidStatus, paramsErr("nil slotnumber post-amsterdam")
	case !api.checkFork(params.Timestamp, forks.Amsterdam):
		return invalidStatus, unsupportedForkErr("newPayloadV5 must only be called for amsterdam payloads")
	}
	requests := convertRequests(executionRequests)
	if err := validateRequests(requests); err != nil {
		return engine.PayloadStatusV1{Status: engine.INVALID}, engine.InvalidParams.With(err)
	}
	return api.newPayload(ctx, params, versionedHashes, beaconRoot, requests, true)
}

// ExecuteStatelessPayloadV5 is analogous to NewPayloadV5, only it operates in
// a stateless mode on top of a provided witness instead of the local database.
func (api *ConsensusAPI) ExecuteStatelessPayloadV5(params engine.ExecutableData, versionedHashes []common.Hash, beaconRoot *common.Hash, executionRequests []hexutil.Bytes, opaqueWitness hexutil.Bytes) (engine.StatelessPayloadStatusV1, error) {
	switch {
	case params.Withdrawals == nil:
		return statelessInvalidStatus, paramsErr("nil withdrawals post-shanghai")
	case params.ExcessBlobGas == nil:
		return statelessInvalidStatus, paramsErr("nil excessBlobGas post-cancun")
	case params.BlobGasUsed == nil:
		return statelessInvalidStatus, paramsErr("nil blobGasUsed post-cancun")
	case versionedHashes == nil:
		return statelessInvalidStatus, paramsErr("nil versionedHashes post-cancun")
	case beaconRoot == nil:
		return statelessInvalidStatus, paramsErr("nil beaconRoot post-cancun")
	case executionRequests == nil:
		return statelessInvalidStatus, paramsErr("nil executionRequests post-prague")
	case params.SlotNumber == nil:
		return statelessInvalidStatus, paramsErr("nil slotnumber post-amsterdam")
	case params.BlockAccessList == nil:
		return statelessInvalidStatus, paramsErr("nil block access list post-amsterdam")
	case !api.checkFork(params.Timestamp, forks.Amsterdam):
		return statelessInvalidStatus, unsupportedForkErr("executeStatelessPayloadV5 must only be called for amsterdam payloads")
	}
	requests := convertRequests(executionRequests)
	if err := validateRequests(requests); err != nil {
		return statelessInvalidStatus, engine.InvalidParams.With(err)
	}
	return api.executeStatelessPayload(params, versionedHashes, beaconRoot, requests, opaqueWitness)
}

// ForkchoiceUpdatedWithWitnessV4 is analogous to ForkchoiceUpdatedV4, only it
// generates an execution witness too if block building was requested.
func (api *ConsensusAPI) ForkchoiceUpdatedWithWitnessV4(ctx context.Context, update engine.ForkchoiceStateV1, params *engine.PayloadAttributes, custodyColumns *types.CustodyBitmap) (engine.ForkChoiceResponse, error) {
	if params != nil {
		switch {
		case params.Withdrawals == nil:
			return engine.STATUS_INVALID, attributesErr("missing withdrawals")
		case params.BeaconRoot == nil:
			return engine.STATUS_INVALID, attributesErr("missing beacon root")
		case params.SlotNumber == nil:
			return engine.STATUS_INVALID, attributesErr("missing slot number")
		case params.TargetGasLimit == nil:
			return engine.STATUS_INVALID, attributesErr("missing target gas limit")
		case !api.checkFork(params.Timestamp, forks.Amsterdam):
			return engine.STATUS_INVALID, unsupportedForkErr("fcuV4 must only be called for amsterdam payloads")
		}
	}
	if custodyColumns != nil {
		api.eth.BlobFetcher().UpdateCustody(*custodyColumns)
	}
	return api.forkchoiceUpdated(ctx, update, params, engine.PayloadV4, true)
}
