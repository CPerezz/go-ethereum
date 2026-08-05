# TODO

Known gaps in the EIP-8297 binary tree (PBT) work, recorded so they are not
rediscovered by accident.

## The engine API has no stateless-consume or witness-build path for the tree

`eth/catalyst/witness.go` has `NewPayloadWithWitnessV1` through **`V5`**,
`ExecuteStatelessPayloadV1` through `V4`, and `ForkchoiceUpdatedWithWitnessV1`
through `V3`. So *producing* a binary tree witness already works:
`NewPayloadWithWitnessV5` is gated on `forks.Amsterdam` and returns one on
payload insertion.

What is missing is the other two directions:

- **Consumption** — an `ExecuteStatelessPayloadV5`. `V4` stops at Bogota.
- **Requesting a build with a witness** — a `ForkchoiceUpdatedWithWitnessV4`.
  `V3` stops at Bogota too.

Both refuse cleanly meanwhile rather than misbehaving, because **Amsterdam is
absent from both fork gates**. `ExecuteStatelessPayloadV4` admits
`Prague, Osaka, BPO1-5, Bogota`, so a binary tree payload is rejected with
*"newPayloadV4 must only be called for prague/osaka payloads"* well before
reaching `ExecuteStateless`. `ForkchoiceUpdatedWithWitnessV3` admits that set
plus `Cancun`, and only checks it when payload attributes are present — which
is exactly the case that requests a build, so the gap that matters is covered.

Shape to copy: `TestWitnessCreationAndConsumption` (`eth/catalyst/api_test.go`)
drives the whole loop, but only at V3. The binary tree fixture to extend is
`TestPBTNodeProducesAndImportsBlocks` (`eth/catalyst/pbt_test.go`), which never
touches witnesses today.

## Code chunks belong in the code zone, not the account header stem

**This tree implements a superseded revision of EIP-8297.** The spec dropped
`CODE_OFFSET` on 2026-08-04 ("Move all code chunks into the code zone", then
"remove CODE_OFFSET and stale header-code references"). All code chunks are
now content-addressed in `CODE_ZONE` (`0x01`), and an account's header stem
holds only `BASIC_DATA` (sub 0), `CODE_HASH` (sub 1) and the first 64 storage
slots (subs 64-127). Subs 128-255 are unused there.

Here, `trie/bintrie/key_encoding.go` still has `CodeOffset = 128`, and
`CodeChunkIndex` puts chunks 0-127 at header subs 128-255; `UpdateContractCode`
(`trie/bintrie/trie.go`) writes them into `HeaderStem(addr)` and only spills
chunk 128 onward into `CodeChunkStem`. `DeleteAccount`'s header sweep assumes
the same layout.

This is consensus-level: every contract's state root changes. The migration
needs `CodeOffset` deleted, `CodeChunkIndex` returning the code zone for every
chunk, the header-chunk branch removed from `UpdateContractCode`, and
`testdata/eip8297_vectors.json` plus any fixtures regenerated. Two further
`CodeOffset` uses will stop compiling and are easy to miss: the header-storage
bound in `HasHeaderStorage` (`trie/bintrie/trie.go`) and the ordering invariant
in `key_encoding.go`'s `init()`. `DeleteAccount` needs nothing - `removeStem`
drops the whole stem without enumerating sub-indices. It also changes the
multiproof measurement below.

## The witness could be a multiproof

The witness ships the nodes a block resolved, which is the same shape as the
per-stem group records: about 26 KB to witness a whole 24 KiB contract, but
about 4.7 KB to witness reading one chunk of it. `trie/bintrie/multiproof.go`
answers the same single-chunk read in 672 B, roughly seven times smaller, and
real blocks read sparsely rather than densely.

**That is not a like-for-like comparison, and the difference is the whole
question.** The small figure came from reading the verified trie back with
`GetStemValue`, the key-shaped walk, which tolerates a stem that is only
partially covered. The `state.Trie` surface does not: `GetAccount` goes through
`getStemGroup`, which returns `ErrPartialStem` on an expanded stem, as do
`HasHeaderStorage` and both `Prefetch` methods. So a proof over exactly the
keys a block read verifies against the root, answers those keys, and still
cannot serve the account read every block performs: it has to carry every
sub-index resident in the stem, whatever the block actually touched.
`TestMultiproofMustCoverWholeHeaderStem` pins that. `GetStorage` goes through
`getValue` rather than `getStemGroup`, so storage reads do tolerate partial
stems and keep their advantage.

**The size of that penalty is not yet known, and earlier figures here were
withdrawn.** They were taken while code chunks 0-127 still lived in the account
header stem, a layout the spec has since dropped (see the code zone migration
below); post-migration a contract's header stem is at most 66 sub-indices and
typically 2. Two further corrections apply whenever it is re-taken:

- The stem's residency is sub-indices 0-1, 64-127 (storage slots 0-63) and,
  today, 128-255 (code chunks). A fixture that writes no storage measures only
  the floor. Price the worst case with storage slots 0-63 resident.
- The node-set baseline must count the paths. A binary witness ships them as a
  parallel array (`core/stateless/encoding.go`), so summing blob lengths alone
  understates the format the multiproof is being compared against.

The other half of the answer does not depend on the layout: moving
`GetAccount`/`HasHeaderStorage`/`Prefetch*` onto the key-shaped walk, so
partial stems are readable end to end, is what removes the whole-stem
requirement altogether. Whether that is worth doing is exactly what the
re-measurement decides.

Two other objections were raised against a key-set-derived witness and both
turn out not to apply to block execution (see
`core/pbt_witness_hard_cases_test.go`):

- **`DeletePrefix` cannot be expressed** — no whole-subtree token exists, and
  `deleteSubtree` resolves every record of a bucket with no early exit. But
  reaching it needs an account that owns committed storage and is then deleted,
  which `StateDB` refuses from Cancun onwards. The walk does still execute —
  deletion happens in `IntermediateRoot` and the refusal comes later, in
  `commit` — but the block is then rejected, so no *valid* block ever needs a
  witness to carry it.
- **The EIP-7610 emptiness probe** — rejection runs off a hardcoded per-chain
  address list, not a live `HasPrefix`, so nothing in block processing calls it.

**What does remain** is collapse. A deletion that empties a branch resolves its
sibling, which in a proof-built trie is nil-backed and therefore a hard
failure; which siblings those are follows the pre-state's shape rather than the
keys touched, and a multi-value group sibling re-folds at a new depth and needs
all of its values. That is unavoidable work for any key-set-derived format, and
it is reachable from ordinary `SSTORE`-to-zero. Note the tests above cover
only the cheap arms - a single-value group or a branch as the collapse
survivor. The multi-value case is *not* covered, because building it trips the
deletion-atomicity bug recorded below.

So swapping the format in needs: the partial-stem read path above, recording
which keys a block touched, covering written stems whole (`insStem` refuses a
write into a partially shipped stem), collapse-sibling coverage, and the
absence handling the multiproof already grew. `TestMultiproofSize` exists to
measure the swap when it happens. If the measurement is poor, close the idea —
the multiproof already earns its place in `eth_getProof`, where the caller
supplies the keys and never calls `GetAccount`.

## Two remaining unwitnessed paths to `stateObject.Code()`

`Witness.AddCode` is reached only from `StateDB.GetCode` and
`StateDB.GetCodeSize`, so a `stateObject.Code()` arriving by any other route
goes unrecorded. The replay then substitutes empty code and carries on, because
`setError` only latches and `IntermediateRoot` never consults it — a wrong root
reported as a good one.

The path that actually fired was `updateStateObject`, which asked for a code
size on every dirty account and loaded the whole contract to measure it. That
is fixed: the binary tree takes the size from the stem it is writing, the
merkle trie never needed it, and `core/stateless.go` now holds both trees to
the completeness check. Two dormant ones are left.

- `recordAccessListChanges` (`core/state/statedb.go`) calls `obj.Code()` under
  `state.codeSet`. Amsterdam/BAL only, and only for accounts with a journalled
  `SetCode`, whose blob is already in hand — so it does not reach the reader
  today. Note that this holds by a cache hit rather than by construction:
  `Code()` short-circuits on `len(s.code) != 0`.
- `ReaderWithBlockLevelAccessList.Code`/`CodeSize`
  (`core/state/reader_eip_7928.go`) read code below the `AddCode` layer
  entirely, falling through to the wrapped reader on an access-list miss.

Neither is reachable in a way that breaks a block today. Both would be found by
the same test shape that caught the first: a block that touches a contract it
never executes, replayed with the completeness check on.

## A consensus divergence: BAL replay does not reproduce EIP-161 clearing

**Not a PBT bug** - `applyBlockAccessList` is shared with the merkle trie. This
is the root cause of the "EIP-161 sweep gives a root mismatch on import"
symptom.

`supportsParallelExecution` (`core/state_processor_parallel.go`) requires
`!wantWitness && block.AccessList() != nil && IsAmsterdam`. So **whether a node
executes in parallel depends on whether it is building a witness**. On the
parallel path the canonical post-state is never executed - it is replayed from
the block access list (`ApplyBlockAccessList` then `IntermediateRoot`), while
each transaction runs against its own throwaway `StateDB`.

`applyBlockAccessList` skips every entry with nothing recorded
(`core/state/statedb_eip_7928.go`, `if !entry.mutated() { continue }`). A
zero-value call to an empty account changes neither balance nor nonce, so
`recordAccessListChanges` records nothing, the account never joins `accounts`,
is never materialised, and the `obj.empty()` sweep never sees it. The
sequential path deletes it via the journal touch in `Finalise`.

**Result: two honest nodes compute different state roots for the same block**,
differing only in whether witness collection was enabled. Reproduced on a PBT
chain: `GenerateChain` (sequential) yields `179e4145...`, `InsertChain`
(parallel) yields `6da5af9b...`; the header root is the correct one.

Also in the same function: the `obj.empty()` deletion is conditioned on neither
`IsEIP158` nor on the account having been touched, so the parallel path's
clearing rule is not EIP-161's rule in either direction - it may also delete
accounts EIP-161 would keep.

A fix has to carry the swept set out of the per-transaction executors - which
do run a real `Finalise` - into the canonical statedb between
`ApplyBlockAccessList` and `IntermediateRoot`. The alternative, recording the
sweep in the BAL, changes the BAL hash and is an EIP-7928 spec question. Before
deciding: confirm it reproduces on a plain merkle chain, and record which
routes can still produce an empty account within a block.

## Deletion in `BinaryTrie` is not atomic

A failed write leaves the tree corrupt, and the corruption is a crash rather
than a wrong answer.

`insStem`'s `*groupNode` arm empties the resident group **in place**, then
returns `empty{}`. The parent branch arm does not rewrite its child pointer,
because it expects `collapse` to replace the whole branch. But `collapse` can
fail - `t.resolve` errors and it returns **the branch**, with the zero-value
group still attached. `UpdateStem` then returns the error **without**
`t.root = root`, so a failed write is a half-applied write. `delStem` and
`delPrefix` share the shape. `s.trie.Hash()` later folds the empty group:
`index out of range [0] with length 0` in `groupNode.foldRange`.

Prover versus replay: on a real chain PBT reads come from flat state with the
prefetcher pre-resolving, so `collapse` never calls `resolve`.
`PBTWitnessDefaults` refuses flat state, so the replay resolves lazily and
`collapse` becomes a failing call site. Reproduced by a block that zeroes the
spread slots of a bucket while leaving a multi-value group behind - the shape
`core/pbt_witness_hard_cases_test.go` says it does not cover.

Severity is not settled. The mechanism needs a `resolve` failure, which a
*complete* witness should not produce, so this is most likely "an incomplete or
malicious witness panics the verifier instead of being rejected" rather than "a
valid block fails". Settle it by running the fixture with `-short`, which skips
the node-dropping loop.

Fix: guard `len(subs) == 0` in `groupNode.fold`; hoist the sibling resolution
out of `collapse` to before the destructive descent; and check `db.Error()`
*before* `IntermediateRoot` in `core/stateless.go` and `core/block_validator.go`
so a latched error stops the hash rather than crashing inside it.

## Two holes in the PBT read-prefetcher lose witness nodes

Under PBT the reader is flat-state-first, so an ordinary read resolves no trie
node. The only thing that puts read-only nodes into a witness is the
read-prefetcher, whose trie becomes `s.trie` in `IntermediateRoot` and whose
tracer is harvested. Any gap in prefetch coverage is therefore a hole in the
witness, and the failure is a **valid block rejected** in replay.

- **Storage slots are deduped globally, not per account.** `trieID` collapses
  to one sub-fetcher for PBT, but `seenReadSlot`/`seenWriteSlot`
  (`core/state/trie_prefetcher.go`) are keyed by the slot alone, and the dedup
  `continue` skips the `slots[task.owner]` append. Two accounts touching the
  same slot >= 64 means only the first is warmed. Under MPT each storage trie
  gets its own sub-fetcher, so the keys are naturally scoped. Fix: key by
  owner+slot, and the metrics and eviction with them.
- **Accounts created in the same block are never storage-prefetched.**
  `core/state/state_object.go` guards on `s.origin != nil`, nil for anything
  `evm.Create` made. True for MPT, where the read short-circuits on an empty
  storage root; false for PBT, where there is no per-account root and the read
  walks the shared tree. Trigger: any constructor reading a slot >= 64.

## The witness completeness check does not cover the path production takes

Two facts that only matter together:

- `executeTransactionsParallel` (`core/state_processor_parallel.go`) runs each
  transaction against its own `StateDB` and returns without ever consulting
  `sdb.Error()`; only the canonical statedb's error propagates. So on the
  parallel path the `db.Error()` check in `ExecuteStateless` sees the access
  list apply and the hashing, and nothing a transaction read.
- `types.Body` has no access-list field and `Block.WithBody` takes it from the
  receiver, so `NewBlockWithHeader(header).WithBody(...)` yields a nil-BAL
  block. That is how the task is built in stateless self-validation
  (`core/blockchain.go`) and was how every test built it, so they all run
  **sequential** - while the engine API builds its block with
  `.WithAccessListUnsafe` (`beacon/engine/types.go`) and runs **parallel**.

Net: the path production uses to consume a stateless payload was untested.
`TestStatelessContractCoinbaseMerkle` now attaches the access list and asserts
it, so at least one test takes that path, but the check still does not observe
what a transaction reads there. Closing it means propagating the per-transaction
states' errors.

## `stateObject.commit()` was not given `updateStateObject`'s gating

`updateStateObject` now declines both the code size and the code blob when
`dirtyCode` is set but the blob is empty under a real code hash.
`stateObject.commit()` still keys on `dirtyCode` alone, so in that same state it
writes an **empty blob under a real code hash** into the code store and poisons
the `CodeDB` cache, after which every `Code()` for that hash returns empty.

Latent: the only production `SetStorage` caller is the RPC override path and
none of its consumers commit. Fixing it at the source - `SetStorage` passing
`obj.Code()` - was tried and reverted, because `internal/ethapi/api.go` gives
`state.Error()` precedence over the result and a missing blob would then fail
an `eth_call` that works today. Gating `commit()` the same way is the
alternative.

## A resurrected account may inherit the dead contract's leaves

**Suspected, not confirmed.** Two different maps drive account destruction and
they disagree about a destroy-and-recreate of one address:

- The trie-level `DeleteAccount` (and so `DeletePrefix`) runs from the deletion
  arm of `IntermediateRoot`, which reads `s.mutations`. That map is keyed by
  address and `markDelete`/`markUpdate` overwrite each other, so a destroy
  followed by a recreate leaves a single `update` entry and `deleteStateObject`
  is never called for it.
- `handleDestruction` reads `s.stateObjectsDestruct` instead, so it *does* fire,
  cleans the flat store, and returns without touching the tree — its comment
  defers that to the `DeletePrefix` which, per the above, never runs.

If that reading is right, the recreated account inherits what nothing cleared.
That is more than it first looks, and less in one respect:

- **Header storage slots (subs 64-127)** survive unconditionally. Nothing else
  writes them.
- **The overflow storage bucket** survives too, and it is the big one - only
  `DeletePrefix` drops it, and by the argument above that never runs. It can be
  arbitrarily larger than the 64 header slots.
- **Code chunks** survive only a *code-free* resurrection. If the replacement
  deploys code, `UpdateContractCode` writes explicit nils across subs 128-255
  beyond the new code, cleaning them.

Either way the tree diverges from a fresh conversion of the same state, and
disagrees with flat state, which `handleDestruction` did clean.

`UpdateAccount`'s empty-code-hash guard covers exactly one leaf of this — the
code size — which is why `TestPBTCodeSizeWrites/recreated_after_destruct`
passes. Nothing covers the rest.

Cheapest probe: extend that subtest to assert on the chunks and header slots,
comparing against an independently built reference state rather than a scalar,
the way `TestPBTCodeShrink` does. If it goes red this is a state-root bug and
wants its own fix. Note the code zone migration above moves the chunks out of
the header stem, which changes the shape of this but not the storage-slot half.

## Is `code_size` worth putting in flat state?

Not for the write path — `UpdateAccount` preserves the resident size, which
costs an in-memory lookup on a group the write resolves anyway. The question is
the read path, where the cost is adversarially reachable.

`opExtCodeSize` (`core/vm/instructions.go`) reaches `StateDB.GetCodeSize`
(`core/state/statedb.go`), which reads the whole blob either way:

```go
if s.witness != nil {
    s.witness.AddCode(stateObject.Code())   // building a witness: the blob, always
}
return stateObject.CodeSize()               // otherwise: a full read on a cold cache
```

These are alternatives rather than two costs on one call. `Code()` caches into
`stateObject.code`, so once `AddCode` has run the following `CodeSize()` returns
from memory and never reaches the reader. With no witness being built,
`CodeReader.CodeSize` (`core/state/database_code.go`) consults a size-only cache
first, so a warm node answers cheaply and a cold one does `len(r.Code(...))` —
reading the entire bytecode to learn its length.

The witness line is the serious one, because no cache spares it: whenever a
witness is being built the blob goes in. A block whose transactions do nothing
but `EXTCODESIZE` against many large contracts drags every one of their
bytecodes into the witness while reading no code at all. At Amsterdam's
`params.MaxCodeSizeAmsterdam` (64 KiB, enforced in `core/vm/common.go`) that is
megabyte-scale amplification for a block that learned nothing but a handful of
integers.

`code_size` in flat state would let both the read and the witness carry four
bytes instead of the blob. It is not free: flat state persists
`types.SlimAccount`, so this is a stored-format change requiring regeneration
on every node.

**Measure before deciding.** Build the adversarial block — many distinct large
contracts, `EXTCODESIZE` only, nothing warm — and compare its witness size and
execution time against a block doing the same number of ordinary reads. That
ratio decides whether the format change earns itself. Do not change
`types.StateAccount` instead: PBT reads accounts through flat state first, so
a field the flat reader cannot fill arrives zero and would erase the size it
was added to carry.

## Witness statistics have no binary-aware histogram

`--vmwitnessstats` is refused on the binary tree
(`core/blockchain.go triedbConfig`) because `WitnessStats` reads a node's path
as a nibble string and its depth as that string's length, bucketed into a fixed
sixteen levels. A binary path is a two-byte bit count followed by packed bits,
so the depth is wrong immediately and passes sixteen after 113 bits.

Making it work needs the bit count read out of the path encoding and a
histogram wider than `trie.LevelStats`'s fixed sixteen. Refusing only stops the
crash.

## Also deferred, for context

These are known and tracked elsewhere; listed so this file is the single place
to look.

- **The code zone (`0x01`) has no coverage against the reference vectors.**
  `trie/bintrie/multiproof_test.go`'s `TestCodeZoneKeyVerifies` proves a
  `CODE_ZONE` key against a real root, so the zone is no longer unverified
  outright. What is still missing is spec conformance: counting the leading
  zone byte of every hashed entry in `trie/bintrie/testdata/eip8297_vectors.json`
  gives 601 for accounts (`0x00`) and 266 for storage (`0xFF`), and **zero** for
  content-addressed code, which appears only under `embedding_vectors.chunks` —
  key derivation, never a root. Closing it needs a re-export from the reference
  implementation via `testdata/export_vectors.py`, so it belongs to the
  EEST/EELS integration phase.
- **One harness blocker before EEST fixtures can run.** `execBlockTest`
  (`tests/block_test.go`) runs every fixture under both the hash and path
  schemes, and the binary tree hard-fails on anything but path. It also always
  requests witness building, which used to be a second blocker; the tree
  supports that now.
- **`TestT8n`** fails on the binary tree fixtures because the prestate is
  reopened with an already-committed trie. Out of scope by instruction.
- **`StackBuilder`** (`trie/bintrie/stackbuilder.go`) has no production caller.
  Its natural consumer is the offline conversion in `cmd/geth`, which still
  inserts one stem at a time. Revisit when conversion is benchmarked; delete if
  still unwired.
