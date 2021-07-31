package consensus

import (
	"time"

	"go.sia.tech/core/types"
)

// SiafundCount is the number of siafunds in existence.
const SiafundCount = 10000

// BlockInterval is the expected wall clock time between consecutive blocks.
const BlockInterval = 10 * time.Minute

func updateOakTotals(oakTime, newTime time.Duration, oakWork, newWork types.Work) (time.Duration, types.Work) {
	// decay totals by 0.5% before adding the new values
	decayedTime := oakTime - (oakTime / 200) + newTime
	decayedWork := oakWork.Sub(oakWork.Div64(200)).Add(newWork)
	return decayedTime, decayedWork
}

func adjustDifficulty(difficulty types.Work, height uint64, actualTime time.Duration, oakTime time.Duration, oakWork types.Work) types.Work {
	// NOTE: To avoid overflow/underflow issues, this function operates on
	// integer seconds (rather than time.Duration, which uses nanoseconds). This
	// shouldn't appreciably affect the precision of the algorithm.

	const blockInterval = BlockInterval / time.Second
	expectedTime := blockInterval * time.Duration(height)
	delta := (expectedTime - actualTime) / time.Second
	// square the delta and preserve its sign
	shift := delta * delta
	if delta < 0 {
		shift = -shift
	}
	// scale such that a delta of 10,000 produces a shift of 10 seconds
	shift *= 10
	shift /= 10000 * 10000

	// calculate the new target block time, clamped to a factor of 3
	targetBlockTime := blockInterval + shift
	if min := blockInterval / 3; targetBlockTime < min {
		targetBlockTime = min
	} else if max := blockInterval * 3; targetBlockTime > max {
		targetBlockTime = max
	}

	// estimate the hashrate from the (decayed) total work and the (decayed,
	// clamped) total time
	if oakTime <= time.Second {
		oakTime = time.Second
	}
	estimatedHashrate := oakWork.Div64(uint64(oakTime / time.Second))

	// multiply the estimated hashrate by the target block time; this is the
	// expected number of hashes required to produce the next block, i.e. the
	// new difficulty
	newDifficulty := estimatedHashrate.Mul64(uint64(targetBlockTime))

	// clamp the adjustment to 0.4%
	maxAdjust := difficulty.Div64(250)
	if min := difficulty.Sub(maxAdjust); newDifficulty.Cmp(min) < 0 {
		newDifficulty = min
	} else if max := difficulty.Add(maxAdjust); newDifficulty.Cmp(max) > 0 {
		newDifficulty = max
	}
	return newDifficulty
}

func applyHeader(vc ValidationContext, h types.BlockHeader) ValidationContext {
	if h.Height == 0 {
		// special handling for GenesisUpdate
		vc.PrevTimestamps[0] = h.Timestamp
		vc.History.AppendLeaf(h.Index())
		vc.Index = h.Index()
		return vc
	}
	blockWork := types.WorkRequiredForHash(h.ID())
	vc.TotalWork = vc.TotalWork.Add(blockWork)
	parentTimestamp := vc.PrevTimestamps[vc.numTimestamps()-1]
	vc.OakTime, vc.OakWork = updateOakTotals(vc.OakTime, h.Timestamp.Sub(parentTimestamp), vc.OakWork, blockWork)
	vc.Difficulty = adjustDifficulty(vc.Difficulty, h.Height, h.Timestamp.Sub(vc.GenesisTimestamp), vc.OakTime, vc.OakWork)
	if vc.numTimestamps() < len(vc.PrevTimestamps) {
		vc.PrevTimestamps[vc.numTimestamps()] = h.Timestamp
	} else {
		copy(vc.PrevTimestamps[:], vc.PrevTimestamps[1:])
		vc.PrevTimestamps[len(vc.PrevTimestamps)-1] = h.Timestamp
	}
	vc.History.AppendLeaf(h.Index())
	vc.Index = h.Index()
	return vc
}

func updatedInBlock(vc ValidationContext, b types.Block) (scos []types.SiacoinOutput, sfos []types.SiafundOutput, objects []stateObject) {
	addObject := func(so stateObject) {
		// copy proofs so we don't mutate transaction data
		so.proof = append([]types.Hash256(nil), so.proof...)
		objects = append(objects, so)
	}

	for _, txn := range b.Transactions {
		for _, in := range txn.SiacoinInputs {
			scos = append(scos, in.Parent)
			if in.Parent.LeafIndex != types.EphemeralLeafIndex {
				addObject(siacoinOutputStateObject(in.Parent, flagSpent))
			}
		}
		for _, in := range txn.SiafundInputs {
			sfos = append(sfos, in.Parent)
			if in.Parent.LeafIndex != types.EphemeralLeafIndex {
				addObject(siafundOutputStateObject(in.Parent, flagSpent))
			}
		}
	}

	return
}

func createdInBlock(vc ValidationContext, b types.Block) (scos []types.SiacoinOutput, sfos []types.SiafundOutput, objects []stateObject) {
	flags := make(map[types.OutputID]uint64)
	for _, txn := range b.Transactions {
		for _, in := range txn.SiacoinInputs {
			if in.Parent.LeafIndex == types.EphemeralLeafIndex {
				flags[in.Parent.ID] = flagSpent
			}
		}
	}
	addSiacoinOutput := func(o types.SiacoinOutput) {
		scos = append(scos, o)
		objects = append(objects, siacoinOutputStateObject(o, flags[o.ID]))
	}
	addSiafundOutput := func(o types.SiafundOutput) {
		sfos = append(sfos, o)
		objects = append(objects, siafundOutputStateObject(o, flags[o.ID]))
	}

	addSiacoinOutput(types.SiacoinOutput{
		ID: types.OutputID{
			TransactionID: types.TransactionID(b.ID()),
			Index:         0,
		},
		Value:    vc.BlockReward(),
		Address:  b.Header.MinerAddress,
		Timelock: vc.BlockRewardTimelock(),
	})
	if subsidy := vc.FoundationSubsidy(); !subsidy.IsZero() {
		addSiacoinOutput(types.SiacoinOutput{
			ID: types.OutputID{
				TransactionID: types.TransactionID(b.ID()),
				Index:         1,
			},
			Value:    subsidy,
			Address:  vc.FoundationAddress,
			Timelock: vc.BlockRewardTimelock(),
		})
	}
	for _, txn := range b.Transactions {
		txid := txn.ID()
		var index uint64
		nextID := func() types.OutputID {
			id := types.OutputID{
				TransactionID: txid,
				Index:         index,
			}
			index++
			return id
		}

		for _, out := range txn.SiacoinOutputs {
			addSiacoinOutput(types.SiacoinOutput{
				ID:       nextID(),
				Value:    out.Value,
				Address:  out.Address,
				Timelock: 0,
			})
		}
		for _, in := range txn.SiafundInputs {
			addSiacoinOutput(types.SiacoinOutput{
				ID: nextID(),
				// TODO: don't create zero-valued claim outputs?
				Value:    vc.SiafundPool.Sub(in.Parent.ClaimStart).Div64(SiafundCount).Mul64(in.Parent.Value.Lo),
				Address:  in.ClaimAddress,
				Timelock: vc.BlockRewardTimelock(), // TODO: define a separate method for this?
			})
		}
		for _, out := range txn.SiafundOutputs {
			addSiafundOutput(types.SiafundOutput{
				ID:         nextID(),
				Value:      out.Value,
				Address:    out.Address,
				ClaimStart: vc.SiafundPool,
			})
		}
	}

	return
}

// A StateApplyUpdate reflects the changes to consensus state resulting from the
// application of a block.
type StateApplyUpdate struct {
	Context             ValidationContext
	SpentSiacoinOutputs []types.SiacoinOutput
	NewSiacoinOutputs   []types.SiacoinOutput
	SpentSiafundOutputs []types.SiafundOutput
	NewSiafundOutputs   []types.SiafundOutput
	updatedObjects      [64][]stateObject
	treeGrowth          [64][]types.Hash256
}

// SiacoinOutputWasSpent returns true if the given SiacoinOutput was spent.
func (sau *StateApplyUpdate) SiacoinOutputWasSpent(o types.SiacoinOutput) bool {
	for i := range sau.SpentSiacoinOutputs {
		if sau.SpentSiacoinOutputs[i].LeafIndex == o.LeafIndex {
			return true
		}
	}
	return false
}

// SiafundOutputWasSpent returns true if the given SiafundOutput was spent.
func (sau *StateApplyUpdate) SiafundOutputWasSpent(o types.SiafundOutput) bool {
	for i := range sau.SpentSiafundOutputs {
		if sau.SpentSiafundOutputs[i].LeafIndex == o.LeafIndex {
			return true
		}
	}
	return false
}

// UpdateSiacoinOutputProof updates the Merkle proof of the supplied output to
// incorporate the changes made to the state tree. The output's proof must be
// up-to-date; if it is not, UpdateSiacoinOutputProof may panic.
func (sau *StateApplyUpdate) UpdateSiacoinOutputProof(o *types.SiacoinOutput) {
	updateProof(o.MerkleProof, o.LeafIndex, &sau.updatedObjects)
	o.MerkleProof = append(o.MerkleProof, sau.treeGrowth[len(o.MerkleProof)]...)
}

// UpdateSiafundOutputProof updates the Merkle proof of the supplied output to
// incorporate the changes made to the state tree. The output's proof must be
// up-to-date; if it is not, UpdateSiafundOutputProof may panic.
func (sau *StateApplyUpdate) UpdateSiafundOutputProof(o *types.SiafundOutput) {
	updateProof(o.MerkleProof, o.LeafIndex, &sau.updatedObjects)
	o.MerkleProof = append(o.MerkleProof, sau.treeGrowth[len(o.MerkleProof)]...)
}

// ApplyBlock integrates a block into the current consensus state, producing
// a StateApplyUpdate detailing the resulting changes. The block is assumed to
// be fully validated.
func ApplyBlock(vc ValidationContext, b types.Block) (sau StateApplyUpdate) {
	sau.Context = applyHeader(vc, b.Header)

	var updated, created []stateObject
	sau.SpentSiacoinOutputs, sau.SpentSiafundOutputs, updated = updatedInBlock(vc, b)
	sau.NewSiacoinOutputs, sau.NewSiafundOutputs, created = createdInBlock(vc, b)

	sau.updatedObjects = sau.Context.State.updateExistingObjects(updated)
	sau.treeGrowth = sau.Context.State.addNewObjects(created)
	for i := range sau.NewSiacoinOutputs {
		sau.NewSiacoinOutputs[i].LeafIndex = created[0].leafIndex
		sau.NewSiacoinOutputs[i].MerkleProof = created[0].proof
		created = created[1:]
	}
	for i := range sau.NewSiafundOutputs {
		sau.NewSiafundOutputs[i].LeafIndex = created[0].leafIndex
		sau.NewSiafundOutputs[i].MerkleProof = created[0].proof
		created = created[1:]
	}

	for _, txn := range b.Transactions {
		if txn.NewFoundationAddress != types.VoidAddress {
			sau.Context.FoundationAddress = txn.NewFoundationAddress
		}
	}

	return
}

// GenesisUpdate returns the StateApplyUpdate for the genesis block b.
func GenesisUpdate(b types.Block, initialDifficulty types.Work) StateApplyUpdate {
	return ApplyBlock(ValidationContext{
		Difficulty:       initialDifficulty,
		GenesisTimestamp: b.Header.Timestamp,
	}, b)
}

// A StateRevertUpdate reflects the changes to consensus state resulting from the
// removal of a block.
type StateRevertUpdate struct {
	Context             ValidationContext
	SpentSiacoinOutputs []types.SiacoinOutput
	NewSiacoinOutputs   []types.SiacoinOutput
	SpentSiafundOutputs []types.SiafundOutput
	NewSiafundOutputs   []types.SiafundOutput
	updatedObjects      [64][]stateObject
}

// SiacoinOutputWasRemoved returns true if the specified SiacoinOutput was
// reverted.
func (sru *StateRevertUpdate) SiacoinOutputWasRemoved(o types.SiacoinOutput) bool {
	return o.LeafIndex >= sru.Context.State.NumLeaves
}

// SiafundOutputWasRemoved returns true if the specified SiafundOutput was
// reverted.
func (sru *StateRevertUpdate) SiafundOutputWasRemoved(o types.SiafundOutput) bool {
	return o.LeafIndex >= sru.Context.State.NumLeaves
}

// UpdateSiacoinOutputProof updates the Merkle proof of the supplied output to
// incorporate the changes made to the state tree. The output's proof must be
// up-to-date; if it is not, UpdateSiacoinOutputProof may panic.
func (sru *StateRevertUpdate) UpdateSiacoinOutputProof(o *types.SiacoinOutput) {
	if mh := mergeHeight(sru.Context.State.NumLeaves, o.LeafIndex); mh <= len(o.MerkleProof) {
		o.MerkleProof = o.MerkleProof[:mh-1]
	}
	updateProof(o.MerkleProof, o.LeafIndex, &sru.updatedObjects)
}

// UpdateSiafundOutputProof updates the Merkle proof of the supplied output to
// incorporate the changes made to the state tree. The output's proof must be
// up-to-date; if it is not, UpdateSiafundOutputProof may panic.
func (sru *StateRevertUpdate) UpdateSiafundOutputProof(o *types.SiafundOutput) {
	if mh := mergeHeight(sru.Context.State.NumLeaves, o.LeafIndex); mh <= len(o.MerkleProof) {
		o.MerkleProof = o.MerkleProof[:mh-1]
	}
	updateProof(o.MerkleProof, o.LeafIndex, &sru.updatedObjects)
}

// RevertBlock produces a StateRevertUpdate from a block and the
// ValidationContext prior to that block.
func RevertBlock(vc ValidationContext, b types.Block) (sru StateRevertUpdate) {
	sru.Context = vc
	sru.SpentSiacoinOutputs, sru.SpentSiafundOutputs, _ = updatedInBlock(vc, b)
	sru.NewSiacoinOutputs, sru.NewSiafundOutputs, _ = createdInBlock(vc, b)
	sru.updatedObjects = objectsByTree(b.Transactions)
	return
}
