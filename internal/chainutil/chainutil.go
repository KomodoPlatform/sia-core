package chainutil

import (
	"crypto/ed25519"
	"encoding/binary"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

// FindBlockNonce finds a block nonce meeting the target.
func FindBlockNonce(h *types.BlockHeader, target types.BlockID) {
	for !h.ID().MeetsTarget(target) {
		binary.LittleEndian.PutUint64(h.Nonce[:], binary.LittleEndian.Uint64(h.Nonce[:])+1)
	}
}

// JustHeaders renters only the headers of each block.
func JustHeaders(blocks []types.Block) []types.BlockHeader {
	headers := make([]types.BlockHeader, len(blocks))
	for i := range headers {
		headers[i] = blocks[i].Header
	}
	return headers
}

// JustTransactions returns only the transactions of each block.
func JustTransactions(blocks []types.Block) [][]types.Transaction {
	txns := make([][]types.Transaction, len(blocks))
	for i := range txns {
		txns[i] = blocks[i].Transactions
	}
	return txns
}

// JustTransactionIDs returns only the transaction ids included in each block.
func JustTransactionIDs(blocks []types.Block) [][]types.TransactionID {
	txns := make([][]types.TransactionID, len(blocks))
	for i := range txns {
		txns[i] = make([]types.TransactionID, len(blocks[i].Transactions))
		for j := range txns[i] {
			txns[i][j] = blocks[i].Transactions[j].ID()
		}
	}
	return txns
}

// JustChainIndexes returns only the chain index of each block.
func JustChainIndexes(blocks []types.Block) []types.ChainIndex {
	cis := make([]types.ChainIndex, len(blocks))
	for i := range cis {
		cis[i] = blocks[i].Index()
	}
	return cis
}

// ChainSim represents a simulation of a blockchain.
type ChainSim struct {
	Genesis consensus.Checkpoint
	Chain   []types.Block
	Context consensus.ValidationContext

	nonce [8]byte // for distinguishing forks

	// for simulating transactions
	pubkey  types.PublicKey
	privkey ed25519.PrivateKey
	outputs []types.SiacoinOutput
}

// Fork forks the current chain.
func (cs *ChainSim) Fork() *ChainSim {
	cs2 := *cs
	cs2.Chain = append([]types.Block(nil), cs2.Chain...)
	cs2.outputs = append([]types.SiacoinOutput(nil), cs2.outputs...)
	if cs.nonce[7]++; cs.nonce[7] == 0 {
		cs.nonce[6]++
	}
	return &cs2
}

//MineBlockWithTxns mine a block with the given transaction.
func (cs *ChainSim) MineBlockWithTxns(txns ...types.Transaction) types.Block {
	prev := cs.Genesis.Block.Header
	if len(cs.Chain) > 0 {
		prev = cs.Chain[len(cs.Chain)-1].Header
	}
	b := types.Block{
		Header: types.BlockHeader{
			Height:       prev.Height + 1,
			ParentID:     prev.ID(),
			Nonce:        cs.nonce,
			Timestamp:    prev.Timestamp.Add(time.Second),
			MinerAddress: types.VoidAddress,
		},
		Transactions: txns,
	}
	b.Header.Commitment = cs.Context.Commitment(b.Header.MinerAddress, b.Transactions)
	FindBlockNonce(&b.Header, types.HashRequiringWork(cs.Context.Difficulty))

	sau := consensus.ApplyBlock(cs.Context, b)
	cs.Context = sau.Context
	cs.Chain = append(cs.Chain, b)

	// update our outputs
	for i := range cs.outputs {
		sau.UpdateSiacoinOutputProof(&cs.outputs[i])
	}
	for _, out := range sau.NewSiacoinOutputs {
		if out.Address == types.StandardAddress(cs.pubkey) {
			cs.outputs = append(cs.outputs, out)
		}
	}

	return b
}

// MineBlockWithBeneficiaries mine a block with a transaction sending siacoin
// to each beneficiary. Requires enough funds to cover the siacoin outputs.
func (cs *ChainSim) MineBlockWithBeneficiaries(bs ...types.Beneficiary) types.Block {
	txn := types.Transaction{
		SiacoinOutputs: bs,
		MinerFee:       types.NewCurrency64(cs.Context.Index.Height),
	}

	totalOut := txn.MinerFee
	for _, b := range bs {
		totalOut = totalOut.Add(b.Value)
	}

	// select inputs and compute change output
	var totalIn types.Currency
	for i, out := range cs.outputs {
		txn.SiacoinInputs = append(txn.SiacoinInputs, types.SiacoinInput{
			Parent:      out,
			SpendPolicy: types.PolicyPublicKey(cs.pubkey),
		})
		totalIn = totalIn.Add(out.Value)
		if totalIn.Cmp(totalOut) >= 0 {
			cs.outputs = cs.outputs[i+1:]
			break
		}
	}

	if totalIn.Cmp(totalOut) < 0 {
		panic("insufficient funds")
	} else if totalIn.Cmp(totalOut) > 0 {
		// add change output
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.Beneficiary{
			Address: types.StandardAddress(cs.pubkey),
			Value:   totalIn.Sub(totalOut),
		})
	}

	// sign and mine
	sigHash := cs.Context.SigHash(txn)
	for i := range txn.SiacoinInputs {
		txn.SiacoinInputs[i].Signatures = []types.InputSignature{types.InputSignature(types.SignHash(cs.privkey, sigHash))}
	}
	return cs.MineBlockWithTxns(txn)
}

// MineBlock mine an empty block.
func (cs *ChainSim) MineBlock() types.Block {
	// simulate chain activity by sending our existing outputs to new addresses
	var txns []types.Transaction
	for _, out := range cs.outputs {
		txn := types.Transaction{
			SiacoinInputs: []types.SiacoinInput{{
				Parent:      out,
				SpendPolicy: types.PolicyPublicKey(cs.pubkey),
			}},
			SiacoinOutputs: []types.Beneficiary{
				{Address: types.StandardAddress(cs.pubkey), Value: out.Value.Sub(types.NewCurrency64(cs.Context.Index.Height + 1))},
				{Address: types.Address{cs.nonce[6], cs.nonce[7], 1, 2, 3}, Value: types.NewCurrency64(1)},
			},
			MinerFee: types.NewCurrency64(cs.Context.Index.Height),
		}
		sigHash := cs.Context.SigHash(txn)
		for i := range txn.SiacoinInputs {
			txn.SiacoinInputs[i].Signatures = []types.InputSignature{types.InputSignature(types.SignHash(cs.privkey, sigHash))}
		}

		txns = append(txns, txn)
	}
	cs.outputs = cs.outputs[:0]
	return cs.MineBlockWithTxns(txns...)
}

// MineBlocks mine a number of blocks.
func (cs *ChainSim) MineBlocks(n int) []types.Block {
	blocks := make([]types.Block, n)
	for i := range blocks {
		blocks[i] = cs.MineBlock()
	}
	return blocks
}

// NewChainSim returns a new ChainSim useful for simulating forks.
func NewChainSim() *ChainSim {
	// gift ourselves some coins in the genesis block
	privkey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	var pubkey types.PublicKey
	copy(pubkey[:], privkey[32:])
	ourAddr := types.StandardAddress(pubkey)
	gift := make([]types.Beneficiary, 10)
	for i := range gift {
		gift[i] = types.Beneficiary{
			Address: ourAddr,
			Value:   types.Siacoins(10 * uint32(i+1)),
		}
	}
	genesisTxns := []types.Transaction{{SiacoinOutputs: gift}}
	genesis := types.Block{
		Header: types.BlockHeader{
			Timestamp: time.Unix(734600000, 0),
		},
		Transactions: genesisTxns,
	}
	sau := consensus.GenesisUpdate(genesis, types.Work{NumHashes: [32]byte{31: 4}})
	var outputs []types.SiacoinOutput
	for _, out := range sau.NewSiacoinOutputs {
		if out.Address == types.StandardAddress(pubkey) {
			outputs = append(outputs, out)
		}
	}
	return &ChainSim{
		Genesis: consensus.Checkpoint{
			Block:   genesis,
			Context: sau.Context,
		},
		Context: sau.Context,
		privkey: privkey,
		pubkey:  pubkey,
		outputs: outputs,
	}
}
