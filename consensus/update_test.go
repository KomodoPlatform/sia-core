package consensus_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

func TestApplyBlock(t *testing.T) {
	n, genesisBlock := chain.TestnetZen()

	n.InitialTarget = types.BlockID{0xFF}

	giftPrivateKey := types.GeneratePrivateKey()
	giftPublicKey := giftPrivateKey.PublicKey()
	giftAddress := types.StandardUnlockHash(giftPublicKey)
	giftAmountSC := types.Siacoins(100)
	giftAmountSF := uint64(100)
	giftTxn := types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: giftAddress, Value: giftAmountSC},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Address: giftAddress, Value: giftAmountSF},
		},
	}
	genesisBlock.Transactions = []types.Transaction{giftTxn}

	dbStore, checkpoint, err := chain.NewDBStore(chain.NewMemDB(), n, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer dbStore.Close()
	cs := checkpoint.State

	signTxn := func(txn *types.Transaction) {
		appendSig := func(parentID types.Hash256) {
			sig := giftPrivateKey.SignHash(cs.WholeSigHash(*txn, parentID, 0, 0, nil))
			txn.Signatures = append(txn.Signatures, types.TransactionSignature{
				ParentID:       parentID,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
				PublicKeyIndex: 0,
				Signature:      sig[:],
			})
		}
		for i := range txn.SiacoinInputs {
			appendSig(types.Hash256(txn.SiacoinInputs[i].ParentID))
		}
		for i := range txn.SiafundInputs {
			appendSig(types.Hash256(txn.SiafundInputs[i].ParentID))
		}
		for i := range txn.FileContractRevisions {
			appendSig(types.Hash256(txn.FileContractRevisions[i].ParentID))
		}
	}
	addBlock := func(b types.Block) (diff consensus.BlockDiff, err error) {
		if err = consensus.ValidateBlock(cs, dbStore, b); err != nil {
			return
		}
		diff = consensus.ApplyDiff(cs, dbStore, b)
		cs = consensus.ApplyState(cs, dbStore, b)
		return
	}

	// block with nothing except block reward
	b1 := types.Block{
		ParentID:     genesisBlock.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
	}
	expect := consensus.BlockDiff{
		CreatedSiacoinElements: []types.SiacoinElement{
			{
				StateElement:   types.StateElement{ID: types.Hash256(b1.ID().MinerOutputID(0))},
				SiacoinOutput:  b1.MinerPayouts[0],
				MaturityHeight: cs.MaturityHeight(),
			},
		},
	}
	if diff, err := addBlock(b1); err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(diff, expect) {
		js1, _ := json.MarshalIndent(diff, "", "  ")
		js2, _ := json.MarshalIndent(expect, "", "  ")
		t.Fatalf("diff doesn't match:\n%s\nvs\n%s\n", js1, js2)
	}

	// block that spends part of the gift transaction
	txnB2 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         giftTxn.SiacoinOutputID(0),
			UnlockConditions: types.StandardUnlockConditions(giftPublicKey),
		}},
		SiafundInputs: []types.SiafundInput{{
			ParentID:         giftTxn.SiafundOutputID(0),
			ClaimAddress:     types.VoidAddress,
			UnlockConditions: types.StandardUnlockConditions(giftPublicKey),
		}},
		SiacoinOutputs: []types.SiacoinOutput{
			{Value: giftAmountSC.Div64(2), Address: giftAddress},
			{Value: giftAmountSC.Div64(2), Address: types.VoidAddress},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Value: giftAmountSF / 2, Address: giftAddress},
			{Value: giftAmountSF / 2, Address: types.VoidAddress},
		},
	}
	signTxn(&txnB2)
	b2 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		Transactions: []types.Transaction{txnB2},
	}
	expect = consensus.BlockDiff{
		Transactions: []consensus.TransactionDiff{{
			CreatedSiacoinElements: []types.SiacoinElement{
				{StateElement: types.StateElement{ID: types.Hash256(txnB2.SiacoinOutputID(0))}, SiacoinOutput: txnB2.SiacoinOutputs[0]},
				{StateElement: types.StateElement{ID: types.Hash256(txnB2.SiacoinOutputID(1))}, SiacoinOutput: txnB2.SiacoinOutputs[1]},
				{
					StateElement:   types.StateElement{ID: types.Hash256(giftTxn.SiafundOutputID(0).ClaimOutputID())},
					SiacoinOutput:  types.SiacoinOutput{Value: types.NewCurrency64(0), Address: txnB2.SiafundInputs[0].ClaimAddress},
					MaturityHeight: cs.MaturityHeight(),
				},
			},
			SpentSiacoinElements: []types.SiacoinElement{
				{StateElement: types.StateElement{ID: types.Hash256(giftTxn.SiacoinOutputID(0))}, SiacoinOutput: giftTxn.SiacoinOutputs[0]},
			},
			CreatedSiafundElements: []types.SiafundElement{
				{StateElement: types.StateElement{ID: types.Hash256(txnB2.SiafundOutputID(0))}, SiafundOutput: txnB2.SiafundOutputs[0]},
				{StateElement: types.StateElement{ID: types.Hash256(txnB2.SiafundOutputID(1))}, SiafundOutput: txnB2.SiafundOutputs[1]},
			},
			SpentSiafundElements: []types.SiafundElement{
				{StateElement: types.StateElement{ID: types.Hash256(giftTxn.SiafundOutputID(0))}, SiafundOutput: giftTxn.SiafundOutputs[0]},
			},
		}},

		CreatedSiacoinElements: []types.SiacoinElement{{
			StateElement:   types.StateElement{ID: types.Hash256(b2.ID().MinerOutputID(0))},
			SiacoinOutput:  b2.MinerPayouts[0],
			MaturityHeight: cs.MaturityHeight(),
		}},
	}
	if diff, err := addBlock(b2); err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(diff, expect) {
		js1, _ := json.MarshalIndent(diff, "", "  ")
		js2, _ := json.MarshalIndent(expect, "", "  ")
		t.Fatalf("diff doesn't match:\n%s\nvs\n%s\n", js1, js2)
	}
}
