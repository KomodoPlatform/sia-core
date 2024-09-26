package rust_port_util

import (
	"encoding/hex"
	"time"

	. "go.sia.tech/core/types"
)

// Utility function to initialize a Signature from a hex string
func SignatureFromHex(hexStr string) Signature {
	var sig Signature
	bytes, _ := hex.DecodeString(hexStr)
	copy(sig[:], bytes)
	return sig
}

// Utility function to initialize a Signature from a hex string
func PublicKeyFromHex(hexStr string) PublicKey {
	var pk PublicKey
	bytes, _ := hex.DecodeString(hexStr)
	copy(pk[:], bytes)
	return pk
}

func SpendPolicyAtomicSwap(alice PublicKey, bob PublicKey, lockTime uint64, hash Hash256) SpendPolicy {
	policy_after := PolicyAfter(time.Unix(int64(lockTime), 0))
	policy_hash := PolicyHash(hash)

	policy_success := PolicyThreshold(2, []SpendPolicy{PolicyPublicKey(alice), policy_hash})
	policy_refund := PolicyThreshold(2, []SpendPolicy{PolicyPublicKey(bob), policy_after})

	return PolicyThreshold(1, []SpendPolicy{policy_success, policy_refund})
}

func SpendPolicyAtomicSwapSuccess(alice PublicKey, bob PublicKey, lockTime uint64, hash Hash256) SpendPolicy {
	policy_after := PolicyAfter(time.Unix(int64(lockTime), 0))
	policy_hash := PolicyHash(hash)

	policy_success := PolicyThreshold(2, []SpendPolicy{PolicyPublicKey(alice), policy_hash})
	policy_refund := PolicyThreshold(2, []SpendPolicy{PolicyPublicKey(bob), policy_after})

	return PolicyThreshold(1, []SpendPolicy{policy_success, PolicyOpaque(policy_refund)})
}

func SpendPolicyAtomicSwapRefund(alice PublicKey, bob PublicKey, lockTime uint64, hash Hash256) SpendPolicy {
	policy_after := PolicyAfter(time.Unix(int64(lockTime), 0))
	policy_hash := PolicyHash(hash)

	policy_success := PolicyThreshold(2, []SpendPolicy{PolicyPublicKey(alice), policy_hash})
	policy_refund := PolicyThreshold(2, []SpendPolicy{PolicyPublicKey(bob), policy_after})

	return PolicyThreshold(1, []SpendPolicy{PolicyOpaque(policy_success), policy_refund})
}
