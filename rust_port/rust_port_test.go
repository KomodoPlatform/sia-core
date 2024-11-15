package rust_port_test

import (
	"encoding/hex"
	"testing"
	"time"

	. "go.sia.tech/core/rust_port/util"
	. "go.sia.tech/core/types"
)

/*
These tests serve as a sanity check that the Rust port's encoding and hashing functions are working as expected.

If any tests within this file fail at any point in the future, it's an indictation that the Rust port must be updated.

Verbose as possible to enable quickly identifying the source of any discrepancies.
*/

// https://github.com/KomodoPlatform/komodo-defi-framew11ork/blob/d180505b43f8167bd733263e73804ea60d4c1632/mm2src/coins/sia/spend_policy.rs#L189
func TestStandardUnlockHash(t *testing.T) {
	pk := PublicKey{1, 2, 3}
	p := SpendPolicy{PolicyTypeUnlockConditions(StandardUnlockConditions(pk))}
	if p.Address().String() != "72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515dd64b9a56043a" {
		t.Fatal("wrong address:", p, p.Address())
	} else if StandardUnlockHash(pk) != p.Address() {
		t.Fatal("StandardUnlockHash differs from Policy.Address")
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/spend_policy.rs#L202
func TestUnlockConditions2of2Multisig(t *testing.T) {
	uc := UnlockConditions{
		Timelock: 0,
		PublicKeys: []UnlockKey{
			PublicKey{1, 2, 3}.UnlockKey(),
			PublicKey{1, 1, 1}.UnlockKey()},
		SignaturesRequired: 2,
	}
	if UnlockConditionsRoot(uc).String() != "1e94357817d236167e54970a8c08bbd41b37bfceeeb52f6c1ce6dd01d50ea1e73a7c081d3178" {
		t.Fatal("wrong address:", uc, UnlockConditionsRoot(uc).String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/spend_policy.rs#L219
func TestUnlockConditions1of2Multisig(t *testing.T) {
	uc := UnlockConditions{
		Timelock: 0,
		PublicKeys: []UnlockKey{
			PublicKey{1, 2, 3}.UnlockKey(),
			PublicKey{1, 1, 1}.UnlockKey()},
		SignaturesRequired: 1,
	}
	if UnlockConditionsRoot(uc).String() != "d7f84e3423da09d111a17f64290c8d05e1cbe4cab2b6bed49e3a4d2f659f0585264e9181a51a" {
		t.Fatal("wrong address:", uc, UnlockConditionsRoot(uc).String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L45
func TestEncoderDefault(t *testing.T) {
	h := NewHasher()
	myHash := h.Sum()
	if myHash.String() != "h:0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L53
func TestEncoderWriteByes(t *testing.T) {
	h := NewHasher()
	h.E.WriteBytes([]byte{1, 2, 3, 4})
	myHash := h.Sum()
	if myHash.String() != "h:d4a72b52e2e1f40e20ee40ea6d5080a1b1f76164786defbb7691a4427f3388f5" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L63
func TestEncoderWriteUint8(t *testing.T) {
	h := NewHasher()
	h.E.WriteUint8(1)
	myHash := h.Sum()
	if myHash.String() != "h:ee155ace9c40292074cb6aff8c9ccdd273c81648ff1149ef36bcea6ebb8a3e25" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L73
func TestEncoderWriteUint64(t *testing.T) {
	h := NewHasher()
	h.E.WriteUint64(1)
	myHash := h.Sum()
	if myHash.String() != "h:1dbd7d0b561a41d23c2a469ad42fbd70d5438bae826f6fd607413190c37c363b" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L83
func TestEncoderWriteDistinguisher(t *testing.T) {
	h := NewHasher()
	h.WriteDistinguisher("test")
	myHash := h.Sum()
	if myHash.String() != "h:25fb524721bf98a9a1233a53c40e7e198971b003bf23c24f59d547a1bb837f9c" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L93
func TestEmcoderWriteBool(t *testing.T) {
	h := NewHasher()
	h.E.WriteBool(true)
	myHash := h.Sum()
	if myHash.String() != "h:ee155ace9c40292074cb6aff8c9ccdd273c81648ff1149ef36bcea6ebb8a3e25" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L103
func TestReset(t *testing.T) {
	h := NewHasher()
	h.E.WriteBool(true)
	myHash := h.Sum()
	if myHash.String() != "h:ee155ace9c40292074cb6aff8c9ccdd273c81648ff1149ef36bcea6ebb8a3e25" {
		t.Fatal("wrong hash:", myHash.String())
	}
	h.Reset()
	h.E.WriteBool(false)
	myHash = h.Sum()
	if myHash.String() != "h:03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L120
func TestEncoderWriteComplex(t *testing.T) {
	h := NewHasher()
	h.WriteDistinguisher("test")
	h.E.WriteBool(true)
	h.E.WriteUint8(1)
	h.E.WriteBytes([]byte{1, 2, 3, 4})
	myHash := h.Sum()
	if myHash.String() != "h:b66d7a9bef9fb303fe0e41f6b5c5af410303e428c4ff9231f6eb381248693221" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/d180505b43f8167bd733263e73804ea60d4c1632/mm2src/coins/sia/spend_policy.rs#L239
func TestPolicyAboveEncodeHash(t *testing.T) {
	h := NewHasher()

	policy := PolicyAbove(1)
	policy.EncodeTo(h.E)

	myaddress := policy.Address()
	myHash := h.Sum()
	if myHash.String() != "h:bebf6cbdfb440a92e3e5d832ac30fe5d226ff6b352ed3a9398b7d35f086a8ab6" {
		t.Fatal("wrong hash:", myHash.String())
	}
	if myaddress.String() != "188b997bb99dee13e95f92c3ea150bd76b3ec72e5ba57b0d57439a1a6e2865e9b25ea5d1825e" {
		t.Fatal("wrong address:", myaddress.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/d180505b43f8167bd733263e73804ea60d4c1632/mm2src/coins/sia/spend_policy.rs#L253
func TestPolicyAfterEncodeHash(t *testing.T) {
	h := NewHasher()

	time := time.Unix(int64(1), 0)
	policy := PolicyAfter(time)
	policy.EncodeTo(h.E)

	myHash := h.Sum()
	myaddress := policy.Address()

	if myHash.String() != "h:07b0f28eafd87a082ad11dc4724e1c491821260821a30bec68254444f97d9311" {
		t.Fatal("wrong hash:", myHash.String())
	}
	if myaddress.String() != "60c74e0ce5cede0f13f83b0132cb195c995bc7688c9fac34bbf2b14e14394b8bbe2991bc017f" {
		t.Fatal("wrong address:", myaddress.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/d180505b43f8167bd733263e73804ea60d4c1632/mm2src/coins/sia/spend_policy.rs#L267
func TestPolicyPublicKeyEncodeHash(t *testing.T) {
	h := NewHasher()

	policy := PolicyPublicKey(PublicKey{1, 2, 3})
	policy.EncodeTo(h.E)

	myHash := h.Sum()
	myaddress := policy.Address()

	if myHash.String() != "h:4355c8f80f6e5a98b70c9c2f9a22f17747989b4744783c90439b2b034f698bfe" {
		t.Fatal("wrong hash:", myHash.String())
	}
	if myaddress.String() != "55a7793237722c6df8222fd512063cb74228085ef1805c5184713648c159b919ac792fbad0e1" {
		t.Fatal("wrong address:", myaddress.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/d180505b43f8167bd733263e73804ea60d4c1632/mm2src/coins/sia/spend_policy.rs#L285
func TestPolicyHash(t *testing.T) {
	h := NewHasher()

	policy := PolicyHash(Hash256{1, 2, 3})
	policy.EncodeTo(h.E)

	myHash := h.Sum()
	myaddress := policy.Address()

	if myHash.String() != "h:9938967aefa6cbecc1f1620d2df5170d6811d4b2f47a879b621c1099a3b0628a" {
		t.Fatal("wrong hash:", myHash.String())
	}
	if myaddress.String() != "a4d5a06d8d3c2e45aa26627858ce8e881505ae3c9d122a1d282c7824163751936cffb347e435" {
		t.Fatal("wrong address:", myaddress.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/d180505b43f8167bd733263e73804ea60d4c1632/mm2src/coins/sia/spend_policy.rs#L301
func TestPolicyThreshold(t *testing.T) {
	h := NewHasher()

	policy := PolicyThreshold(1, []SpendPolicy{
		PolicyAbove(1),
		PolicyAfter(time.Unix(int64(1), 0)),
	})
	policy.EncodeTo(h.E)

	myHash := h.Sum()
	myaddress := policy.Address()

	if myHash.String() != "h:7d792df6cd0b5e0f795287b3bf4087bbcc4c1bd0c52880a552cdda3e5e33d802" {
		t.Fatal("wrong hash:", myHash.String())
	}
	if myaddress.String() != "4179b53aba165e46e4c85b3c8766bb758fb6f0bfa5721550b81981a3ec38efc460557dc1ded4" {
		t.Fatal("wrong address:", myaddress.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/d180505b43f8167bd733263e73804ea60d4c1632/mm2src/coins/sia/spend_policy.rs#L319
func TestPolicyUnlockConditionEncodeSpecialCase(t *testing.T) {
	pubkey := PublicKey{1, 2, 3}
	unlock_condition := PolicyTypeUnlockConditions{
		PublicKeys:         []UnlockKey{pubkey.UnlockKey()},
		SignaturesRequired: 1,
		Timelock:           0,
	}
	policy := PolicyThreshold(1, []SpendPolicy{
		{unlock_condition},
	})

	// Unlock condition SpendPolicy has a special condition for v1 comaptibility if it is not within a Threshold
	originalUnlockConditions := UnlockConditions(unlock_condition)
	uc_address := originalUnlockConditions.UnlockHash()
	if uc_address.String() != "72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515dd64b9a56043a" {
		t.Fatal("wrong address:", uc_address.String())
	}

	uc_inside_threshold_address := policy.Address()
	if uc_inside_threshold_address.String() != "1498a58c843ce66740e52421632d67a0f6991ea96db1fc97c29e46f89ae56e3534078876331d" {
		t.Fatal("wrong address:", uc_inside_threshold_address.String())
	}
}

// FIXME link to equivalent rust code once pushed
// mm2src/coins/sia/transaction.rs test_siacoin_input_encode
func TestSiacoinInputEncodeHash(t *testing.T) {
	h := NewHasher()

	uc := UnlockConditions{
		Timelock: 0,
		PublicKeys: []UnlockKey{
			PublicKey{1, 2, 3}.UnlockKey(),
		},
		SignaturesRequired: 1,
	}

	vin := SiacoinInput{
		ParentID:         SiacoinOutputID(Hash256{4, 5, 6}),
		UnlockConditions: uc,
	}

	vin.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:1d4b77aaa82c71ca68843210679b380f9638f8bec7addf0af16a6536dd54d6b4" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// FIXME mm2src/coins/sia/address.rs test_address_encode
func TestSiacoinAddressEncodeHash(t *testing.T) {
	h := NewHasher()

	public_key := PublicKey{1, 2, 3}
	addr := StandardUnlockHash(public_key)

	addr.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:d64b9a56043a909494f07520915e10dae62d75dba24b17c8414f8f3f30c53425" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_unlock_condition_encode
func TestSiacoinUnlockConditionEncodeHash(t *testing.T) {
	h := NewHasher()

	uc := UnlockConditions{
		Timelock: 0,
		PublicKeys: []UnlockKey{
			PublicKey{1, 2, 3}.UnlockKey(),
		},
		SignaturesRequired: 1,
	}

	uc.EncodeTo(h.E)

	myHash := h.Sum()

	if myHash.String() != "h:5d49bae37b97c86573a1525246270c180464acf33d63cc2ac0269ef9a8cb9d98" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_public_key_encode
func TestSiacoinPublicKeyEncodeHash(t *testing.T) {
	h := NewHasher()
	publicKey := PublicKey{1, 2, 3}

	publicKey.EncodeTo(h.E)

	myHash := h.Sum()

	if myHash.String() != "h:d487326614f066416308bf6aa4e5041d1949928e4b26ede98e3cebb36a3b1726" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_siacoin_currency_encode_v1
func TestSiacoinCurrencyEncodeHashV1(t *testing.T) {
	h := NewHasher()
	currency := NewCurrency64(1)

	V1Currency(currency).EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:a1cc3a97fc1ebfa23b0b128b153a29ad9f918585d1d8a32354f547d8451b7826" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_siacoin_currency_encode_v2
func TestSiacoinCurrencyEncodeHashV2(t *testing.T) {
	h := NewHasher()
	currency := NewCurrency64(1)

	V2Currency(currency).EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:a3865e5e284e12e0ea418e73127db5d1092bfb98ed372ca9a664504816375e1d" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_siacoin_currency_encode_v1
func TestSiacoinCurrencyEncodeHashV1Max(t *testing.T) {
	h := NewHasher()
	currency := NewCurrency(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

	V1Currency(currency).EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:4b9ed7269cb15f71ddf7238172a593a8e7ffe68b12c1bf73d67ac8eec44355bb" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_siacoin_currency_encode_v2_max
func TestSiacoinCurrencyEncodeHashV2Max(t *testing.T) {
	h := NewHasher()
	currency := NewCurrency(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

	V2Currency(currency).EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:681467b3337425fd38fa3983531ca1a6214de9264eebabdf9c9bc5d157d202b4" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_siacoin_output_encode_v1
func TestSiacoinOutputEncodeHashV1(t *testing.T) {
	h := NewHasher()
	addr := StandardUnlockHash(PublicKey{1, 2, 3})
	vout := SiacoinOutput{
		Value:   NewCurrency64(1),
		Address: addr,
	}

	V1SiacoinOutput(vout).EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:3253c57e76600721f2bdf03497a71ed47c09981e22ef49aed92e40da1ea91b28" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_siacoin_output_encode_v1
func TestSiacoinOutputEncodeHashV2(t *testing.T) {
	h := NewHasher()
	addr := StandardUnlockHash(PublicKey{1, 2, 3})
	vout := SiacoinOutput{
		Value:   NewCurrency64(1),
		Address: addr,
	}

	V2SiacoinOutput(vout).EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:c278eceae42f594f5f4ca52c8a84b749146d08af214cc959ed2aaaa916eaafd3" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_siacoin_output_encode_v1
func TestSiacoinInputEncodeHashV1(t *testing.T) {
	h := NewHasher()
	uc := UnlockConditions{
		Timelock:           0,
		PublicKeys:         []UnlockKey{},
		SignaturesRequired: 0,
	}
	parent := SiacoinOutputID(Hash256{0})

	vin := SiacoinInput{
		ParentID:         parent,
		UnlockConditions: uc,
	}

	vin.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:2f806f905436dc7c5079ad8062467266e225d8110a3c58d17628d609cb1c99d0" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_state_element_encode
func TestStateElementEncodeHash(t *testing.T) {
	h := NewHasher()

	se := StateElement{
		LeafIndex:   1,
		MerkleProof: []Hash256{{4, 5, 6}, {7, 8, 9}},
	}

	se.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:bf6d7b74fb1e15ec4e86332b628a450e387c45b54ea98e57a6da8c9af317e468" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_state_element_encode_null_merkle_proof
func TestStateElementEncodeHashNullMerkleProof(t *testing.T) {
	h := NewHasher()

	se := StateElement{
		LeafIndex: 1,
	}

	se.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:d69bc48bc797aff93050447aff0a3f7c4d489705378c122cd123841fe7778a3e" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_siacoin_element_encode
func TestSiacoinElementEncodeHash(t *testing.T) {
	h := NewHasher()

	stateElement := StateElement{
		LeafIndex:   1,
		MerkleProof: []Hash256{{4, 5, 6}, {7, 8, 9}},
	}

	addr := StandardUnlockHash(PublicKey{1, 2, 3})

	siacoinElement := SiacoinElement{
		ID:           SiacoinOutputID{1, 2, 3},
		StateElement: stateElement,
		SiacoinOutput: SiacoinOutput{
			Address: addr,
			Value:   NewCurrency64(1),
		},
		MaturityHeight: 0,
	}

	siacoinElement.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:3c867a54b7b3de349c56585f25a4365f31d632c3e42561b615055c77464d889e" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_signature_encode
func TestSignatureEncodeHash(t *testing.T) {
	h := NewHasher()

	hexStr := "105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309" // Replace this with your hex string
	bytes, _ := hex.DecodeString(hexStr)

	var signature Signature
	copy(signature[:], bytes)

	signature.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:1e6952fe04eb626ae759a0090af2e701ba35ee6ad15233a2e947cb0f7ae9f7c7" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

func TestSatisfiedPolicyEncodeHashPublicKeyMissingSignature(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		} else {
			expected := "runtime error: index out of range [0] with length 0"
			if errMsg, ok := r.(error); ok {
				if errMsg.Error() != expected {
					t.Errorf("Expected panic: '%s', got: '%s'", expected, errMsg.Error())
				}
			} else {
				if r != expected {
					t.Errorf("Expected panic: '%s', got: '%v'", expected, r)
				}
			}
		}
	}()

	h := NewHasher()

	sp := SatisfiedPolicy{Policy: PolicyPublicKey(PublicKey{1, 2, 3})}
	sp.EncodeTo(h.E) // This should panic
}

// mm2src/coins/sia/transaction.rs test_satisfied_policy_encode_public_key
func TestSatisfiedPolicyPublicKey(t *testing.T) {
	h := NewHasher()

	hexStr := "105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309" // Replace this with your hex string
	bytes, _ := hex.DecodeString(hexStr)

	var signature Signature
	copy(signature[:], bytes)

	sp := SatisfiedPolicy{
		Policy:     PolicyPublicKey(PublicKey{1, 2, 3}),
		Signatures: []Signature{signature}}
	sp.EncodeTo(h.E)

	myHash := h.Sum()

	if myHash.String() != "h:51832be911c7382502a2011cbddf1a9f689c4ca08c6a83ae3d021fb0dc781822" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// sia-rust/src/tests/transaction.rs test_satisfied_policy_encode_hash_empty
func TestSatisfiedPolicyHashEmpty(t *testing.T) {
	h := NewHasher()

	sp := SatisfiedPolicy{
		Policy:     PolicyHash(Hash256{0}),
		Signatures: []Signature{{}},
		Preimages:  [][32]byte{{}}}

	sp.EncodeTo(h.E)

	myHash := h.Sum()

	if myHash.String() != "h:1e612d1ee36338b93a36bac0c52007a2d678cde0bd9b95c36a1f61166cf02b87" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_satisfied_policy_encode_hash
// Adding a signature to SatisfiedPolicy of PolicyHash should have no effect
func TestSatisfiedPolicyHashFrivulousSignature(t *testing.T) {
	h := NewHasher()
	bytes, _ := hex.DecodeString("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309")
	var signature Signature
	copy(signature[:], bytes)

	sp := SatisfiedPolicy{
		Policy:     PolicyHash(Hash256{0}),
		Signatures: []Signature{signature},
		Preimages:  [][32]byte{{1, 2, 3, 4}}}

	sp.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:7424653d0ca3ffded9a029bebe75f9ae9c99b5f284e23e9d07c0b03456f724f9" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_satisfied_policy_encode_hash
func TestSatisfiedPolicyHash(t *testing.T) {
	h := NewHasher()

	sp := SatisfiedPolicy{
		Policy:     PolicyHash(Hash256{0}),
		Signatures: []Signature{{}},
		Preimages:  [][32]byte{{1, 2, 3, 4}}}

	sp.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:7424653d0ca3ffded9a029bebe75f9ae9c99b5f284e23e9d07c0b03456f724f9" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_satisfied_policy_encode_unlock_condition_standard
func TestSatisfiedPolicyUnlockConditionStandard(t *testing.T) {
	h := NewHasher()

	pk := PublicKey{1, 2, 3}
	policy := SpendPolicy{PolicyTypeUnlockConditions(StandardUnlockConditions(pk))}

	bytes, _ := hex.DecodeString("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309")
	var signature Signature
	copy(signature[:], bytes)

	sp := SatisfiedPolicy{
		Policy:     policy,
		Signatures: []Signature{signature},
		Preimages:  [][32]byte{}}

	sp.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:c749f9ac53395ec557aed7e21d202f76a58e0de79222e5756b27077e9295931f" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_satisfied_policy_encode_unlock_condition_complex
func TestSatisfiedPolicyUnlockConditionComplex(t *testing.T) {
	h := NewHasher()

	uc0 := PublicKeyFromHex("0102030000000000000000000000000000000000000000000000000000000000").UnlockKey()
	uc1 := PublicKeyFromHex("06C87838297B7BB16AB23946C99DFDF77FF834E35DB07D71E9B1D2B01A11E96D").UnlockKey()
	uc2 := PublicKeyFromHex("BE043906FD42297BC0A03CAA6E773EF27FC644261C692D090181E704BE4A88C3").UnlockKey()

	unlock_condition := UnlockConditions{
		Timelock:           77777777,
		PublicKeys:         []UnlockKey{uc0, uc1, uc2},
		SignaturesRequired: 3,
	}

	policy := SpendPolicy{Type: PolicyTypeUnlockConditions(unlock_condition)}

	sig0 := SignatureFromHex("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309")
	sig1 := SignatureFromHex("0734761D562958F6A82819474171F05A40163901513E5858BFF9E4BD9CAFB04DEF0D6D345BACE7D14E50C5C523433B411C7D7E1618BE010A63C55C34A2DEE70A")
	sig2 := SignatureFromHex("482A2A905D7A6FC730387E06B45EA0CF259FCB219C9A057E539E705F60AC36D7079E26DAFB66ED4DBA9B9694B50BCA64F1D4CC4EBE937CE08A34BF642FAC1F0C")

	sp := SatisfiedPolicy{
		Policy:     policy,
		Signatures: []Signature{sig0, sig1, sig2},
		Preimages:  [][32]byte{}}

	sp.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:13806b6c13a97478e476e0e5a0469c9d0ad8bf286bec0ada992e363e9fc60901" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_satisfied_policy_threshold_simple
func TestSatisfiedPolicyThresholdSimple(t *testing.T) {
	h := NewHasher()

	subPolicy := PolicyHash(Hash256{0})
	policy := PolicyThreshold(1, []SpendPolicy{subPolicy})

	sp := SatisfiedPolicy{
		Policy:     policy,
		Signatures: []Signature{{}},
		Preimages:  [][32]byte{{1, 2, 3, 4}}}

	sp.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:50f4808b0661f56842472aed259136a43ed2bd7d59a88a3be28de9883af4a92d" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

/*
emulate the following bitcoin script
OP_IF <locktime> OP_CHECKLOCKTIMEVERIFY
        OP_DROP <pubkey0> OP_CHECKSIG
OP_ELSE
        OP_SIZE 20 OP_EQUALVERIFY OP_HASH160 <secret hash> OP_EQUALVERIFY <pubkey1> OP_CHECKSIG
OP_ENDIF
*/
// mm2src/coins/sia/transaction.rs test_satisfied_policy_threshold_atomic_swap_success
func TestSatisfiedPolicyThresholdAtomicSwapSuccess(t *testing.T) {
	h := NewHasher()

	alicePublicKey := PublicKeyFromHex("0102030000000000000000000000000000000000000000000000000000000000")
	bobPublicKey := PublicKeyFromHex("06C87838297B7BB16AB23946C99DFDF77FF834E35DB07D71E9B1D2B01A11E96D")

	policy := SpendPolicyAtomicSwapSuccess(alicePublicKey, bobPublicKey, 77777777, Hash256{1})
	signature := SignatureFromHex("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309")

	sp := SatisfiedPolicy{
		Policy:     policy,
		Signatures: []Signature{signature},
		Preimages:  [][32]byte{{1, 2, 3, 4}}}

	sp.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:c835e516bbf76602c897a9160c17bfe0e4a8bc9044f62b3e5e45a381232a2f86" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_satisfied_policy_threshold_atomic_swap_refund

func TestSatisfiedPolicyThresholdAtomicSwapRefund(t *testing.T) {
	h := NewHasher()

	alicePublicKey := PublicKeyFromHex("0102030000000000000000000000000000000000000000000000000000000000")
	bobPublicKey := PublicKeyFromHex("06C87838297B7BB16AB23946C99DFDF77FF834E35DB07D71E9B1D2B01A11E96D")

	policy := SpendPolicyAtomicSwapRefund(alicePublicKey, bobPublicKey, 77777777, Hash256{1})
	signature := SignatureFromHex("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309")

	sp := SatisfiedPolicy{
		Policy:     policy,
		Signatures: []Signature{signature},
		Preimages:  [][32]byte{{1, 2, 3, 4}}}

	sp.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:8975e8cf990d5a20d9ec3dae18ed3b3a0c92edf967a8d93fcdef6a1eb73bb348" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_siacoin_input_encode_v2
func TestSiacoinInputEncodeV2(t *testing.T) {
	h := NewHasher()

	subPolicy := PolicyHash(Hash256{0})
	policy := PolicyThreshold(1, []SpendPolicy{subPolicy})
	address := policy.Address()

	satisfiedPolicy := SatisfiedPolicy{
		Policy:    policy,
		Preimages: [][32]byte{{1, 2, 3, 4}},
	}

	stateElement := StateElement{
		LeafIndex:   0,
		MerkleProof: []Hash256{{0}},
	}
	siacoinElement := SiacoinElement{
		ID:           SiacoinOutputID{0},
		StateElement: stateElement,
		SiacoinOutput: SiacoinOutput{
			Address: address,
			Value:   NewCurrency64(1),
		},
		MaturityHeight: 0,
	}

	vin := V2SiacoinInput{
		Parent:          siacoinElement,
		SatisfiedPolicy: satisfiedPolicy,
	}

	vin.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:a8ab11b91ee19ce68f2d608bd4d19212841842f0c50151ae4ccb8e9db68cd6c4" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_attestation_encode
func TestAttestationEncode(t *testing.T) {
	h := NewHasher()

	publicKey := PublicKeyFromHex("0102030000000000000000000000000000000000000000000000000000000000")
	signature := SignatureFromHex("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309")

	attestation := Attestation{
		PublicKey: publicKey,
		Key:       "HostAnnouncement",
		Value:     []byte{1, 2, 3, 4},
		Signature: signature,
	}

	attestation.EncodeTo(h.E)
	println("buf: ", hex.EncodeToString(h.E.Buf()[:h.E.N()]))
	myHash := h.Sum()

	if myHash.String() != "h:b28b32c6f91d1b57ab4a9ea9feecca16b35bb8febdee6a0162b22979415f519d" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_file_contract_v2_encode
func TestFileContractV2Encode(t *testing.T) {
	h := NewHasher()

	pubkey0 := PublicKeyFromHex("0102030000000000000000000000000000000000000000000000000000000000")
	pubkey1 := PublicKeyFromHex("06C87838297B7BB16AB23946C99DFDF77FF834E35DB07D71E9B1D2B01A11E96D")

	sig0 := SignatureFromHex("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309")
	sig1 := SignatureFromHex("0734761D562958F6A82819474171F05A40163901513E5858BFF9E4BD9CAFB04DEF0D6D345BACE7D14E50C5C523433B411C7D7E1618BE010A63C55C34A2DEE70A")

	address0 := StandardUnlockHash(pubkey0)
	address1 := StandardUnlockHash(pubkey1)

	vout0 := SiacoinOutput{
		Value:   NewCurrency64(1),
		Address: address0,
	}
	vout1 := SiacoinOutput{
		Value:   NewCurrency64(1),
		Address: address1,
	}

	contract := V2FileContract{
		Filesize:         1,
		FileMerkleRoot:   Hash256{0},
		ProofHeight:      1,
		ExpirationHeight: 1,
		RenterOutput:     vout0,
		HostOutput:       vout1,
		MissedHostValue:  NewCurrency64(1),
		TotalCollateral:  NewCurrency64(1),
		RenterPublicKey:  pubkey0,
		HostPublicKey:    pubkey1,
		RevisionNumber:   1,
		RenterSignature:  sig0,
		HostSignature:    sig1,
	}

	contract.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:6171a8d8ec31e06f80d46efbd1aecf2c5a7c344b5f2a2d4f660654b0cb84113c" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_file_contract_element_v2_encode
func TestFileContractElementV2Encode(t *testing.T) {
	h := NewHasher()

	pubkey0 := PublicKeyFromHex("0102030000000000000000000000000000000000000000000000000000000000")
	pubkey1 := PublicKeyFromHex("06C87838297B7BB16AB23946C99DFDF77FF834E35DB07D71E9B1D2B01A11E96D")

	sig0 := SignatureFromHex("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309")
	sig1 := SignatureFromHex("0734761D562958F6A82819474171F05A40163901513E5858BFF9E4BD9CAFB04DEF0D6D345BACE7D14E50C5C523433B411C7D7E1618BE010A63C55C34A2DEE70A")

	address0 := StandardUnlockHash(pubkey0)
	address1 := StandardUnlockHash(pubkey1)

	vout0 := SiacoinOutput{
		Value:   NewCurrency64(1),
		Address: address0,
	}
	vout1 := SiacoinOutput{
		Value:   NewCurrency64(1),
		Address: address1,
	}

	contract := V2FileContract{
		Filesize:         1,
		FileMerkleRoot:   Hash256{0},
		ProofHeight:      1,
		ExpirationHeight: 1,
		RenterOutput:     vout0,
		HostOutput:       vout1,
		MissedHostValue:  NewCurrency64(1),
		TotalCollateral:  NewCurrency64(1),
		RenterPublicKey:  pubkey0,
		HostPublicKey:    pubkey1,
		RevisionNumber:   1,
		RenterSignature:  sig0,
		HostSignature:    sig1,
	}

	stateElement := StateElement{
		LeafIndex:   1,
		MerkleProof: []Hash256{{4, 5, 6}, {7, 8, 9}},
	}

	contractElement := V2FileContractElement{
		ID:             FileContractID{1, 2, 3},
		StateElement:   stateElement,
		V2FileContract: contract,
	}

	contractElement.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:4cde411635118b2b7e1b019c659a2327ada53b303da0e46524e604d228fcd039" {
		t.Fatal("wrong hash:", myHash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_file_contract_element_v2_encode
func TestFileContractRevisionV2Encode(t *testing.T) {
	h := NewHasher()

	pubkey0 := PublicKeyFromHex("0102030000000000000000000000000000000000000000000000000000000000")
	pubkey1 := PublicKeyFromHex("06C87838297B7BB16AB23946C99DFDF77FF834E35DB07D71E9B1D2B01A11E96D")

	sig0 := SignatureFromHex("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309")
	sig1 := SignatureFromHex("0734761D562958F6A82819474171F05A40163901513E5858BFF9E4BD9CAFB04DEF0D6D345BACE7D14E50C5C523433B411C7D7E1618BE010A63C55C34A2DEE70A")

	address0 := StandardUnlockHash(pubkey0)
	address1 := StandardUnlockHash(pubkey1)

	vout0 := SiacoinOutput{
		Value:   NewCurrency64(1),
		Address: address0,
	}
	vout1 := SiacoinOutput{
		Value:   NewCurrency64(1),
		Address: address1,
	}

	contract := V2FileContract{
		Filesize:         1,
		FileMerkleRoot:   Hash256{0},
		ProofHeight:      1,
		ExpirationHeight: 1,
		RenterOutput:     vout0,
		HostOutput:       vout1,
		MissedHostValue:  NewCurrency64(1),
		TotalCollateral:  NewCurrency64(1),
		RenterPublicKey:  pubkey0,
		HostPublicKey:    pubkey1,
		RevisionNumber:   1,
		RenterSignature:  sig0,
		HostSignature:    sig1,
	}

	stateElement := StateElement{
		LeafIndex:   1,
		MerkleProof: []Hash256{{4, 5, 6}, {7, 8, 9}},
	}

	contractElement := V2FileContractElement{
		ID:             FileContractID{1, 2, 3},
		StateElement:   stateElement,
		V2FileContract: contract,
	}

	contractRevision := V2FileContractRevision{
		Parent:   contractElement,
		Revision: contract,
	}

	contractRevision.EncodeTo(h.E)
	myHash := h.Sum()

	if myHash.String() != "h:22d5d1fd8c2762758f6b6ecf7058d73524ef209ac5a64f160b71ce91677db9a6" {
		t.Fatal("wrong hash:", myHash.String())
	}
}
