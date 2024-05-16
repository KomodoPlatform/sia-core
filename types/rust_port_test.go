package types

import (
	"testing"
	"time"
)

/*
These tests serve as a sanity check that the Rust port's encoding and hashing functions are working as expected.

If any tests within this file fail at any point in the future, it's an indictation that the Rust port must be updated.

Verbose as possible to enable quickly identifying the source of any discrepancies.
*/

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/d180505b43f8167bd733263e73804ea60d4c1632/mm2src/coins/sia/spend_policy.rs#L189
func TestStandardUnlockHash(t *testing.T) {
	pk := PublicKey{1, 2, 3}
	p := SpendPolicy{PolicyTypeUnlockConditions(StandardUnlockConditions(pk))}
	if p.Address().String() != "addr:72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515dd64b9a56043a" {
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
	if unlockConditionsRoot(uc).String() != "addr:1e94357817d236167e54970a8c08bbd41b37bfceeeb52f6c1ce6dd01d50ea1e73a7c081d3178" {
		t.Fatal("wrong address:", uc, unlockConditionsRoot(uc).String())
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
	if unlockConditionsRoot(uc).String() != "addr:d7f84e3423da09d111a17f64290c8d05e1cbe4cab2b6bed49e3a4d2f659f0585264e9181a51a" {
		t.Fatal("wrong address:", uc, unlockConditionsRoot(uc).String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L45
func TestEncoderDefault(t *testing.T) {
	h := NewHasher()
	myhash := h.Sum()
	if myhash.String() != "h:0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L53
func TestEncoderWriteByes(t *testing.T) {
	h := NewHasher()
	h.E.WriteBytes([]byte{1, 2, 3, 4})
	myhash := h.Sum()
	if myhash.String() != "h:d4a72b52e2e1f40e20ee40ea6d5080a1b1f76164786defbb7691a4427f3388f5" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L63
func TestEncoderWriteUint8(t *testing.T) {
	h := NewHasher()
	h.E.WriteUint8(1)
	myhash := h.Sum()
	if myhash.String() != "h:ee155ace9c40292074cb6aff8c9ccdd273c81648ff1149ef36bcea6ebb8a3e25" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L73
func TestEncoderWriteUint64(t *testing.T) {
	h := NewHasher()
	h.E.WriteUint64(1)
	myhash := h.Sum()
	if myhash.String() != "h:1dbd7d0b561a41d23c2a469ad42fbd70d5438bae826f6fd607413190c37c363b" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L83
func TestEncoderWriteDistinguisher(t *testing.T) {
	h := NewHasher()
	h.WriteDistinguisher("test")
	myhash := h.Sum()
	if myhash.String() != "h:25fb524721bf98a9a1233a53c40e7e198971b003bf23c24f59d547a1bb837f9c" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L93
func TestEmcoderWriteBool(t *testing.T) {
	h := NewHasher()
	h.E.WriteBool(true)
	myhash := h.Sum()
	if myhash.String() != "h:ee155ace9c40292074cb6aff8c9ccdd273c81648ff1149ef36bcea6ebb8a3e25" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L103
func TestReset(t *testing.T) {
	h := NewHasher()
	h.E.WriteBool(true)
	myhash := h.Sum()
	if myhash.String() != "h:ee155ace9c40292074cb6aff8c9ccdd273c81648ff1149ef36bcea6ebb8a3e25" {
		t.Fatal("wrong hash:", myhash.String())
	}
	h.Reset()
	h.E.WriteBool(false)
	myhash = h.Sum()
	if myhash.String() != "h:03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/b6af96ef5a2f75b4ce3d1308e0f8b9757ec15a95/mm2src/coins/sia/encoding.rs#L120
func TestEncoderWriteComplex(t *testing.T) {
	h := NewHasher()
	h.WriteDistinguisher("test")
	h.E.WriteBool(true)
	h.E.WriteUint8(1)
	h.E.WriteBytes([]byte{1, 2, 3, 4})
	myhash := h.Sum()
	if myhash.String() != "h:b66d7a9bef9fb303fe0e41f6b5c5af410303e428c4ff9231f6eb381248693221" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/d180505b43f8167bd733263e73804ea60d4c1632/mm2src/coins/sia/spend_policy.rs#L239
func TestPolicyAboveEncodeHash(t *testing.T) {
	h := NewHasher()

	policy := PolicyAbove(1)
	policy.EncodeTo(h.E)

	myaddress := policy.Address()
	myhash := h.Sum()
	if myhash.String() != "h:bebf6cbdfb440a92e3e5d832ac30fe5d226ff6b352ed3a9398b7d35f086a8ab6" {
		t.Fatal("wrong hash:", myhash.String())
	}
	if myaddress.String() != "addr:188b997bb99dee13e95f92c3ea150bd76b3ec72e5ba57b0d57439a1a6e2865e9b25ea5d1825e" {
		t.Fatal("wrong address:", myaddress.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/d180505b43f8167bd733263e73804ea60d4c1632/mm2src/coins/sia/spend_policy.rs#L253
func TestPolicyAfterEncodeHash(t *testing.T) {
	h := NewHasher()

	time := time.Unix(int64(1), 0)
	policy := PolicyAfter(time)
	policy.EncodeTo(h.E)

	myhash := h.Sum()
	myaddress := policy.Address()

	if myhash.String() != "h:07b0f28eafd87a082ad11dc4724e1c491821260821a30bec68254444f97d9311" {
		t.Fatal("wrong hash:", myhash.String())
	}
	if myaddress.String() != "addr:60c74e0ce5cede0f13f83b0132cb195c995bc7688c9fac34bbf2b14e14394b8bbe2991bc017f" {
		t.Fatal("wrong address:", myaddress.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/d180505b43f8167bd733263e73804ea60d4c1632/mm2src/coins/sia/spend_policy.rs#L267
func TestPolicyPublicKeyEncodeHash(t *testing.T) {
	h := NewHasher()

	policy := PolicyPublicKey(PublicKey{1, 2, 3})
	policy.EncodeTo(h.E)

	myhash := h.Sum()
	myaddress := policy.Address()

	if myhash.String() != "h:4355c8f80f6e5a98b70c9c2f9a22f17747989b4744783c90439b2b034f698bfe" {
		t.Fatal("wrong hash:", myhash.String())
	}
	if myaddress.String() != "addr:55a7793237722c6df8222fd512063cb74228085ef1805c5184713648c159b919ac792fbad0e1" {
		t.Fatal("wrong address:", myaddress.String())
	}
}

// https://github.com/KomodoPlatform/komodo-defi-framework/blob/d180505b43f8167bd733263e73804ea60d4c1632/mm2src/coins/sia/spend_policy.rs#L285
func TestPolicyHash(t *testing.T) {
	h := NewHasher()

	policy := PolicyHash(Hash256{1, 2, 3})
	policy.EncodeTo(h.E)

	myhash := h.Sum()
	myaddress := policy.Address()

	if myhash.String() != "h:9938967aefa6cbecc1f1620d2df5170d6811d4b2f47a879b621c1099a3b0628a" {
		t.Fatal("wrong hash:", myhash.String())
	}
	if myaddress.String() != "addr:a4d5a06d8d3c2e45aa26627858ce8e881505ae3c9d122a1d282c7824163751936cffb347e435" {
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

	myhash := h.Sum()
	myaddress := policy.Address()

	if myhash.String() != "h:7d792df6cd0b5e0f795287b3bf4087bbcc4c1bd0c52880a552cdda3e5e33d802" {
		t.Fatal("wrong hash:", myhash.String())
	}
	if myaddress.String() != "addr:4179b53aba165e46e4c85b3c8766bb758fb6f0bfa5721550b81981a3ec38efc460557dc1ded4" {
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
	if uc_address.String() != "addr:72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515dd64b9a56043a" {
		t.Fatal("wrong address:", uc_address.String())
	}

	uc_inside_threshold_address := policy.Address()
	if uc_inside_threshold_address.String() != "addr:1498a58c843ce66740e52421632d67a0f6991ea96db1fc97c29e46f89ae56e3534078876331d" {
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
	myhash := h.Sum()

	if myhash.String() != "h:1d4b77aaa82c71ca68843210679b380f9638f8bec7addf0af16a6536dd54d6b4" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// FIXME mm2src/coins/sia/address.rs test_address_encode
func TestSiacoinAddressEncodeHash(t *testing.T) {
	h := NewHasher()

	public_key := PublicKey{1, 2, 3}
	addr := StandardUnlockHash(public_key)

	addr.EncodeTo(h.E)
	myhash := h.Sum()

	if myhash.String() != "h:d64b9a56043a909494f07520915e10dae62d75dba24b17c8414f8f3f30c53425" {
		t.Fatal("wrong hash:", myhash.String())
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

	myhash := h.Sum()

	if myhash.String() != "h:5d49bae37b97c86573a1525246270c180464acf33d63cc2ac0269ef9a8cb9d98" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_public_key_encode
func TestSiacoinPublicKeyEncodeHash(t *testing.T) {
	h := NewHasher()
	publicKey := PublicKey{1, 2, 3}

	publicKey.EncodeTo(h.E)

	myhash := h.Sum()

	if myhash.String() != "h:d487326614f066416308bf6aa4e5041d1949928e4b26ede98e3cebb36a3b1726" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_siacoin_currency_encode_v1
func TestSiacoinCurrencyEncodeHashV1(t *testing.T) {
	h := NewHasher()
	currency := NewCurrency64(1)

	V1Currency(currency).EncodeTo(h.E)
	myhash := h.Sum()

	if myhash.String() != "h:a1cc3a97fc1ebfa23b0b128b153a29ad9f918585d1d8a32354f547d8451b7826" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_siacoin_currency_encode_v2
func TestSiacoinCurrencyEncodeHashV2(t *testing.T) {
	h := NewHasher()
	currency := NewCurrency64(1)

	V2Currency(currency).EncodeTo(h.E)
	myhash := h.Sum()

	if myhash.String() != "h:a3865e5e284e12e0ea418e73127db5d1092bfb98ed372ca9a664504816375e1d" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_siacoin_currency_encode_v1
func TestSiacoinCurrencyEncodeHashV1Max(t *testing.T) {
	h := NewHasher()
	currency := NewCurrency(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

	V1Currency(currency).EncodeTo(h.E)
	myhash := h.Sum()

	if myhash.String() != "h:4b9ed7269cb15f71ddf7238172a593a8e7ffe68b12c1bf73d67ac8eec44355bb" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// mm2src/coins/sia/spend_policy.rs test_siacoin_currency_encode_v2_max
func TestSiacoinCurrencyEncodeHashV2Max(t *testing.T) {
	h := NewHasher()
	currency := NewCurrency(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

	V2Currency(currency).EncodeTo(h.E)
	myhash := h.Sum()

	if myhash.String() != "h:681467b3337425fd38fa3983531ca1a6214de9264eebabdf9c9bc5d157d202b4" {
		t.Fatal("wrong hash:", myhash.String())
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
	myhash := h.Sum()

	if myhash.String() != "h:3253c57e76600721f2bdf03497a71ed47c09981e22ef49aed92e40da1ea91b28" {
		t.Fatal("wrong hash:", myhash.String())
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
	myhash := h.Sum()

	if myhash.String() != "h:c278eceae42f594f5f4ca52c8a84b749146d08af214cc959ed2aaaa916eaafd3" {
		t.Fatal("wrong hash:", myhash.String())
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
	myhash := h.Sum()

	if myhash.String() != "h:2f806f905436dc7c5079ad8062467266e225d8110a3c58d17628d609cb1c99d0" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_state_element_encode
func TestStateElementHash(t *testing.T) {
	h := NewHasher()

	se := StateElement{
		ID:          Hash256{1, 2, 3},
		LeafIndex:   1,
		MerkleProof: []Hash256{{4, 5, 6}, {7, 8, 9}},
	}

	se.EncodeTo(h.E)
	myhash := h.Sum()

	if myhash.String() != "h:bf6d7b74fb1e15ec4e86332b628a450e387c45b54ea98e57a6da8c9af317e468" {
		t.Fatal("wrong hash:", myhash.String())
	}
}

// mm2src/coins/sia/transaction.rs test_siacoin_element_encode
func TestSiacoinElementHash(t *testing.T) {
	h := NewHasher()

	stateElement := StateElement{
		ID:          Hash256{1, 2, 3},
		LeafIndex:   1,
		MerkleProof: []Hash256{{4, 5, 6}, {7, 8, 9}},
	}

	addr := StandardUnlockHash(PublicKey{1, 2, 3})

	siacoinElement := SiacoinElement{
		StateElement: stateElement,
		SiacoinOutput: SiacoinOutput{
			Address: addr,
			Value:   NewCurrency64(1),
		},
		MaturityHeight: 0,
	}

	siacoinElement.EncodeTo(h.E)
	myhash := h.Sum()

	if myhash.String() != "h:3c867a54b7b3de349c56585f25a4365f31d632c3e42561b615055c77464d889e" {
		t.Fatal("wrong hash:", myhash.String())
	}
}
