package rhp

import (
	"errors"
	"fmt"

	"go.sia.tech/core/types"
)

// Validate validates a read sector request.
func (req *RPCReadSectorRequest) Validate(pk types.PublicKey) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	} else if err := req.Token.Validate(); err != nil {
		return fmt.Errorf("token is invalid: %w", err)
	}
	switch {
	case req.Length == 0:
		return errors.New("length must be greater than 0")
	case req.Offset+req.Length > SectorSize:
		return errors.New("read request exceeds sector bounds")
	case (req.Offset+req.Length)%LeafSize != 0:
		return errors.New("read request must be segment aligned")
	}
	return nil
}

// Validate validates a write sector request.
func (req *RPCWriteSectorStreamingRequest) Validate(pk types.PublicKey, maxDuration uint64) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	} else if err := req.Token.Validate(); err != nil {
		return fmt.Errorf("token is invalid: %w", err)
	}
	switch {
	case req.Duration == 0:
		return errors.New("duration must be greater than 0")
	case req.DataLength == 0:
		return errors.New("sector must not be empty")
	case req.DataLength%LeafSize != 0:
		return errors.New("sector must be segment aligned")
	case req.DataLength > SectorSize:
		return errors.New("sector exceeds sector bounds")
	case req.Duration > maxDuration:
		return fmt.Errorf("duration exceeds maximum: %d > %d", req.Duration, maxDuration)
	}
	return nil
}

// Validate validates a modify sectors request. Signatures are not validated.
func (req *RPCModifySectorsRequest) Validate(pk types.PublicKey, maxActions uint64) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	}
	return ValidateModifyActions(req.Actions, maxActions)
}

// Validate validates a sector roots request. Signatures are not validated.
func (req *RPCSectorRootsRequest) Validate(pk types.PublicKey, fc types.V2FileContract) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	}

	contractSectors := fc.Filesize / SectorSize
	switch {
	case req.Length == 0:
		return errors.New("length must be greater than 0")
	case req.Length+req.Offset > contractSectors:
		return fmt.Errorf("read request range exceeds contract sectors: %d > %d", req.Length+req.Offset, contractSectors)
	}
	return nil
}

// Validate validates a form contract request. Prices are not validated
func (req *RPCFormContractRequest) Validate(pk types.PublicKey, tip types.ChainIndex, maxCollateral types.Currency, maxDuration uint64) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	}

	// validate the request fields
	switch {
	case req.MinerFee.IsZero():
		return errors.New("miner fee must be greater than 0")
	case req.Basis == (types.ChainIndex{}):
		return errors.New("basis must be set")
	case len(req.RenterInputs) == 0:
		return errors.New("renter inputs must not be empty")
	}

	// validate the contract fields
	hp := req.Prices
	expirationHeight := req.Contract.ProofHeight + proofWindow
	duration := expirationHeight - hp.TipHeight
	// calculate the minimum allowance required for the contract based on the
	// host's locked collateral and the contract duration
	minRenterAllowance := MinRenterAllowance(hp, duration, req.Contract.Collateral)

	switch {
	case expirationHeight <= tip.Height: // must be validated against tip instead of prices
		return errors.New("contract expiration height is in the past")
	case req.Contract.Allowance.IsZero():
		return errors.New("allowance is zero")
	case req.Contract.Collateral.Cmp(maxCollateral) > 0:
		return fmt.Errorf("collateral %v exceeds max collateral %v", req.Contract.Collateral, maxCollateral)
	case duration > maxDuration:
		return fmt.Errorf("contract duration %v exceeds max duration %v", duration, maxDuration)
	case req.Contract.Allowance.Cmp(minRenterAllowance) < 0:
		return fmt.Errorf("allowance %v is less than minimum %v for collateral", req.Contract.Allowance, minRenterAllowance)
	default:
		return nil
	}
}

// Validate validates a renew contract request. Prices are not validated
func (req *RPCRenewContractRequest) Validate(pk types.PublicKey, tip types.ChainIndex, maxCollateral types.Currency, maxDuration uint64) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	}

	// validate the request fields
	switch {
	case req.MinerFee.IsZero():
		return errors.New("miner fee must be greater than 0")
	case req.Basis == (types.ChainIndex{}):
		return errors.New("basis must be set")
	case len(req.RenterInputs) == 0:
		return errors.New("renter inputs must not be empty")
	}

	// validate the contract fields
	hp := req.Prices
	expirationHeight := req.Renewal.ProofHeight + proofWindow
	duration := expirationHeight - hp.TipHeight
	// calculate the minimum allowance required for the contract based on the
	// host's locked collateral and the contract duration
	minRenterAllowance := MinRenterAllowance(hp, duration, req.Renewal.Collateral)

	switch {
	case expirationHeight <= tip.Height: // must be validated against tip instead of prices
		return errors.New("contract expiration height is in the past")
	case req.Renewal.Allowance.IsZero():
		return errors.New("allowance is zero")
	case req.Renewal.Collateral.Cmp(maxCollateral) > 0:
		return fmt.Errorf("collateral %v exceeds max collateral %v", req.Renewal.Collateral, maxCollateral)
	case duration > maxDuration:
		return fmt.Errorf("contract duration %v exceeds max duration %v", duration, maxDuration)
	case req.Renewal.Allowance.Cmp(minRenterAllowance) < 0:
		return fmt.Errorf("allowance %v is less than minimum %v for collateral", req.Renewal.Allowance, minRenterAllowance)
	default:
		return nil
	}
}

// Validate checks that the request is valid
func (req *RPCVerifySectorRequest) Validate(pk types.PublicKey) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	} else if err := req.Token.Validate(); err != nil {
		return fmt.Errorf("token is invalid: %w", err)
	} else if req.LeafIndex >= LeavesPerSector {
		return fmt.Errorf("leaf index must be less than %d", LeavesPerSector)
	}
	return nil
}
