package license

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

type Authorization struct {
	Version        int    `json:"version"`
	LicenseID      string `json:"license_id"`
	InstallationID string `json:"installation_id"`
	IssuedAt       int64  `json:"issued_at"`
	ValidUntil     int64  `json:"valid_until"`
	Nonce          string `json:"nonce"`
	Signature      string `json:"signature"`
}

var (
	ErrInvalidAuthorization = errors.New(
		"invalid authorization",
	)

	ErrAuthorizationExpired = errors.New(
		"authorization expired",
	)
)

func (a Authorization) SigningBytes() []byte {
	return []byte(fmt.Sprintf(
		"PROCEDA-AUTHORIZATION-V2\n%d\n%s\n%s\n%d\n%d\n%s",
		a.Version,
		a.LicenseID,
		a.InstallationID,
		a.IssuedAt,
		a.ValidUntil,
		a.Nonce,
	))
}

func (a Authorization) VerifySignature(
	publicKey ed25519.PublicKey,
) error {
	return verifySignature(
		publicKey,
		a.SigningBytes(),
		a.Signature,
	)
}

func (a Authorization) Validate(
	licenseID string,
	installationID string,
	expectedNonce string,
	now time.Time,
) error {
	if err := a.ValidateStructure(); err != nil {
		return err
	}

	if a.LicenseID != licenseID ||
		a.InstallationID != installationID ||
		a.Nonce != expectedNonce ||
		!validCanonicalString(expectedNonce) {
		return ErrInvalidAuthorization
	}

	if now.Unix() < a.IssuedAt {
		return ErrInvalidAuthorization
	}

	if now.Unix() >= a.ValidUntil {
		return ErrAuthorizationExpired
	}

	return nil
}

func (a Authorization) ValidateStructure() error {
	if a.Version != 2 {
		return ErrInvalidAuthorization
	}

	if !validCanonicalString(a.LicenseID) ||
		!validCanonicalString(a.InstallationID) ||
		!validCanonicalString(a.Nonce) ||
		a.IssuedAt <= 0 ||
		a.ValidUntil <= a.IssuedAt {
		return ErrInvalidAuthorization
	}

	return nil
}
