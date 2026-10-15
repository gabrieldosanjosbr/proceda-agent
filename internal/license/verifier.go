package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"
)

var (
	ErrInvalidSignature = errors.New(
		"invalid license signature",
	)

	ErrInvalidLicense = errors.New(
		"invalid license",
	)

	ErrExpired = errors.New(
		"license expired",
	)

	ErrHostMismatch = errors.New(
		"license is not valid for this host",
	)
)

func (l License) Validate(
	installationID string,
	hostFingerprint string,
	now time.Time,
) error {
	if l.InstallationID != installationID {
		return ErrInvalidLicense
	}

	if l.Version != 1 {
		return ErrInvalidLicense
	}

	if l.LicenseID == "" ||
		l.InstallationID == "" ||
		l.HostFingerprint == "" ||
		l.MaxInstances <= 0 {
		return ErrInvalidLicense
	}

	if l.HostFingerprint != hostFingerprint {
		return ErrHostMismatch
	}

	if now.Unix() > l.ExpiresAt {
		return ErrExpired
	}

	return nil
}

func (l License) VerifySignature(
	publicKey ed25519.PublicKey,
) error {
	data, err := l.SigningBytes()
	if err != nil {
		return err
	}

	return verifySignature(
		publicKey,
		data,
		l.Signature,
	)
}

func verifySignature(
	publicKey ed25519.PublicKey,
	data []byte,
	encodedSignature string,
) error {
	signature, err := base64.StdEncoding.DecodeString(
		encodedSignature,
	)
	if err != nil {
		return ErrInvalidSignature
	}

	if !ed25519.Verify(
		publicKey,
		data,
		signature,
	) {
		return ErrInvalidSignature
	}

	return nil
}
