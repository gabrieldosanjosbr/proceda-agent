package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type License struct {
	Version               int    `json:"version"`
	LicenseID             string `json:"license_id"`
	Customer              string `json:"customer"`
	InstallationID        string `json:"installation_id"`
	HostFingerprint       string `json:"host_fingerprint"`
	InstallationPublicKey string `json:"installation_public_key"`
	Mode                  string `json:"mode"`
	MaxInstances          int    `json:"max_instances"`
	IssuedAt              int64  `json:"issued_at"`
	ExpiresAt             int64  `json:"expires_at"`
	Signature             string `json:"signature"`
}

func (l License) Save(
	path string,
) error {
	data, err := json.MarshalIndent(
		l,
		"",
		"  ",
	)
	if err != nil {
		return err
	}

	return os.WriteFile(
		path,
		append(data, '\n'),
		0600,
	)
}

func Load(
	path string,
) (License, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return License{}, err
	}

	var license License

	if err := json.Unmarshal(
		data,
		&license,
	); err != nil {
		return License{}, err
	}

	return license, nil
}

func (l License) SigningBytes() (
	[]byte,
	error,
) {
	values := []struct {
		name  string
		value string
	}{
		{"license_id", l.LicenseID},
		{"customer", l.Customer},
		{"installation_id", l.InstallationID},
		{"host_fingerprint", l.HostFingerprint},
		{"installation_public_key", l.InstallationPublicKey},
		{"mode", l.Mode},
	}

	for _, field := range values {
		if err := validateCanonicalString(
			field.value,
		); err != nil {
			return nil, fmt.Errorf(
				"invalid canonical field %s: %w",
				field.name,
				err,
			)
		}
	}

	return []byte(fmt.Sprintf(
		"PROCEDA-LICENSE-V1\n%d\n%s\n%s\n%s\n%s\n%s\n%s\n%d\n%d\n%d",
		l.Version,
		l.LicenseID,
		l.Customer,
		l.InstallationID,
		l.HostFingerprint,
		l.InstallationPublicKey,
		l.Mode,
		l.MaxInstances,
		l.IssuedAt,
		l.ExpiresAt,
	)), nil
}

func validateCanonicalString(
	value string,
) error {
	if value == "" ||
		strings.ContainsAny(
			value,
			"\r\n",
		) {
		return errors.New(
			"invalid canonical string",
		)
	}

	return nil
}

func (l License) VerifyInstallationPublicKey(
	publicKey ed25519.PublicKey,
) error {
	expected := base64.StdEncoding.EncodeToString(
		publicKey,
	)

	if l.InstallationPublicKey != expected {
		return fmt.Errorf(
			"license installation public key does not match local installation key",
		)
	}

	return nil
}

func validCanonicalString(
	value string,
) bool {
	return value != "" &&
		!strings.ContainsAny(
			value,
			"\r\n",
		)
}
