package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

const publicKeyBase64 = "dZqurfd8kWQwdo/RCaaNAiTEQjcwwv9Pscnv4/ngDnA="

func PublicKey() (
	ed25519.PublicKey,
	error,
) {
	value, err := base64.StdEncoding.DecodeString(
		publicKeyBase64,
	)
	if err != nil {
		return nil, err
	}

	if len(value) != ed25519.PublicKeySize {
		return nil, errors.New(
			"invalid embedded public key",
		)
	}

	return ed25519.PublicKey(value), nil
}
