package license

import (
	"crypto/ed25519"
	"encoding/base64"
)

func (l *License) Sign(
	privateKey ed25519.PrivateKey,
) error {
	data, err := l.SigningBytes()
	if err != nil {
		return err
	}

	signature := ed25519.Sign(
		privateKey,
		data,
	)

	l.Signature = base64.StdEncoding.EncodeToString(
		signature,
	)

	return nil
}
