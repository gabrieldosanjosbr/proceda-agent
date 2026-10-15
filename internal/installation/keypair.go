package installation

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
)

type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func GenerateKeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(
		rand.Reader,
	)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func LoadOrCreateKeyPair(
	path string,
) (*KeyPair, error) {
	data, err := os.ReadFile(path)

	if err == nil {
		if len(data) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf(
				"invalid installation signing key size: got %d, expected %d",
				len(data),
				ed25519.PrivateKeySize,
			)
		}

		privateKey := ed25519.PrivateKey(data)

		publicKey, ok := privateKey.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf(
				"invalid installation signing public key",
			)
		}

		return &KeyPair{
			PublicKey:  publicKey,
			PrivateKey: privateKey,
		}, nil
	}

	if !os.IsNotExist(err) {
		return nil, err
	}

	keyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	if err := savePrivateKey(
		path,
		keyPair.PrivateKey,
	); err != nil {
		return nil, err
	}

	return keyPair, nil
}

func savePrivateKey(
	path string,
	privateKey ed25519.PrivateKey,
) error {
	tmp := path + ".tmp"

	if err := os.WriteFile(
		tmp,
		privateKey,
		0600,
	); err != nil {
		return err
	}

	if err := os.Rename(
		tmp,
		path,
	); err != nil {
		_ = os.Remove(tmp)

		return err
	}

	return nil
}
