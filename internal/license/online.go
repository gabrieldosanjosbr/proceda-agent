package license

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const authorizationCacheTTL = 5 * time.Minute

type OnlineAuthorizer struct {
	client         *Client
	publicKey      ed25519.PublicKey
	licenseID      string
	installationID string

	mu         sync.Mutex
	validUntil time.Time
}

func NewOnlineAuthorizer(
	client *Client,
	publicKey ed25519.PublicKey,
	licenseID string,
	installationID string,
) *OnlineAuthorizer {
	return &OnlineAuthorizer{
		client:         client,
		publicKey:      publicKey,
		licenseID:      licenseID,
		installationID: installationID,
	}
}

func (a *OnlineAuthorizer) Authorize(
	ctx context.Context,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	now := time.Now()

	if now.Before(a.validUntil) {
		return nil
	}

	// An expired authorization must never be reused.
	a.validUntil = time.Time{}

	nonceBytes := make([]byte, 32)

	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf(
			"generate authorization nonce: %w",
			err,
		)
	}

	nonce := hex.EncodeToString(nonceBytes)

	authorization, err := a.client.RequestAuthorization(
		ctx,
		AuthorizationRequest{
			LicenseID:      a.licenseID,
			InstallationID: a.installationID,
			Nonce:          nonce,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"request online authorization: %w",
			err,
		)
	}

	if err := authorization.ValidateStructure(); err != nil {
		return fmt.Errorf(
			"invalid authorization structure: %w",
			err,
		)
	}

	if err := authorization.VerifySignature(
		a.publicKey,
	); err != nil {
		return fmt.Errorf(
			"verify authorization signature: %w",
			err,
		)
	}

	now = time.Now()

	if err := authorization.Validate(
		a.licenseID,
		a.installationID,
		nonce,
		now,
	); err != nil {
		return fmt.Errorf(
			"validate online authorization: %w",
			err,
		)
	}

	remaining := time.Until(
		time.Unix(authorization.ValidUntil, 0),
	)

	// Do not cache up to the exact signed expiration.
	// Leave a one-second safety margin.
	if remaining <= time.Second {
		return ErrAuthorizationExpired
	}

	ttl := min(
		authorizationCacheTTL,
		remaining-time.Second,
	)

	a.validUntil = time.Now().Add(ttl)

	return nil
}
