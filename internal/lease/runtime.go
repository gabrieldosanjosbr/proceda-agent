package lease

import (
	"context"
	"errors"
	"log"
	"time"
)

var ErrInstanceLimitReached = errors.New(
	"instance limit reached",
)

var ErrUnauthorized = errors.New(
	"agent authorization is not valid",
)

type Authorizer interface {
	Authorize(ctx context.Context) error
}

type Manager struct {
	store          *SQLiteStore
	maxInstances   int
	ttl            time.Duration
	clockTolerance time.Duration

	authorizer Authorizer
}

func NewManager(
	store *SQLiteStore,
	maxInstances int,
	ttl time.Duration,
	authorizer Authorizer,
) *Manager {
	return &Manager{
		store:          store,
		maxInstances:   maxInstances,
		ttl:            ttl,
		clockTolerance: 5 * time.Minute,
		authorizer:     authorizer,
	}
}

func (m *Manager) Acquire(
	ctx context.Context,
	instanceID string,
) (Lease, error) {
	if err := m.authorizer.Authorize(ctx); err != nil {
		log.Printf(
			"authorization denied: %v",
			err,
		)

		return Lease{}, ErrUnauthorized
	}

	now := time.Now()

	if err := m.store.ObserveTime(
		ctx,
		now,
		m.clockTolerance,
	); err != nil {
		return Lease{}, err
	}

	return m.store.AcquireOrRenew(
		ctx,
		instanceID,
		m.maxInstances,
		now,
		m.ttl,
	)
}
