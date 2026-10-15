package lease

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

type Lease struct {
	ID         string
	InstanceID string
	ExpiresAt  time.Time
}

type SQLiteStore struct {
	db  *sql.DB
	mac []byte
}

var (
	ErrLeaseTampered    = errors.New("lease integrity check failed")
	ErrDatabaseMismatch = errors.New("database does not belong to this installation")
	ErrClockRollback    = errors.New("system clock rollback detected")
)

func (s *SQLiteStore) calculateMAC(id, instanceID string, expiresAt int64) string {
	h := hmac.New(sha256.New, s.mac)
	_, _ = h.Write([]byte(id))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(instanceID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strconv.FormatInt(expiresAt, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *SQLiteStore) verifyMAC(id, instanceID string, expiresAt int64, macValue string) bool {
	provided, err := hex.DecodeString(macValue)
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(s.calculateMAC(id, instanceID, expiresAt))
	if err != nil {
		return false
	}
	return hmac.Equal(expected, provided)
}

func NewSQLiteStore(
	path string,
	mac []byte,
) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)

	store := &SQLiteStore{
		db:  db,
		mac: append([]byte(nil), mac...),
	}

	if err := store.migrate(); err != nil {
		_ = db.Close()

		return nil, err
	}

	return store, nil
}

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS installation (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			database_id TEXT NOT NULL,
			installation_id TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS clock_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			last_seen_at INTEGER NOT NULL,
			mac TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS leases (
			id TEXT PRIMARY KEY,
			instance_id TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			mac TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_leases_expires_at ON leases (expires_at);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_leases_instance_id ON leases (instance_id);
	`)
	return err
}

func (s *SQLiteStore) calculateClockMAC(lastSeenAt int64) string {
	h := hmac.New(sha256.New, s.mac)
	_, _ = h.Write([]byte("clock_state"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strconv.FormatInt(lastSeenAt, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *SQLiteStore) ObserveTime(ctx context.Context, now time.Time, tolerance time.Duration) error {
	nowUnix := now.Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var lastSeenAt int64
	var macValue string
	err = tx.QueryRowContext(ctx, `SELECT last_seen_at, mac FROM clock_state WHERE id = 1`).Scan(&lastSeenAt, &macValue)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO clock_state (id, last_seen_at, mac) VALUES (1, ?, ?)`,
			nowUnix, s.calculateClockMAC(nowUnix))
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	provided, err := hex.DecodeString(macValue)
	if err != nil {
		return ErrClockRollback
	}
	expected, err := hex.DecodeString(s.calculateClockMAC(lastSeenAt))
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, provided) {
		return ErrClockRollback
	}
	if nowUnix < lastSeenAt-int64(tolerance/time.Second) {
		return ErrClockRollback
	}
	if nowUnix > lastSeenAt {
		_, err = tx.ExecContext(ctx,
			`UPDATE clock_state SET last_seen_at = ?, mac = ? WHERE id = 1`,
			nowUnix, s.calculateClockMAC(nowUnix))
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

func (s *SQLiteStore) BindInstallation(ctx context.Context, installationID, databaseID string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO installation (id, database_id, installation_id) VALUES (1, ?, ?)`,
		databaseID, installationID)
	return err
}

func (s *SQLiteStore) VerifyInstallation(ctx context.Context, installationID, databaseID string) error {
	var storedDatabaseID, storedInstallationID string
	err := s.db.QueryRowContext(ctx,
		`SELECT database_id, installation_id FROM installation WHERE id = 1`).Scan(
		&storedDatabaseID, &storedInstallationID)
	if err != nil {
		return err
	}
	if storedDatabaseID != databaseID || storedInstallationID != installationID {
		return ErrDatabaseMismatch
	}
	return nil
}

// AcquireOrRenew atomically enforces the instance limit within this store.
// The caller must still verify authorization and observe the clock before calling it.
func (s *SQLiteStore) AcquireOrRenew(
	ctx context.Context,
	instanceID string,
	maxInstances int,
	now time.Time,
	ttl time.Duration,
) (Lease, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Lease{}, err
	}
	defer func() { _ = tx.Rollback() }()

	// Verify lease integrity and remove only legitimately expired leases.
	rows, err := tx.QueryContext(ctx, `SELECT id, instance_id, expires_at, mac FROM leases`)
	if err != nil {
		return Lease{}, err
	}
	type oldLease struct {
		id        string
		expiresAt int64
		mac       string
	}
	var expired []oldLease
	var existing *Lease
	count := 0
	for rows.Next() {
		var id, inst, macValue string
		var expiresAt int64
		if err := rows.Scan(&id, &inst, &expiresAt, &macValue); err != nil {
			_ = rows.Close()
			return Lease{}, err
		}
		if !s.verifyMAC(
			id,
			inst,
			expiresAt,
			macValue,
		) {
			_ = rows.Close()

			return Lease{}, ErrLeaseTampered
		}

		if expiresAt <= now.Unix() {
			expired = append(
				expired,
				oldLease{id, expiresAt, macValue},
			)

			continue
		}
		count++
		if inst == instanceID {
			item := Lease{ID: id, InstanceID: inst, ExpiresAt: time.Unix(expiresAt, 0)}
			existing = &item
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return Lease{}, err
	}
	if err := rows.Close(); err != nil {
		return Lease{}, err
	}
	for _, old := range expired {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM leases WHERE id = ? AND expires_at = ? AND mac = ?`,
			old.id, old.expiresAt, old.mac); err != nil {
			return Lease{}, err
		}
	}
	if existing != nil {
		updated := now.Add(ttl)
		unix := updated.Unix()
		result, err := tx.ExecContext(ctx,
			`UPDATE leases SET expires_at = ?, mac = ? WHERE id = ?`,
			unix, s.calculateMAC(existing.ID, existing.InstanceID, unix), existing.ID)
		if err != nil {
			return Lease{}, err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return Lease{}, err
		}
		if affected != 1 {
			return Lease{}, fmt.Errorf(
				"unexpected lease update: affected %d rows",
				affected,
			)
		}
		existing.ExpiresAt = updated
		if err := tx.Commit(); err != nil {
			return Lease{}, err
		}
		return *existing, nil
	}
	if count >= maxInstances {
		return Lease{}, ErrInstanceLimitReached
	}
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return Lease{}, fmt.Errorf("generate lease id: %w", err)
	}
	item := Lease{ID: hex.EncodeToString(idBytes), InstanceID: instanceID, ExpiresAt: now.Add(ttl)}
	unix := item.ExpiresAt.Unix()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO leases (id, instance_id, expires_at, mac) VALUES (?, ?, ?, ?)`,
		item.ID, item.InstanceID, unix, s.calculateMAC(item.ID, item.InstanceID, unix)); err != nil {
		return Lease{}, err
	}
	if err := tx.Commit(); err != nil {
		return Lease{}, err
	}
	return item, nil
}
