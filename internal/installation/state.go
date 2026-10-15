package installation

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidState = errors.New(
		"installation state integrity check failed",
	)

	ErrStateMissing = errors.New(
		"installation state is missing",
	)

	ErrInvalidMachineID = errors.New(
		"invalid machine id",
	)
)

type State struct {
	Version        int    `json:"version"`
	InstallationID string `json:"installation_id"`
	DatabaseID     string `json:"database_id"`
	CreatedAt      int64  `json:"created_at"`
	MAC            string `json:"mac"`
}

func HostFingerprint(
	path string,
) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	machineID := strings.TrimSpace(
		string(data),
	)

	if machineID == "" {
		return "", ErrInvalidMachineID
	}

	hash := sha256.Sum256(
		[]byte(machineID),
	)

	return hex.EncodeToString(
		hash[:],
	), nil
}

func New() (State, error) {
	installationID, err := randomID()
	if err != nil {
		return State{}, err
	}

	databaseID, err := randomID()
	if err != nil {
		return State{}, err
	}

	return State{
		Version:        1,
		InstallationID: installationID,
		DatabaseID:     databaseID,
		CreatedAt:      time.Now().Unix(),
	}, nil
}

func randomID() (string, error) {
	value := make([]byte, 32)

	if _, err := rand.Read(value); err != nil {
		return "", err
	}

	return hex.EncodeToString(value), nil
}

func (s State) calculateMAC(
	key []byte,
) []byte {
	h := hmac.New(
		sha256.New,
		key,
	)

	h.Write([]byte(strconv.Itoa(s.Version)))
	h.Write([]byte{0})

	h.Write([]byte(s.InstallationID))
	h.Write([]byte{0})

	h.Write([]byte(s.DatabaseID))
	h.Write([]byte{0})

	h.Write([]byte(
		strconv.FormatInt(s.CreatedAt, 10),
	))

	return h.Sum(nil)
}

func (s *State) Sign(
	key []byte,
) {
	s.MAC = hex.EncodeToString(
		s.calculateMAC(key),
	)
}

func (s State) Verify(
	key []byte,
) bool {
	provided, err := hex.DecodeString(s.MAC)
	if err != nil {
		return false
	}

	expected := s.calculateMAC(key)

	return hmac.Equal(
		expected,
		provided,
	)
}

func (s State) Save(
	path string,
) error {
	data, err := json.MarshalIndent(
		s,
		"",
		"  ",
	)
	if err != nil {
		return err
	}

	return os.WriteFile(
		path,
		data,
		0600,
	)
}

func Load(
	path string,
	key []byte,
) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return State{}, ErrStateMissing
		}

		return State{}, err
	}

	var state State

	if err := json.Unmarshal(
		data,
		&state,
	); err != nil {
		return State{}, ErrInvalidState
	}

	if !state.Verify(key) {
		return State{}, ErrInvalidState
	}

	return state, nil
}

func LoadOrCreate(
	path string,
	key []byte,
) (State, error) {
	state, err := Load(path, key)

	if err == nil {
		return state, nil
	}

	if !errors.Is(err, ErrStateMissing) {
		return State{}, err
	}

	state, err = New()
	if err != nil {
		return State{}, err
	}

	state.Sign(key)

	if err := state.Save(path); err != nil {
		return State{}, err
	}

	return state, nil
}

func LoadOrCreateMAC(path string) ([]byte, error) {
	key, err := os.ReadFile(path)

	if err == nil {
		if len(key) != 32 {
			return nil, errors.New("invalid MAC key")
		}

		return key, nil
	}

	if !os.IsNotExist(err) {
		return nil, err
	}

	key = make([]byte, 32)

	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	if err := os.WriteFile(
		path,
		key,
		0600,
	); err != nil {
		return nil, err
	}

	return key, nil
}
