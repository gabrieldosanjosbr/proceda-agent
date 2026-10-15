package httpapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"proceda-agent/internal/lease"
	"proceda-agent/internal/license"
)

type Server struct {
	manager    *lease.Manager
	privateKey ed25519.PrivateKey
	license    license.License
}

type AcquireRequest struct {
	InstanceID string `json:"instance_id"`
	Nonce      string `json:"nonce"`
}

type LeaseProof struct {
	Version    int    `json:"version"`
	LeaseID    string `json:"lease_id"`
	InstanceID string `json:"instance_id"`
	ExpiresAt  int64  `json:"expires_at"`
	Nonce      string `json:"nonce"`
}

type AcquireResponse struct {
	LeaseProof LeaseProof      `json:"proof"`
	License    license.License `json:"license"`
	Signature  string          `json:"signature"`
}

func NewServer(
	manager *lease.Manager,
	privateKey ed25519.PrivateKey,
	lic license.License,
) *Server {
	return &Server{
		manager:    manager,
		privateKey: privateKey,
		license:    lic,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("POST /lease", s.acquire)

	return mux
}

func (s *Server) acquire(
	w http.ResponseWriter,
	r *http.Request,
) {
	var input AcquireRequest

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(
			w,
			"invalid request",
			http.StatusBadRequest,
		)

		return
	}

	if err := validateCanonicalString(
		input.InstanceID,
	); err != nil {
		http.Error(
			w,
			"invalid instance_id",
			http.StatusBadRequest,
		)

		return
	}

	if err := validateCanonicalString(
		input.Nonce,
	); err != nil {
		http.Error(
			w,
			"invalid nonce",
			http.StatusBadRequest,
		)

		return
	}

	item, err := s.manager.Acquire(
		r.Context(),
		input.InstanceID,
	)
	if err != nil {
		if errors.Is(
			err,
			lease.ErrInstanceLimitReached,
		) {
			http.Error(
				w,
				err.Error(),
				http.StatusConflict,
			)

			return
		}

		if errors.Is(
			err,
			lease.ErrUnauthorized,
		) {
			http.Error(
				w,
				err.Error(),
				http.StatusServiceUnavailable,
			)

			return
		}

		http.Error(
			w,
			"internal error",
			http.StatusInternalServerError,
		)

		return
	}

	proof := LeaseProof{
		Version:    1,
		LeaseID:    item.ID,
		InstanceID: item.InstanceID,
		ExpiresAt:  item.ExpiresAt.Unix(),
		Nonce:      input.Nonce,
	}

	signingBytes, err := proof.SigningBytes()
	if err != nil {
		http.Error(
			w,
			"internal error",
			http.StatusInternalServerError,
		)

		return
	}

	signature := ed25519.Sign(
		s.privateKey,
		signingBytes,
	)

	response := AcquireResponse{
		LeaseProof: proof,
		License:    s.license,
		Signature: base64.StdEncoding.EncodeToString(
			signature,
		),
	}

	writeJSON(
		w,
		http.StatusCreated,
		response,
	)
}

func (s *Server) health(
	w http.ResponseWriter,
	_ *http.Request,
) {
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(
	w http.ResponseWriter,
	status int,
	value any,
) {
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(value)
}

func (p LeaseProof) SigningBytes() (
	[]byte,
	error,
) {
	values := []string{
		p.LeaseID,
		p.InstanceID,
		p.Nonce,
	}

	for _, value := range values {
		if err := validateCanonicalString(
			value,
		); err != nil {
			return nil, err
		}
	}

	return []byte(fmt.Sprintf(
		"PROCEDA-LEASE-PROOF-V1\n%d\n%s\n%s\n%d\n%s",
		p.Version,
		p.LeaseID,
		p.InstanceID,
		p.ExpiresAt,
		p.Nonce,
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
