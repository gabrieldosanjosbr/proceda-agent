package license

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ActivationRequest struct {
	InstallationID        string `json:"installation_id"`
	HostFingerprint       string `json:"host_fingerprint"`
	InstallationPublicKey string `json:"installation_public_key"`
	Token                 string `json:"token"`
}

type AuthorizationRequest struct {
	LicenseID      string `json:"license_id"`
	InstallationID string `json:"installation_id"`
	Nonce          string `json:"nonce"`
}

type Client struct {
	baseURL string
	client  *http.Client
}

func NewClient(
	baseURL string,
) *Client {
	return &Client{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 4 * time.Second,
		},
	}
}

func (c *Client) Activate(
	ctx context.Context,
	request ActivationRequest,
) (License, error) {
	var license License

	if err := c.post(
		ctx,
		"/v1/activate",
		request,
		&license,
	); err != nil {
		return License{}, err
	}

	return license, nil
}

func (c *Client) RequestAuthorization(
	ctx context.Context,
	request AuthorizationRequest,
) (Authorization, error) {
	var authorization Authorization

	if err := c.post(
		ctx,
		"/v1/authorization",
		request,
		&authorization,
	); err != nil {
		return Authorization{}, err
	}

	return authorization, nil
}

func (c *Client) post(
	ctx context.Context,
	path string,
	request any,
	response any,
) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf(
			"encode request: %w",
			err,
		)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf(
			"create request: %w",
			err,
		)
	}

	req.Header.Set(
		"Content-Type",
		"application/json",
	)

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf(
			"send request: %w",
			err,
		)
	}

	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode < 200 ||
		res.StatusCode >= 300 {
		data, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf(
				"license server returned status %d",
				res.StatusCode,
			)
		}

		return fmt.Errorf(
			"license server returned status %d: %s",
			res.StatusCode,
			strings.TrimSpace(string(data)),
		)
	}

	if err := json.NewDecoder(
		res.Body,
	).Decode(response); err != nil {
		return fmt.Errorf(
			"decode response: %w",
			err,
		)
	}

	return nil
}
