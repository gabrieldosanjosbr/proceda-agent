package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proceda-agent/internal/httpapi"
	"proceda-agent/internal/installation"
	"proceda-agent/internal/lease"
	"proceda-agent/internal/license"
)

const (
	dbPath                     = "/var/lib/proceda/proceda.db"
	statePath                  = "/var/lib/proceda/installation.state"
	installationKeyPath        = "/var/lib/proceda/installation.key"
	installationSigningKeyPath = "/var/lib/proceda/installation-signing-key"
	licensePath                = "/var/lib/proceda/license.json"
	socketPath                 = "/run/proceda/agent.sock"
	machineIDPath              = "/host/etc/machine-id"
)

func main() {
	if len(os.Args) > 1 &&
		os.Args[1] == "activate" {
		if len(os.Args) != 3 ||
			strings.TrimSpace(os.Args[2]) == "" {
			log.Fatal(
				"usage: proceda-agent activate <token>",
			)
		}

		if err := activate(
			os.Args[2],
		); err != nil {
			log.Fatal(err)
		}

		return
	}

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func activate(
	token string,
) error {
	mac, err := installation.LoadOrCreateMAC(
		installationKeyPath,
	)
	if err != nil {
		return err
	}

	state, err := installation.LoadOrCreate(
		statePath,
		mac,
	)
	if err != nil {
		return err
	}

	fingerprint, err := installation.HostFingerprint(
		machineIDPath,
	)
	if err != nil {
		return err
	}

	serverURL := os.Getenv(
		"PROCEDA_LICENSE_SERVER",
	)
	if serverURL == "" {
		return fmt.Errorf(
			"PROCEDA_LICENSE_SERVER is required",
		)
	}

	keyPair, err := installation.LoadOrCreateKeyPair(
		installationSigningKeyPath,
	)
	if err != nil {
		return err
	}

	installationPublicKey := base64.StdEncoding.EncodeToString(
		keyPair.PublicKey,
	)

	client := license.NewClient(
		serverURL,
	)

	lic, err := client.Activate(
		context.Background(),
		license.ActivationRequest{
			InstallationID:        state.InstallationID,
			HostFingerprint:       fingerprint,
			InstallationPublicKey: installationPublicKey,
			Token:                 token,
		},
	)
	if err != nil {
		return err
	}

	rootPublicKey, err := license.PublicKey()
	if err != nil {
		return err
	}

	if err := lic.VerifySignature(
		rootPublicKey,
	); err != nil {
		return err
	}

	if err := lic.VerifyInstallationPublicKey(
		keyPair.PublicKey,
	); err != nil {
		return err
	}

	if err := lic.Save(
		licensePath,
	); err != nil {
		return err
	}

	log.Printf(
		"installation activated: %s",
		state.InstallationID,
	)

	return nil
}

func run() error {
	mac, err := installation.LoadOrCreateMAC(
		installationKeyPath,
	)
	if err != nil {
		return err
	}

	state, err := installation.Load(
		statePath,
		mac,
	)
	if err != nil {
		return err
	}

	lic, err := license.Load(
		licensePath,
	)
	if err != nil {
		return err
	}

	rootPublicKey, err := license.PublicKey()
	if err != nil {
		return err
	}

	if err := lic.VerifySignature(
		rootPublicKey,
	); err != nil {
		return err
	}

	keyPair, err := installation.LoadOrCreateKeyPair(
		installationSigningKeyPath,
	)
	if err != nil {
		return err
	}

	if err := lic.VerifyInstallationPublicKey(
		keyPair.PublicKey,
	); err != nil {
		return err
	}

	fingerprint, err := installation.HostFingerprint(
		machineIDPath,
	)
	if err != nil {
		return err
	}

	if err := lic.Validate(
		state.InstallationID,
		fingerprint,
		time.Now(),
	); err != nil {
		return err
	}

	serverURL := os.Getenv(
		"PROCEDA_LICENSE_SERVER",
	)
	if serverURL == "" {
		return fmt.Errorf(
			"PROCEDA_LICENSE_SERVER is required",
		)
	}

	client := license.NewClient(
		serverURL,
	)

	authorizer := license.NewOnlineAuthorizer(
		client,
		rootPublicKey,
		lic.LicenseID,
		state.InstallationID,
	)

	store, err := bootstrap(
		dbPath,
		state,
		mac,
	)
	if err != nil {
		return err
	}

	defer func() {
		_ = store.Close()
	}()

	manager := lease.NewManager(
		store,
		lic.MaxInstances,
		2*time.Minute,
		authorizer,
	)

	server := httpapi.NewServer(
		manager,
		keyPair.PrivateKey,
		lic,
	)

	if err := os.MkdirAll(
		filepath.Dir(socketPath),
		0755,
	); err != nil {
		return err
	}

	/*
	 * Remove socket abandonado de uma execução anterior.
	 */
	if err := os.Remove(socketPath); err != nil &&
		!os.IsNotExist(err) {
		return err
	}

	listener, err := net.Listen(
		"unix",
		socketPath,
	)
	if err != nil {
		return err
	}

	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()

	if err := os.Chmod(
		socketPath,
		0660,
	); err != nil {
		return err
	}

	log.Printf(
		"proceda-agent listening on unix://%s",
		socketPath,
	)

	if err := http.Serve(
		listener,
		server.Routes(),
	); err != nil {
		return err
	}

	return nil
}

func bootstrap(
	dbPath string,
	state installation.State,
	mac []byte,
) (*lease.SQLiteStore, error) {
	_, dbErr := os.Stat(dbPath)

	if dbErr == nil {
		return validate(
			dbPath,
			state,
			mac,
		)
	}

	if os.IsNotExist(dbErr) {
		return initialize(
			dbPath,
			state,
			mac,
		)
	}

	return nil, dbErr
}

func initialize(
	dbPath string,
	state installation.State,
	mac []byte,
) (*lease.SQLiteStore, error) {
	store, err := lease.NewSQLiteStore(
		dbPath,
		mac,
	)
	if err != nil {
		return nil, err
	}

	if err := store.BindInstallation(
		context.Background(),
		state.InstallationID,
		state.DatabaseID,
	); err != nil {
		_ = store.Close()

		return nil, err
	}

	return store, nil
}

func validate(
	dbPath string,
	state installation.State,
	mac []byte,
) (*lease.SQLiteStore, error) {
	store, err := lease.NewSQLiteStore(
		dbPath,
		mac,
	)
	if err != nil {
		return nil, err
	}

	if err := store.VerifyInstallation(
		context.Background(),
		state.InstallationID,
		state.DatabaseID,
	); err != nil {
		_ = store.Close()

		return nil, err
	}

	return store, nil
}
