package vaultmock

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/hashicorp/go-uuid"
	vaultAPI "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/audit"
	credAppId "github.com/hashicorp/vault/builtin/credential/app-id"
	"github.com/hashicorp/vault/helper/salt"
	vaultHTTP "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/physical"
	"github.com/hashicorp/vault/vault"
	log "github.com/mgutz/logxi/v1"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"testing"
	"sync"
)

func RunMockVault(t *testing.T) (net.Listener, string, string, string) {
	core, err := vault.NewCore(GetMockVaultConfig())
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	keys, rootToken := vault.TestCoreInit(t, core)
	for _, key := range keys {
		if _, err := core.Unseal(key); err != nil {
			t.Fatalf("unseal err: %s", err)
		}
	}
	sealed, err := core.Sealed()
	if err != nil {
		t.Fatalf("err checking seal status: %s", err)
	}
	if sealed {
		t.Fatal("should not be sealed")
	}
	ln, addr := vaultHTTP.TestServer(t, core)

	// Create client to vault for configuration
	cfg := vaultAPI.DefaultConfig()
	cfg.Address = addr
	c, _ := vaultAPI.NewClient(cfg)
	c.SetToken(rootToken)

	// Configure app-id auth
	err = c.Sys().EnableAuth("app-id", "app-id", "app-id")
	if err != nil {
		t.Fatalf("Error enabling app-id on mock vault: %v", err)
	}

	// Generate and configure an app-id and user-id
	test_app_id, _ := uuid.GenerateUUID()
	test_user_id, _ := uuid.GenerateUUID()
	req, err := http.NewRequest("POST", addr+"/v1/auth/app-id/map/app-id/"+test_app_id, bytes.NewBufferString(`{"value":"admins", "display_name":"test"}`))
	req.Header.Set("X-Vault-Token", rootToken)
	if err != nil {
		t.Fatalf("Error creating http request to set up app-id for mock vault: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Error setting up app-id for mock vault: HTTP code: %v Error: %v", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusNoContent {
		defer resp.Body.Close()
		html, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("Error setting up app-id for mock vault: HTTP code: %v Response: %v", resp.StatusCode, string(html))
	}
	req, err = http.NewRequest("POST", addr+"/v1/auth/app-id/map/user-id/"+test_user_id, bytes.NewBufferString(fmt.Sprintf(`{"value":"%s"}`, test_app_id)))
	req.Header.Set("X-Vault-Token", rootToken)
	if err != nil {
		t.Fatalf("Error creating http request to map user-id to app-id for mock vault: %v", err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Error mapping user-id to app-id for mock vault: HTTP code: %v Error: %v", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusNoContent {
		defer resp.Body.Close()
		html, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("Error mapping user-id to app-id for mock vault: HTTP code: %v Response: %v", resp.StatusCode, string(html))
	}

	return ln, addr, test_app_id, test_user_id

}

func GetMockVaultConfig() *vault.CoreConfig {
	logger := log.NewLogger(log.NewConcurrentWriter(os.Stdout), "Mock Vault: ")
	inm := physical.NewInmem(logger)

	noopAudits := map[string]audit.Factory{
		"noop": func(config *audit.BackendConfig) (audit.Backend, error) {
			view := &logical.InmemStorage{}
			view.Put(&logical.StorageEntry{
				Key:   "salt",
				Value: []byte("foo"),
			})
			config.SaltConfig = &salt.Config{
				HMAC:     sha256.New,
				HMACType: "hmac-sha256",
			}
			config.SaltView = view
			return &NoopAudit{
				Config: config,
			}, nil
		},
	}

	conf := &vault.CoreConfig{
		Physical:      inm,
		AuditBackends: noopAudits,
		LogicalBackends: map[string]logical.Factory{
			"generic": vault.LeasedPassthroughBackendFactory,
		},
		CredentialBackends: map[string]logical.Factory{
			"app-id": credAppId.Factory,
		},
		DisableMlock: true,
		Logger:       logger,
	}

	return conf
}

type NoopAudit struct {
	Config    *audit.BackendConfig
	salt      *salt.Salt
	saltMutex sync.RWMutex
}

func (n *NoopAudit) GetHash(data string) (string, error) {
	salt, err := n.Salt()
	if err != nil {
		return "", err
	}
	return salt.GetIdentifiedHMAC(data), nil
}

func (n *NoopAudit) LogRequest(a *logical.Auth, r *logical.Request, e error) error {
	return nil
}

func (n *NoopAudit) LogResponse(a *logical.Auth, r *logical.Request, re *logical.Response, err error) error {
	return nil
}

func (n *NoopAudit) Reload() error {
	return nil
}

func (n *NoopAudit) Invalidate() {
	n.saltMutex.Lock()
	defer n.saltMutex.Unlock()
	n.salt = nil
}

func (n *NoopAudit) Salt() (*salt.Salt, error) {
	n.saltMutex.RLock()
	if n.salt != nil {
		defer n.saltMutex.RUnlock()
		return n.salt, nil
	}
	n.saltMutex.RUnlock()
	n.saltMutex.Lock()
	defer n.saltMutex.Unlock()
	if n.salt != nil {
		return n.salt, nil
	}
	salt, err := salt.NewSalt(n.Config.SaltView, n.Config.SaltConfig)
	if err != nil {
		return nil, err
	}
	n.salt = salt
	return salt, nil
}
