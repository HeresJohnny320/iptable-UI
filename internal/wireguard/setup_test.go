package wireguard

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fixedKeys struct {
	private string
	public  string
}

func (k fixedKeys) Generate(context.Context) (string, string, error) {
	return k.private, k.public, nil
}

func TestConfigureCreatesPrivateServerConfigAndClientTemplate(t *testing.T) {
	privateKey := strings.Repeat("A", 43) + "="
	publicKey := strings.Repeat("B", 43) + "="
	manager := SetupManager{ConfigDir: t.TempDir(), Keys: fixedKeys{private: privateKey, public: publicKey}}
	result, err := manager.Configure(context.Background(), SetupRequest{
		InterfaceName: "wg0", ServerAddress: "10.66.0.1/24", PeerAddress: "10.66.0.2",
		HomeLAN: "192.168.1.0/24", PeerPublicKey: strings.Repeat("C", 43) + "=",
		PublicEndpoint: "vpn.example.net:51820", ListenPort: 51820,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ServerPublicKey != publicKey || strings.Contains(result.PeerConfig, privateKey) || !strings.Contains(result.PeerConfig, "Address = 10.66.0.2/24") {
		t.Fatalf("unexpected client template result: %+v", result)
	}
	content, err := os.ReadFile(result.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "PrivateKey = "+privateKey) || !strings.Contains(string(content), "AllowedIPs = 10.66.0.2/32, 192.168.1.0/24") {
		t.Fatalf("server config missing expected settings: %s", content)
	}
	info, err := os.Stat(result.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestConfigureRefusesOverwriteAndInvalidRequests(t *testing.T) {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "wg0.conf")
	if err := os.WriteFile(configPath, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	manager := SetupManager{ConfigDir: configDir, Keys: fixedKeys{private: strings.Repeat("A", 43) + "=", public: strings.Repeat("B", 43) + "="}}
	_, err := manager.Configure(context.Background(), SetupRequest{
		InterfaceName: "wg0", ServerAddress: "10.66.0.1/24", PeerAddress: "10.66.0.2",
		HomeLAN: "192.168.1.0/24", PeerPublicKey: strings.Repeat("C", 43) + "=", PublicEndpoint: "vpn.example.net:51820",
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("expected existing config protection, got %v", err)
	}
	content, err := os.ReadFile(configPath)
	if err != nil || string(content) != "keep me" {
		t.Fatalf("existing config was changed: %q, %v", content, err)
	}
	if _, err := validateRequest(SetupRequest{InterfaceName: "wg0", ServerAddress: "10.66.0.1/24", PeerAddress: "10.66.0.2", HomeLAN: "192.168.1.0/24", PeerPublicKey: "not-a-key", PublicEndpoint: "vpn.example.net:51820"}); err == nil {
		t.Fatal("expected invalid key to be rejected")
	}
	if _, err := validateRequest(SetupRequest{InterfaceName: "wg0", ServerAddress: "10.66.0.1/24", PeerAddress: "10.66.0.2", HomeLAN: "192.168.1.0/24", PeerPublicKey: strings.Repeat("C", 43) + "=", PublicEndpoint: "vpn.example.net\nPostUp = bad:51820"}); err == nil {
		t.Fatal("expected endpoint config injection to be rejected")
	}
}
