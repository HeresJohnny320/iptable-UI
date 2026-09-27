package wireguard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type commandCall struct {
	args []string
}

type fakeCommandRunner struct {
	calls     []commandCall
	active    bool
	stripText string
	syncMode  os.FileMode
	syncErr   error
}

func (r *fakeCommandRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, commandCall{args: append([]string(nil), args...)})
	if len(args) >= 2 && args[0] == "ip" && args[1] == "link" && !r.active {
		return nil, errors.New("interface is down")
	}
	if len(args) >= 2 && args[0] == "wg-quick" && args[1] == "strip" {
		return []byte(r.stripText), nil
	}
	if len(args) == 4 && args[0] == "wg" && args[1] == "syncconf" {
		info, err := os.Stat(args[3])
		if err != nil {
			return nil, err
		}
		r.syncMode = info.Mode().Perm()
		return nil, r.syncErr
	}
	return nil, nil
}

func TestLoadExistingConfigNeverExposesPrivateKey(t *testing.T) {
	manager, path, privateKey := writeExistingConfigFixture(t, &fakeCommandRunner{})
	config, err := manager.LoadExisting(context.Background(), "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if config.Address != "10.66.0.1/24" || config.ListenPort != 51820 || config.PeerPublicKey != testPublicKeyC || config.AllowedIPs != "10.66.0.2/32, 192.168.1.0/24" {
		t.Fatalf("unexpected safe config view: %+v", config)
	}
	if strings.Contains(strings.ToLower(strings.Join([]string{config.InterfaceName, config.ConfigPath, config.Address, config.PeerPublicKey, config.AllowedIPs}, " ")), strings.ToLower(privateKey)) {
		t.Fatal("private key was returned by config reader")
	}
	if config.ConfigPath != path || config.Active {
		t.Fatalf("unexpected config path or active state: %+v", config)
	}
}

func TestUpdateExistingBacksUpAndPreservesPrivateKeyAndOtherSettings(t *testing.T) {
	runner := &fakeCommandRunner{}
	manager, path, privateKey := writeExistingConfigFixture(t, runner)
	result, err := manager.UpdateExisting(context.Background(), EditConfigRequest{
		InterfaceName: "wg0", Address: "10.66.0.1/24", ListenPort: 51821,
		PeerPublicKey: testPublicKeyD, AllowedIPs: "10.66.0.2/32, 192.168.2.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Applied || !strings.Contains(result.Message, "not active") {
		t.Fatalf("inactive interface should save without claiming runtime apply: %+v", result)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, expected := range []string{"PrivateKey = " + privateKey, "ListenPort = 51821", "PublicKey = " + testPublicKeyD, "AllowedIPs = 10.66.0.2/32, 192.168.2.0/24", "PostUp = echo keep-me"} {
		if !strings.Contains(text, expected) {
			t.Errorf("updated config missing %q:\n%s", expected, text)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}
	backups, err := filepath.Glob(path + ".iptable-ui-*.bak")
	if err != nil || len(backups) != 1 {
		t.Fatalf("expected protected config backup, files=%v err=%v", backups, err)
	}
	backupInfo, err := os.Stat(backups[0])
	if err != nil || backupInfo.Mode().Perm() != 0600 {
		t.Fatalf("backup must be mode 0600: %v, %v", backupInfo, err)
	}
}

func TestUpdateExistingSyncsActiveInterface(t *testing.T) {
	runner := &fakeCommandRunner{active: true, stripText: "[Interface]\nListenPort = 51820\n"}
	manager, _, _ := writeExistingConfigFixture(t, runner)
	result, err := manager.UpdateExisting(context.Background(), EditConfigRequest{
		InterfaceName: "wg0", Address: "10.66.0.1/24", ListenPort: 51821,
		PeerPublicKey: testPublicKeyD, AllowedIPs: "10.66.0.2/32",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied || !strings.Contains(result.Message, "synced") {
		t.Fatalf("active interface should be synchronized: %+v", result)
	}
	foundSync := false
	for _, call := range runner.calls {
		if len(call.args) == 4 && call.args[0] == "wg" && call.args[1] == "syncconf" && call.args[2] == "wg0" {
			foundSync = true
		}
	}
	if !foundSync || runner.syncMode != 0600 {
		t.Fatalf("wg syncconf was not safely run: mode=%o calls=%+v", runner.syncMode, runner.calls)
	}
}

func TestLoadRejectsMultiplePeers(t *testing.T) {
	manager := SetupManager{ConfigDir: t.TempDir()}
	content := "[Interface]\nAddress = 10.66.0.1/24\nListenPort = 51820\nPrivateKey = " + testPrivateKey + "\n[Peer]\nPublicKey = " + testPublicKeyC + "\nAllowedIPs = 10.66.0.2/32\n[Peer]\nPublicKey = " + testPublicKeyD + "\nAllowedIPs = 10.66.0.3/32\n"
	if err := os.WriteFile(filepath.Join(manager.ConfigDir, "wg0.conf"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.LoadExisting(context.Background(), "wg0"); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected multi-peer config to be rejected, got %v", err)
	}
}

const (
	testPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	testPublicKeyC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	testPublicKeyD = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
)

func writeExistingConfigFixture(t *testing.T, runner *fakeCommandRunner) (SetupManager, string, string) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "wg0.conf")
	config := "[Interface]\nAddress = 10.66.0.1/24\nListenPort = 51820\nPrivateKey = " + testPrivateKey + "\nPostUp = echo keep-me\n\n[Peer]\nPublicKey = " + testPublicKeyC + "\nAllowedIPs = 10.66.0.2/32, 192.168.1.0/24\n"
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	return SetupManager{ConfigDir: directory, Commands: runner}, path, testPrivateKey
}
