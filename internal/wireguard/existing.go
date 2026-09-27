package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type ExistingConfig struct {
	InterfaceName string `json:"interfaceName"`
	ConfigPath    string `json:"configPath"`
	Address       string `json:"serverAddress"`
	ListenPort    uint16 `json:"listenPort"`
	PeerPublicKey string `json:"peerPublicKey"`
	AllowedIPs    string `json:"allowedIPs"`
	Active        bool   `json:"active"`
}

type EditConfigRequest struct {
	InterfaceName string `json:"interfaceName"`
	Address       string `json:"serverAddress"`
	ListenPort    uint16 `json:"listenPort"`
	PeerPublicKey string `json:"peerPublicKey"`
	AllowedIPs    string `json:"allowedIPs"`
}

type EditConfigResult struct {
	Config  ExistingConfig `json:"config"`
	Applied bool           `json:"applied"`
	Message string         `json:"message"`
}

type CommandRunner interface {
	Run(context.Context, ...string) ([]byte, error)
}

type OSCommandRunner struct{}

func (OSCommandRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New("missing command")
	}
	return exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
}

func (m SetupManager) LoadExisting(ctx context.Context, interfaceName string) (ExistingConfig, error) {
	if !interfacePattern.MatchString(interfaceName) {
		return ExistingConfig{}, errors.New("invalid WireGuard interface name")
	}
	path := m.configPath(interfaceName)
	info, err := os.Lstat(path)
	if err != nil {
		return ExistingConfig{}, fmt.Errorf("read WireGuard config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return ExistingConfig{}, errors.New("WireGuard config must be a regular file, not a symlink or special file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return ExistingConfig{}, fmt.Errorf("read WireGuard config: %w", err)
	}
	config, _, err := parseExistingConfig(string(contents), interfaceName, path)
	if err != nil {
		return ExistingConfig{}, err
	}
	config.Active = m.isActive(ctx, interfaceName)
	return config, nil
}

func (m SetupManager) UpdateExisting(ctx context.Context, request EditConfigRequest) (EditConfigResult, error) {
	if !interfacePattern.MatchString(request.InterfaceName) {
		return EditConfigResult{}, errors.New("invalid WireGuard interface name")
	}
	if err := validateEditableConfig(request); err != nil {
		return EditConfigResult{}, err
	}
	path := m.configPath(request.InterfaceName)
	info, err := os.Lstat(path)
	if err != nil {
		return EditConfigResult{}, fmt.Errorf("read WireGuard config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return EditConfigResult{}, errors.New("WireGuard config must be a regular file, not a symlink or special file")
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return EditConfigResult{}, fmt.Errorf("read WireGuard config: %w", err)
	}
	if _, _, err := parseExistingConfig(string(original), request.InterfaceName, path); err != nil {
		return EditConfigResult{}, err
	}
	lines := strings.Split(strings.TrimSuffix(string(original), "\n"), "\n")
	for _, field := range []struct{ section, key, value string }{
		{"Interface", "Address", strings.TrimSpace(request.Address)},
		{"Interface", "ListenPort", strconv.Itoa(int(request.ListenPort))},
		{"Peer", "PublicKey", strings.TrimSpace(request.PeerPublicKey)},
		{"Peer", "AllowedIPs", normalizeAllowedIPs(request.AllowedIPs)},
	} {
		lines, err = replaceConfigValue(lines, field.section, field.key, field.value)
		if err != nil {
			return EditConfigResult{}, err
		}
	}
	updatedContents := strings.Join(lines, "\n") + "\n"
	backupPath, err := writeConfigBackup(path, original)
	if err != nil {
		return EditConfigResult{}, err
	}
	if err := atomicReplaceConfig(path, updatedContents); err != nil {
		return EditConfigResult{}, err
	}
	config, _, err := parseExistingConfig(updatedContents, request.InterfaceName, path)
	if err != nil {
		return EditConfigResult{}, err
	}
	active := m.isActive(ctx, request.InterfaceName)
	config.Active = active
	if !active {
		return EditConfigResult{Config: config, Message: "Saved. The interface is not active; bring it up with wg-quick to apply the saved config."}, nil
	}
	if err := m.syncActive(ctx, request.InterfaceName, path); err != nil {
		return EditConfigResult{Config: config, Message: fmt.Sprintf("Saved, but the active interface could not be synced: %v. Backup: %s", err, backupPath)}, nil
	}
	return EditConfigResult{Config: config, Applied: true, Message: fmt.Sprintf("Saved and synced WireGuard peer settings. Address/route changes may require restarting the interface. Backup: %s", backupPath)}, nil
}

func (m SetupManager) configPath(interfaceName string) string {
	configDir := m.ConfigDir
	if configDir == "" {
		configDir = "/etc/wireguard"
	}
	return filepath.Join(configDir, interfaceName+".conf")
}

func (m SetupManager) runner() CommandRunner {
	if m.Commands != nil {
		return m.Commands
	}
	return OSCommandRunner{}
}

func (m SetupManager) isActive(ctx context.Context, interfaceName string) bool {
	_, err := m.runner().Run(ctx, "ip", "link", "show", "dev", interfaceName)
	return err == nil
}

func (m SetupManager) syncActive(ctx context.Context, interfaceName, configPath string) error {
	runner := m.runner()
	stripped, err := runner.Run(ctx, "wg-quick", "strip", configPath)
	if err != nil {
		return fmt.Errorf("strip wg-quick config: %w", err)
	}
	file, err := os.CreateTemp("", "iptable-ui-wg-sync-*.conf")
	if err != nil {
		return fmt.Errorf("create temporary WireGuard sync config: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return fmt.Errorf("protect temporary WireGuard sync config: %w", err)
	}
	if _, err := file.Write(stripped); err != nil {
		file.Close()
		return fmt.Errorf("write temporary WireGuard sync config: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary WireGuard sync config: %w", err)
	}
	if _, err := runner.Run(ctx, "wg", "syncconf", interfaceName, temporaryPath); err != nil {
		return fmt.Errorf("sync active WireGuard interface: %w", err)
	}
	return nil
}

func parseExistingConfig(contents, interfaceName, path string) (ExistingConfig, string, error) {
	lines := strings.Split(contents, "\n")
	section := ""
	interfaceCount, peerCount := 0, 0
	values := map[string]map[string][]string{"Interface": {}, "Peer": {}}
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			switch section {
			case "Interface":
				interfaceCount++
			case "Peer":
				peerCount++
			}
			continue
		}
		if section != "Interface" && section != "Peer" {
			return ExistingConfig{}, "", errors.New("unsupported WireGuard config section; expected Interface and one Peer")
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return ExistingConfig{}, "", errors.New("unrecognized line in WireGuard config; edit is limited to standard key=value configs")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		values[section][key] = append(values[section][key], strings.TrimSpace(value))
	}
	if interfaceCount != 1 || peerCount != 1 {
		return ExistingConfig{}, "", errors.New("web editing supports configs with exactly one [Interface] and one [Peer] section")
	}
	get := func(section, key string) (string, error) {
		found := values[section][strings.ToLower(key)]
		if len(found) != 1 || found[0] == "" {
			return "", fmt.Errorf("WireGuard config must contain exactly one %s entry", key)
		}
		return found[0], nil
	}
	address, err := get("Interface", "Address")
	if err != nil {
		return ExistingConfig{}, "", err
	}
	listenPortText, err := get("Interface", "ListenPort")
	if err != nil {
		return ExistingConfig{}, "", err
	}
	listenPort, err := strconv.ParseUint(listenPortText, 10, 16)
	if err != nil || listenPort == 0 {
		return ExistingConfig{}, "", errors.New("existing WireGuard listen port is invalid")
	}
	privateKey, err := get("Interface", "PrivateKey")
	if err != nil || !validKey(privateKey) {
		return ExistingConfig{}, "", errors.New("existing WireGuard private key is missing or invalid; it will not be exposed or changed")
	}
	peerPublicKey, err := get("Peer", "PublicKey")
	if err != nil || !validKey(peerPublicKey) {
		return ExistingConfig{}, "", errors.New("existing peer public key is missing or invalid")
	}
	allowedIPs, err := get("Peer", "AllowedIPs")
	if err != nil {
		return ExistingConfig{}, "", err
	}
	return ExistingConfig{InterfaceName: interfaceName, ConfigPath: path, Address: address, ListenPort: uint16(listenPort), PeerPublicKey: peerPublicKey, AllowedIPs: allowedIPs}, privateKey, nil
}

func validateEditableConfig(request EditConfigRequest) error {
	addressList := strings.Split(request.Address, ",")
	if len(addressList) != 1 {
		return errors.New("edit one IPv4 interface address/CIDR at a time")
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(addressList[0]))
	if err != nil || !prefix.Addr().Is4() || prefix.Addr() == prefix.Masked().Addr() {
		return errors.New("interface address must be an IPv4 CIDR such as 10.66.0.1/24")
	}
	if request.ListenPort == 0 {
		return errors.New("listen port must be between 1 and 65535")
	}
	if !validKey(strings.TrimSpace(request.PeerPublicKey)) {
		return errors.New("peer public key must be a valid WireGuard key")
	}
	return validateAllowedIPs(request.AllowedIPs)
}

func validateAllowedIPs(value string) error {
	parts := strings.Split(value, ",")
	if len(parts) == 0 {
		return errors.New("at least one peer AllowedIPs address or network is required")
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return errors.New("peer AllowedIPs contains an empty entry")
		}
		if strings.Contains(part, "/") {
			if _, err := netip.ParsePrefix(part); err != nil {
				return fmt.Errorf("invalid AllowedIPs network %q", part)
			}
		} else if _, err := netip.ParseAddr(part); err != nil {
			return fmt.Errorf("invalid AllowedIPs address %q", part)
		}
	}
	return nil
}

func normalizeAllowedIPs(value string) string {
	parts := strings.Split(value, ",")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	return strings.Join(parts, ", ")
}

func replaceConfigValue(lines []string, sectionName, key, value string) ([]string, error) {
	section := ""
	start, end := -1, len(lines)
	matches := make([]int, 0, 1)
	for index, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if section == sectionName && end == len(lines) {
				end = index
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == sectionName {
				if start >= 0 {
					return nil, fmt.Errorf("multiple [%s] sections are not supported", sectionName)
				}
				start = index
			}
			continue
		}
		if section != sectionName || line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		left, _, hasValue := strings.Cut(line, "=")
		if hasValue && strings.EqualFold(strings.TrimSpace(left), key) {
			matches = append(matches, index)
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("missing [%s] section", sectionName)
	}
	if end == len(lines) {
		end = len(lines)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("multiple %s entries in [%s] section are not supported", key, sectionName)
	}
	if len(matches) == 1 {
		line := lines[matches[0]]
		left, _, _ := strings.Cut(line, "=")
		lines[matches[0]] = strings.TrimSpace(left) + " = " + value
		return lines, nil
	}
	insertAt := end
	for insertAt > start+1 && strings.TrimSpace(lines[insertAt-1]) == "" {
		insertAt--
	}
	lines = append(lines, "")
	copy(lines[insertAt+1:], lines[insertAt:])
	lines[insertAt] = key + " = " + value
	return lines, nil
}

func writeConfigBackup(configPath string, contents []byte) (string, error) {
	backupPath := configPath + ".iptable-ui-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".bak"
	file, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("create WireGuard config backup: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("write WireGuard config backup: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("sync WireGuard config backup: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("close WireGuard config backup: %w", err)
	}
	return backupPath, nil
}

func atomicReplaceConfig(path, contents string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".iptable-ui-wg-*.conf")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return fmt.Errorf("protect temporary config: %w", err)
	}
	if _, err := file.WriteString(contents); err != nil {
		file.Close()
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace WireGuard config: %w", err)
	}
	return nil
}
