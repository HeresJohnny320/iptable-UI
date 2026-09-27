package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type SetupRequest struct {
	InterfaceName  string `json:"interfaceName"`
	ServerAddress  string `json:"serverAddress"`
	PeerAddress    string `json:"peerAddress"`
	HomeLAN        string `json:"homeLAN"`
	PeerPublicKey  string `json:"peerPublicKey"`
	PublicEndpoint string `json:"publicEndpoint"`
	ListenPort     uint16 `json:"listenPort"`
}

type SetupResult struct {
	ConfigPath      string `json:"configPath"`
	ServerPublicKey string `json:"serverPublicKey"`
	PeerConfig      string `json:"peerConfig"`
}

type KeyGenerator interface {
	Generate(context.Context) (privateKey, publicKey string, err error)
}

type WGKeyGenerator struct{}

func (WGKeyGenerator) Generate(ctx context.Context) (string, string, error) {
	privateOutput, err := exec.CommandContext(ctx, "wg", "genkey").Output()
	if err != nil {
		return "", "", fmt.Errorf("generate WireGuard private key (is wireguard-tools installed?): %w", err)
	}
	privateKey := strings.TrimSpace(string(privateOutput))
	if !validKey(privateKey) {
		return "", "", errors.New("wg genkey returned an invalid key")
	}
	command := exec.CommandContext(ctx, "wg", "pubkey")
	command.Stdin = strings.NewReader(privateKey + "\n")
	publicOutput, err := command.Output()
	if err != nil {
		return "", "", fmt.Errorf("derive WireGuard public key: %w", err)
	}
	publicKey := strings.TrimSpace(string(publicOutput))
	if !validKey(publicKey) {
		return "", "", errors.New("wg pubkey returned an invalid key")
	}
	return privateKey, publicKey, nil
}

type SetupManager struct {
	ConfigDir string
	Keys      KeyGenerator
	Commands  CommandRunner
}

func (m SetupManager) Configure(ctx context.Context, request SetupRequest) (SetupResult, error) {
	validated, err := validateRequest(request)
	if err != nil {
		return SetupResult{}, err
	}
	keys := m.Keys
	if keys == nil {
		keys = WGKeyGenerator{}
	}
	privateKey, publicKey, err := keys.Generate(ctx)
	if err != nil {
		return SetupResult{}, err
	}
	if !validKey(privateKey) || !validKey(publicKey) {
		return SetupResult{}, errors.New("key generator returned invalid keys")
	}
	configDir := m.ConfigDir
	if configDir == "" {
		configDir = "/etc/wireguard"
	}
	configPath := filepath.Join(configDir, validated.InterfaceName+".conf")
	serverConfig := fmt.Sprintf("[Interface]\nAddress = %s\nListenPort = %d\nPrivateKey = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32, %s\n", validated.ServerAddress, validated.ListenPort, privateKey, validated.PeerPublicKey, validated.PeerAddress, validated.HomeLAN)
	if err := writeNewConfig(configPath, serverConfig); err != nil {
		return SetupResult{}, err
	}
	serverPrefix, _ := netip.ParsePrefix(validated.ServerAddress)
	peerConfig := fmt.Sprintf("[Interface]\nAddress = %s/%d\nPrivateKey = <HOME_PRIVATE_KEY>\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", validated.PeerAddress, serverPrefix.Bits(), publicKey, validated.PublicEndpoint, serverPrefix.Masked())
	return SetupResult{ConfigPath: configPath, ServerPublicKey: publicKey, PeerConfig: peerConfig}, nil
}

type validatedRequest struct {
	InterfaceName  string
	ServerAddress  string
	PeerAddress    string
	HomeLAN        string
	PeerPublicKey  string
	PublicEndpoint string
	ListenPort     uint16
}

var interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
var hostnamePattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$`)

func validateRequest(request SetupRequest) (validatedRequest, error) {
	request.InterfaceName = strings.TrimSpace(request.InterfaceName)
	if !interfacePattern.MatchString(request.InterfaceName) {
		return validatedRequest{}, errors.New("interface name must be 1-15 letters, numbers, dots, dashes, or underscores")
	}
	serverPrefix, err := netip.ParsePrefix(strings.TrimSpace(request.ServerAddress))
	if err != nil || !serverPrefix.Addr().Is4() || serverPrefix.Addr() == serverPrefix.Masked().Addr() {
		return validatedRequest{}, errors.New("server tunnel address must be an IPv4 CIDR such as 10.66.0.1/24")
	}
	peerAddress, err := netip.ParseAddr(strings.TrimSpace(request.PeerAddress))
	if err != nil || !peerAddress.Is4() || !serverPrefix.Contains(peerAddress) || peerAddress == serverPrefix.Addr() {
		return validatedRequest{}, errors.New("home peer tunnel address must be a different IPv4 address inside the server tunnel subnet")
	}
	homeLAN, err := netip.ParsePrefix(strings.TrimSpace(request.HomeLAN))
	if err != nil || !homeLAN.Addr().Is4() {
		return validatedRequest{}, errors.New("home LAN must be an IPv4 CIDR such as 192.168.0.0/24")
	}
	if !validKey(strings.TrimSpace(request.PeerPublicKey)) {
		return validatedRequest{}, errors.New("home peer public key must be a valid WireGuard key")
	}
	if request.ListenPort == 0 {
		request.ListenPort = 51820
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(request.PublicEndpoint)); err != nil {
		return validatedRequest{}, errors.New("VPS public endpoint must include a host and port, such as vpn.example.net:51820")
	}
	host, portString, _ := net.SplitHostPort(strings.TrimSpace(request.PublicEndpoint))
	if _, err := netip.ParseAddr(host); err != nil && !hostnamePattern.MatchString(host) {
		return validatedRequest{}, errors.New("VPS endpoint must use an IPv4/IPv6 address or a valid DNS hostname")
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil || port == 0 {
		return validatedRequest{}, errors.New("VPS endpoint port must be between 1 and 65535")
	}
	return validatedRequest{
		InterfaceName: request.InterfaceName, ServerAddress: serverPrefix.String(), PeerAddress: peerAddress.String(),
		HomeLAN: homeLAN.Masked().String(), PeerPublicKey: strings.TrimSpace(request.PeerPublicKey),
		PublicEndpoint: net.JoinHostPort(host, strconv.FormatUint(port, 10)), ListenPort: request.ListenPort,
	}, nil
}

func validKey(key string) bool {
	decoded, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(decoded) == 32
}

func writeNewConfig(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create WireGuard config directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing WireGuard config %s", path)
		}
		return fmt.Errorf("create WireGuard config: %w", err)
	}
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write WireGuard config: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync WireGuard config: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close WireGuard config: %w", err)
	}
	return nil
}
