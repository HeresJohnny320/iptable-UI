# IP Table UI - Port Forward Manager

A user-friendly web and terminal interface for managing iptables port forwarding rules with WireGuard integration.

## 📋 Overview

IP Table UI simplifies managing iptables port forwarding rules. It provides:

- **Web Interface**: Easy-to-use web UI for managing rules
- **Terminal Interface**: TUI (Terminal User Interface) for command-line users
- **WireGuard Integration**: Manage WireGuard interfaces and peers
- **Database Storage**: Persistent storage of your port forwarding rules
- **Automatic Reconciliation**: Syncs your saved rules with actual iptables rules
- **Packet Forwarding Toggle**: Turn IPv4 forwarding on or off, saved across reboots
- **Apply Rules on Boot**: Optional systemd unit that re-applies your saved rules at startup
- **VPN Auto-Detection**: Finds WireGuard, Tailscale, OpenVPN, ZeroTier, Nebula and NetBird interfaces

## 🚀 Quick Start

### Prerequisites

- Linux system (tested on Ubuntu/Debian)
- Root/sudo access (required for firewall operations)
- Go 1.21+ (for building from source)

### Installation

#### One-line Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/HeresJohnny320/iptable-UI/main/install.sh | sh
```

This picks the right build for your CPU (amd64 or arm64), installs it as
`/usr/local/bin/iptable-ui` already executable, and asks for `sudo` only for that final copy.
No `chmod` needed.

#### Manual Download

From [GitHub Releases](https://github.com/HeresJohnny320/iptable-UI/releases), the `.tar.gz`
downloads keep the executable bit:

```bash
tar -xzf iptable-ui-linux-amd64.tar.gz
./iptable-ui-linux-amd64 install     # copies it to /usr/local/bin/iptable-ui
```

A raw `iptable-ui-linux-amd64` download loses the executable bit, as every browser, `wget` and
`curl` download does, and Linux will not start a file without it. Run
`chmod +x iptable-ui-linux-amd64` once, then `./iptable-ui-linux-amd64 install`.


### Setup Wizard

New server with no VPN yet? iptable-ui offers a setup wizard on first start when it finds no
WireGuard, Tailscale, NetBird or other tunnel. Run it any time with:

```bash
iptable-ui setup
```

It asks before every change, and:

1. Detects your distribution and package manager: Ubuntu/Debian (`apt`), Fedora/RHEL (`dnf`,
   `yum`), Arch (`pacman`), openSUSE (`zypper`) and Alpine (`apk`).
2. Lets you pick **WireGuard**, **Tailscale**, **NetBird**, or skip.
3. Installs what is missing: the VPN, `iptables`, `conntrack` (recommended) and `whiptail`
   (optional), using each distro's package names.
4. Sets up the VPN:
   - **WireGuard**: generates keys for both ends, writes `/etc/wireguard/wg0.conf`, saves a
     ready-to-use home config (`~/wg0-home-peer.conf`, readable only by root), opens the port in
     ufw or firewalld when active, and starts the tunnel on boot.
   - **Tailscale / NetBird**: runs the official installer, then signs in with a browser link or an
     auth/setup key you paste.
5. Turns on IPv4 forwarding and apply-on-boot, then opens the TUI.

Pass `--no-wizard` to stop the first-start question.

## 🛠️ Usage

### Basic Commands

#### Start the Application

```bash
iptable-ui
```

No need to type `sudo`: when iptable-ui needs root, it re-runs itself with `sudo` (or `doas`) and
asks for your password. Read-only commands such as `iptable-ui list` run as your user.

This will:
1. Start the web interface on `http://0.0.0.0:8787`
2. Launch the TUI interface
3. Display a temporary web token for authentication

#### List Existing Rules

```bash
iptable-ui list
```

#### Re-apply Rules

```bash
iptable-ui reconcile
```

Rebuilds the firewall from your saved rules, the same as `R` in the TUI. This is also what
"apply rules on boot" runs at startup.

### Web Interface

After starting the application:
1. Open your browser to `http://localhost:8787`
2. Enter the temporary web token displayed in the terminal
3. Use the web interface to:
   - Add new port forwarding rules
   - Edit existing rules
   - Enable/disable rules
   - Delete rules

### Terminal Interface (TUI)

The TUI provides:
- Real-time rule list
- Quick enable/disable toggle
- Edit rules
- Delete rules
- WireGuard interface management
- Gateway status: IPv4 forwarding, VPN link and apply-on-boot
- A help screen (`?`) explaining every key

| Key | Action |
| --- | --- |
| `/` | Search: filter rules as you type (`Enter` keeps the filter, `Esc` clears it) |
| `A` / `E` | Add / edit a rule |
| `T` | Enable or disable the selected rule |
| `I` | Toggle passing the real client IP for the selected rule (off by default; asks before turning on) |
| `D` | Remove the selected rule (asks first) |
| `R` | Re-apply rules: rebuild the firewall from your saved rules (only needed if another tool wiped them) |
| `F` | Toggle IPv4 packet forwarding (asks before turning it off) |
| `B` | Apply rules on boot: re-apply your saved rules automatically after a reboot |
| `G` | WireGuard setup |
| `W` | Start or stop the web UI |
| `U` | Switch to the whiptail look (classic blue menus; needs the whiptail package) |
| `?` | Help: explains every key |
| `Q` | Quit |

### Whiptail Mode

Prefer classic blue menus like `raspi-config`? Start with `--whiptail`, or press `U` in the TUI.
Whiptail mode can list, add, edit, toggle and remove rules, and toggle forwarding, apply-on-boot and
the web UI. Choose "Switch to the full TUI" to go back (WireGuard setup lives there).

```bash
sudo apt install whiptail      # Debian/Ubuntu (Fedora: sudo dnf install newt)
iptable-ui --whiptail
```

The web UI shows the same gateway status with switches for forwarding and apply-on-boot.

### Searching Rules

Both the TUI (`/`) and the web UI (the search box, or press `/`) filter rules as you type. Every
word must match:

- part of a name, port, destination address or `#ID`: `25565`, `10.66`, `minecraft`, `#3`
- or a keyword: `on`/`up`/`enabled`, `off`/`down`/`disabled`, `tcp`, `udp` (rules on "both"
  match either), `real`, `masked`

Words combine: `udp off` shows disabled rules that carry UDP.

**Re-apply rules** (`R` in the TUI, the button in the web UI, `iptable-ui reconcile` on the command
line) rebuilds the firewall from your saved rules. Every change already applies automatically, so
you only need it if something else wiped or changed the firewall: another script, a ufw or
firewalld reload, Docker restarting, or `iptables -F`.

### Gateway Settings

**IPv4 forwarding** must be on for any forward to pass traffic. Turning it on or off writes
`/etc/sysctl.d/99-iptable-ui-forward.conf`, applies the value immediately, and comments out a
conflicting `net.ipv4.ip_forward` line in `/etc/sysctl.conf`. If another sysctl file would still
undo the setting at boot, iptable-ui names that file so you can fix it.

**Apply rules on boot** exists because iptables keeps rules only in memory, so a reboot erases
them. Turning it on installs `/etc/systemd/system/iptable-ui-restore.service`, which runs
`iptable-ui reconcile` with the current database and interfaces once the network is up. iptables
keeps rules only in memory, so without it your forwards stay inactive after a reboot until
iptable-ui runs again. If the binary moves or the interfaces change, the unit is refreshed the next
time you start the app.

### How a Forward Works

For each rule, iptable-ui keeps its own chains (`IPTUI_*`) at the top of the built-in ones and
rebuilds them on every change with a single `iptables-restore` call. Changes apply in one step no
matter how many rules you have, are never half-applied, and never touch other tools' rules:

| Chain | Rule |
| --- | --- |
| `nat IPTUI_DNAT` | Traffic from the internet (`-i ens3`) to the public port is redirected to the target |
| `filter IPTUI_FWD` | The connection may go internet → tunnel (`-i ens3 -o wg0`), and replies tunnel → internet only. Works even when the `FORWARD` policy is `DROP` (Docker, ufw) |
| `nat IPTUI_SNAT` | `MASQUERADE` into the tunnel so replies come back (skipped for real-client-IP rules) |
| `mangle IPTUI_MSS` | TCP MSS clamping into the tunnel, so large transfers do not stall on the smaller tunnel MTU |

**Turning a rule off** stops traffic immediately, including connections that were already open: a
disabled rule leaves a `DROP` for connections that were redirected to its target. Deleting or
editing a rule closes its open connections with `conntrack` when installed
(`sudo apt install conntrack`); otherwise they end once idle. If another script also forwards the
same port, iptable-ui says so; restart iptable-ui to take that rule over.

### Keep the Real Client IP

By default the destination server sees every visitor as the VPS (masked). Turn on **real client
IP** for a rule when the server must see visitors' addresses, for example for game-server bans or
logs: press `I` in the TUI, click **Use real IP** in the web UI, or pick the rule in whiptail mode.
Turning it off again is instant and always safe. Replies then go straight to the visitor, so they must be routed back through the tunnel.

This works when the destination is the **WireGuard home peer itself** (its tunnel address, such as
`10.66.0.2`). On the home peer, edit `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.66.0.2/24
PrivateKey = <HOME_PRIVATE_KEY>
# Do not route all traffic through the VPS; only replies from the tunnel address.
Table = off
PostUp = ip route add default dev wg0 table 51820; ip rule add from 10.66.0.2 table 51820 priority 100
PostDown = ip rule del from 10.66.0.2 table 51820 priority 100; ip route flush table 51820

[Peer]
PublicKey = <VPS_PUBLIC_KEY>
Endpoint = <VPS_PUBLIC_IP>:51820
# Allow replies to any visitor address through the tunnel.
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Then `sudo wg-quick down wg0 && sudo wg-quick up wg0`. Only traffic *from* `10.66.0.2` (replies
to forwarded connections) uses the tunnel; the home peer's normal internet traffic is unchanged.

Limits: a server elsewhere on the home LAN (such as `192.168.1.50`) sends replies to its own
router, not the tunnel, so keep it masked. Tailscale does not accept replies to arbitrary internet
addresses without exit-node routing, so keep Tailscale rules masked too.

**Interface auto-detection** lets iptable-ui run on any setup without flags. An interface only
counts as active when it is up *and* has a link (an unplugged NIC or idle Wi-Fi is skipped).

- **Public interface** (`-public-if`): the active interface with the lowest-metric default route.
  VPN interfaces are never picked, so a Tailscale exit node or full-tunnel VPN does not fool it.
- **VPN interface** (`-wg-if`), in order of preference:
  1. The interface the system actually routes your saved forward destinations through. This also
     finds tunnels with custom names.
  2. An active tunnel with an IPv4 address (`wg*`, `tailscale*`, `tun*`, `tap*`, `zt*`,
     `nebula*`, `wt*`, `ppp*`, or any WireGuard device), preferring `wg0`, then WireGuard devices.
  3. A tunnel that exists but is down, then `wg0` as a last resort.

The chosen interfaces and the reason are printed at startup and shown in the TUI and web UI
(`ROUTE ens3 -> wg0 UP`). If a guess is wrong, set it explicitly:

```bash
iptable-ui -wg-if tailscale0
```

## 🔧 Configuration

### Database Location

The application uses SQLite for storage:

- **As root**: `/var/lib/iptable-ui/rules.db`
- **As regular user**: `~/.local/share/iptable-ui/rules.db`

You can specify a custom database path:

```bash
iptable-ui -db /path/to/custom/rules.db
```

### WireGuard Setup

The application can help you set up WireGuard:

```bash
# Install WireGuard tools
iptable-ui wireguard install

# Check WireGuard status
iptable-ui wireguard status
```

## 📝 Creating Port Forwarding Rules

### Web Interface Method

1. Click "Add Rule"
2. Fill in the form:
   - **Name**: Descriptive name for the rule
   - **Public Port**: The port exposed on your public interface
   - **Destination IP**: The internal IP to forward to
   - **Destination Port**: The port on the destination IP
   - **Protocol**: TCP or UDP
3. Click "Save"
4. Enable the rule with the toggle switch

### Terminal Method

Use the TUI interface to add and manage rules.

## 🔥 Important Notes

### Security Warnings

1. **Web Interface Security**: The web interface is served over plain HTTP by default. For production use:
   - Bind to localhost only: `iptable-ui -web-address 127.0.0.1:8787`
   - Use a reverse proxy with TLS
   - Restrict access with firewall rules

2. **Root Access**: Most operations require root access. Use sudo carefully.

3. **Firewall Rules**: The application manages iptables rules. Review the rules before applying changes.

### WireGuard Configuration

The application does NOT create WireGuard keys or peer configurations. You need to:
1. Generate keys manually
2. Create WireGuard configuration files
3. Set up proper routes and firewall rules

See the WireGuard guide within the TUI for detailed instructions.

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied

```
Error: open database: permission denied
```

Solution: Ensure the database directory exists and is writable:
```bash
sudo mkdir -p /var/lib/iptable-ui
sudo chown $USER:$USER /var/lib/iptable-ui
```

#### iptables Commands Fail

Make sure iptables is installed:
```bash
sudo apt-get install iptables
```

#### WireGuard Not Found

Install WireGuard tools:
```bash
iptable-ui wireguard install
```

## 📚 Additional Information

### Architecture

- **Frontend**: Web interface with real-time updates
- **Backend**: Go application with SQLite database
- **Firewall**: Uses iptables for port forwarding
- **WireGuard**: Integrates with wg-quick for interface management

### Database Schema

The SQLite database stores:
- Port forwarding rules
- Rule enable/disable state
- Creation and modification timestamps

### Rule Reconciliation

The application automatically:
1. Discovers existing iptables rules on startup
2. Imports them into the database
3. Syncs enabled rules to iptables
4. Removes legacy rules on reconcile

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For issues and questions, please open an issue on GitHub.

---