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

The web address and sign-in token are masked on screen (`http://203.•••.•••.•••:8787`,
`3f9a••••••••`), so screenshots and screen sharing do not give them away. They stay usable:

- **Click** the masked address (Ctrl+click in most terminals) to open the web UI already signed
  in, in terminals that support links (Windows Terminal, iTerm2, GNOME Terminal, kitty, WezTerm).
- Press **`C`** in the TUI to copy the full sign-in link to your computer's clipboard (OSC 52; also
  works over SSH and inside tmux).
- Press **`V`** to show the real address and token, for terminals without links or clipboard
  support such as PuTTY, then **`V`** again to hide them. In whiptail mode, choose **Show web UI
  sign-in link**.

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

The help bar lists the everyday keys. Press `Enter` on a rule for its actions (edit, on/off, real
client IP, remove), and `M` for a menu with everything else. Every letter below also works
directly from the rule list.

| Key | Action |
| --- | --- |
| `Enter` | Actions for the selected rule |
| `M` | More actions menu |
| `/` | Search: filter rules as you type (`Enter` keeps the filter, `Esc` clears it) |
| `A` / `E` | Add / edit a rule |
| `T` | Enable or disable the selected rule |
| `I` | Toggle passing the real client IP for the selected rule (off by default; asks before turning on) |
| `D` | Remove the selected rule (asks first) |
| `R` | Re-apply rules: rebuild the firewall from your saved rules (only needed if another tool wiped them) |
| `F` | Toggle IPv4 packet forwarding (asks before turning it off) |
| `B` | Apply rules on boot: re-apply your saved rules automatically after a reboot |
| `S` | Backups: back up now (`N`), download (`D`), restore (`Enter`), import a file (`I`), change folder (`O`) |
| `L` | Live firewall rules (`iptables -t nat -L IPTUI_DNAT -n -v --line-numbers`) |
| `P` | Change the web UI port (saved for next time) |
| `C` | Copy the web UI sign-in link to your clipboard |
| `V` | Show or hide the web UI address and token (masked by default) |
| `O` | Switch the TUI look (saved for next time) |
| `N` | Switch between the detailed and the simple view (saved for next time) |
| `X` | Remove all rules (type `REMOVE ALL` to confirm; a backup is taken first) |
| `G` | WireGuard setup |
| `W` | Start or stop the web UI |
| `U` | Switch to the whiptail look (classic blue menus; needs the whiptail package) |
| `?` | Help: explains every key |
| `Q` | Quit |

### Whiptail Mode

Prefer classic blue menus like `raspi-config`? Start with `--whiptail`, or press `U` in the TUI.
Whiptail mode can list, add, edit, toggle and remove rules, and toggle forwarding, apply-on-boot and
the web UI. Choose "Switch to the full TUI" to go back; the full TUI also has the options whiptail
mode does not (backups, live firewall rules, web port, remove all, search and WireGuard setup).

```bash
sudo apt install whiptail      # Debian/Ubuntu (Fedora: sudo dnf install newt)
iptable-ui --whiptail
```

The web UI shows the same gateway status with switches for forwarding and apply-on-boot.

### Themes

Pick a theme from the **Theme** menu in the web UI header: System (follows your device's light or
dark mode), Light, Dark, Ocean, Midnight, Sunset, High contrast, Nord, Dracula, Solarized, Gruvbox
or Rose. The choice is saved in
iptable-ui's database, so every browser you sign in from uses it.

The TUI has its own look: press `O` (or pick **TUI look** in the `M` menu) to switch between
Classic, Readable (bright, high contrast), Light terminal (for white backgrounds), Ocean and Plain
(no colors, for monochrome terminals and screen readers). It is saved in the database too.

Press `N` (or pick **Simple view** in the `M` menu) for a cleaner, plain-language view: the header
reads "Forwarding is on.", "Connected through Tailscale (this server is 100.64.0.1 on it).",
"After a reboot: your rules come back automatically.", and each rule reads like
`On   Minecraft   port 25565 → 10.66.0.2:25565   TCP+UDP` (the port this server listens on, then
where it forwards to). Press `N` again for the detailed view with
interface names, codes and columns. The choice is saved in the database.

### Traffic and VPN

- **Speeds:** the TUI header and the web UI show how fast each network adapter is receiving (RX)
  and sending (TX). Each forward shows its own speed: ▼ toward your server, ▲ back to visitors
  (on wide TUI screens, in a rule's `Enter` menu, and on each rule in the web UI). Speeds come from
  counters the kernel already keeps and are measured every 2 seconds.
- **VPN:** iptable-ui names the VPN it forwards through (WireGuard, Tailscale, NetBird, ZeroTier,
  Nebula, OpenVPN) and shows this server's address on it. The web UI header follows it
  ("TAILSCALE GATEWAY"), and WireGuard setup is hidden while another VPN is in use.
- **Importing:** when another script made a TCP rule and a UDP rule for the same port and
  destination, iptable-ui combines them into one TCP+UDP rule, including pairs imported earlier.

### Backups

iptable-ui backs up its database (all rules and settings such as the theme) to
`~/iptable-ui-backups` of the user who ran `sudo` (for example `/home/ubuntu/iptable-ui-backups`,
or `/root/iptable-ui-backups` when logged in as root). The files belong to that user, so you can
download them with WinSCP, FileZilla or `scp` without root. The folder is shown on startup, in the
web UI's Backups section and on the TUI backups screen. Change it under **Settings → Backup folder**
or with `O` on the TUI backups screen; existing backups move with it. Backups are taken:

- when it starts,
- every 5 minutes while it runs, but only when something changed,
- whenever you press **Back up now** (web UI, Backups section) or `N` on the backups screen
  (`S` in the TUI).

**Download** saves a backup to your computer: in the web UI, click **Download** next to a backup.
In the TUI, press `D` on a backup to get a link (`http://<server>:<port>/download/...`) that works
for 10 minutes without signing in, for a browser or `curl -O`. The web UI must be on (`W`). The
TUI also prints an `scp` command for copying the file directly.

**Upload** a backup file (for example one you downloaded earlier) with **Upload backup…** in the
web UI. On the TUI backups screen, press `I` to import a file that is already on the server (copy it
there with `scp` first). Only real iptable-ui databases with valid rules are accepted; the upload is
added to the list, and the web UI offers to restore it right away.

**Restore** replaces every rule and setting with the backup and applies the rules to the firewall
right away. The current state is backed up first (shown as "before a restore"), so you can undo a
restore by restoring that backup. The newest 100 automatic backups and 20 before-restore backups
are kept; manual backups are never deleted automatically. Host settings that live outside the
database (IPv4 forwarding, apply on boot, WireGuard configs) are not part of a backup.

### Live Firewall Rules

To see the port forwards exactly as the firewall has them, with packet and byte counters, click
**Live rules** in the web UI or press `L` in the TUI (also in the `M` menu). It runs:

```bash
sudo iptables -t nat -L IPTUI_DNAT -n -v --line-numbers
```

### Web UI Port

The web UI listens on port 8787 by default. Change it under **Settings** in the web UI, or press
`P` in the TUI. The new port is saved in the database and used every time iptable-ui starts; a
running web UI moves to it immediately and the browser page follows. Allow the new port in your
firewall and at your VPS provider. Passing `--web-address` on the command line overrides the saved
port for that run.

### Removing All Rules

**Remove all rules** (web UI **Settings**, or `X` in the TUI) deletes every forwarding rule from the
database and the firewall at once. You must type `REMOVE ALL` to confirm, and a backup is taken
first (listed as "before removing all"), so you can undo it by restoring that backup.

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