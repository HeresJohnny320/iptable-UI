# IP Table UI - Port Forward Manager

A user-friendly web and terminal interface for managing iptables port forwarding rules with WireGuard integration.

## 📋 Overview

IP Table UI simplifies managing iptables port forwarding rules. It provides:

- **Web Interface**: Easy-to-use web UI for managing rules
- **Terminal Interface**: TUI (Terminal User Interface) for command-line users
- **WireGuard Integration**: Manage WireGuard interfaces and peers
- **Database Storage**: Persistent storage of your port forwarding rules
- **Automatic Reconciliation**: Syncs your saved rules with actual iptables rules

## 🚀 Quick Start

### Prerequisites

- Linux system (tested on Ubuntu/Debian)
- Root/sudo access (required for firewall operations)
- Go 1.21+ (for building from source)

### Installation

#### Option 1: Pre-built Binary (Recommended)

Download the latest release from [GitHub Releases](https://github.com/HeresJohnny320/iptable-ui/releases):

```bash
wget https://github.com/HeresJohnny320/iptable-ui/releases/download/v0.1.0/iptable-ui_linux_amd64.tar.gz
sudo tar -xzf iptable-ui_linux_amd64.tar.gz -C /usr/local/bin/
```

#### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/HeresJohnnyJohnny320/iptable-ui.git
cd iptable-ui

# Build the application
make build

# Install
sudo make install
```

## 🛠️ Usage

### Basic Commands

#### Start the Application

```bash
chmod +x ./iptable-ui
sudo ./iptable-ui
```

This will:
1. Start the web interface on `http://0.0.0.0:8787`
2. Launch the TUI interface
3. Display a temporary web token for authentication

#### List Existing Rules

```bash
sudo iptable-ui list
```

#### Reconcile Rules

```bash
sudo iptable-ui reconcile
```

This syncs your saved rules with the actual iptables configuration.

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

## 🔧 Configuration

### Database Location

The application uses SQLite for storage:

- **As root**: `/var/lib/iptable-ui/rules.db`
- **As regular user**: `~/.local/share/iptable-ui/rules.db`

You can specify a custom database path:

```bash
sudo iptable-ui -db /path/to/custom/rules.db
```

### WireGuard Setup

The application can help you set up WireGuard:

```bash
# Install WireGuard tools
sudo iptable-ui wireguard install

# Check WireGuard status
sudo iptable-ui wireguard status
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
   - Bind to localhost only: `sudo iptable-ui -web-address 127.0.0.1:8787`
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
sudo iptable-ui wireguard install
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