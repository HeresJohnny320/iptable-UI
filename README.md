# iptable-ui

iptable-ui forwards ports from a cheap VPS to a machine at home, through a VPN tunnel. People
connect to your VPS, and the traffic ends up at your home server. Your home IP stays hidden and you
never have to open ports on your home router.

```
  players / visitors  ──>  your VPS (iptable-ui)  ══ VPN tunnel ══>  your server at home
       internet               public IP                              Minecraft, a website, ...
```

You can do all of this with a few `iptables` commands, and plenty of people keep a shell script
around for it. That works until you need to change something, forget which rule does what, reboot
and lose everything, or try to remove a rule by line number. iptable-ui keeps your forwards in a
small database and gives you two ways to manage them: a terminal UI for SSH, and a web page for the
browser.

## What you get

- Add, edit, switch off and remove forwards without touching `iptables` yourself.
- A terminal UI that works over plain SSH (PuTTY included) and a web UI you can open from your
  phone.
- Works with WireGuard, Tailscale, NetBird, ZeroTier, Nebula and OpenVPN. It finds the VPN on its
  own.
- A setup wizard that installs a VPN for you if the server doesn't have one yet, on Ubuntu, Debian,
  Fedora, RHEL, Arch, openSUSE and Alpine.
- Your forwards come back after a reboot, if you want them to.
- Automatic backups of your rules, with restore, download and upload.
- Live speeds per adapter and per forward, and the raw firewall view when you want to double
  check.
- If you already have forwards made by another script, it imports them instead of fighting them.

## What you need

- A Linux VPS with a public IP (amd64 or arm64).
- Root access, or a user that can use `sudo`.
- A VPN between the VPS and your home server, or let the setup wizard install one.

## Install

The quickest way:

```bash
curl -fsSL https://raw.githubusercontent.com/HeresJohnny320/iptable-UI/main/install.sh | sh
```

It downloads the newest release for your CPU and puts it at `/usr/local/bin/iptable-ui`. It only
asks for `sudo` for that last copy step.

Prefer to do it by hand? Grab the `.tar.gz` for your CPU from the
[releases page](https://github.com/HeresJohnny320/iptable-UI/releases):

```bash
tar -xzf iptable-ui-linux-amd64.tar.gz
./iptable-ui-linux-amd64 install
```

If you downloaded the plain binary instead of the `.tar.gz`, Linux won't run it until it's marked
executable. That's how downloads work, not something iptable-ui can fix from the inside. Run
`chmod +x iptable-ui-linux-amd64` once, then `./iptable-ui-linux-amd64 install`.

## First run

```bash
iptable-ui
```

You don't need to type `sudo`. iptable-ui changes the firewall, so when it needs root it re-runs
itself with `sudo` (or `doas`) and asks for your password.

The very first time, before it touches anything, it explains what it's about to do to your
firewall and lists any port forwards it found from other scripts. Those get taken over, which
means older scripts may stop working (more on that further down). Answer `n` and nothing is
changed. Later on it only asks again if it finds new forwards from another tool.

On startup it:

- works out which adapter faces the internet and which one is your VPN, and prints both,
- backs up its database,
- picks up any port forwards that already exist on the server,
- starts the web UI on port 8787 and prints a sign-in link,
- opens the terminal UI.

If it can't find any VPN, it offers to run the setup wizard. You can also start the wizard
yourself at any time:

```bash
iptable-ui setup
```

The wizard asks before it installs or changes anything. It detects your distro, lets you choose
WireGuard, Tailscale or NetBird, installs what's missing, and gets the tunnel up:

- WireGuard: it makes the keys for both ends, writes the VPS config, and saves a finished config
  for your home machine (usually `/root/wg0-home-peer.conf`; the wizard prints the exact path and
  the `scp` command to fetch it). Copy that file home as `/etc/wireguard/wg0.conf`, run
  `sudo wg-quick up wg0` there, and you're connected. Delete the file from the VPS afterwards, since
  it contains your home machine's private key.
- Tailscale and NetBird: it runs their official installer and signs you in, either with a browser
  link or with a key you paste.

It also turns on IP forwarding and "apply on boot" for you. Don't want the wizard question at
startup? Pass `--no-wizard`.

## Your first forward

Say you run a Minecraft server at home, and your home machine is `10.66.0.2` on the VPN.

1. Press `A` in the terminal UI, or use the form on the right of the web UI.
2. Label: `Minecraft`. Public port: `25565`. Destination: `10.66.0.2`. Leave the destination port
   empty to reuse 25565. Protocol: TCP+UDP.
3. Save. It's live right away.

Players now connect to `your-vps-ip:25565`. Use your home server's VPN address as the destination,
not its home network address like `192.168.1.x`. With Tailscale or NetBird that's the `100.x.x.x`
address, which `tailscale ip -4` or `netbird status` will show you on the home machine.

## The terminal UI

The bar at the bottom only shows the keys you'll use most. Everything else is one step away:

- `Enter` on a rule opens its actions: edit, on/off, real client IP, remove.
- `M` opens a menu with the rest.
- `?` explains every key.

| Key | What it does |
| --- | --- |
| `↑` `↓` | Pick a rule |
| `Enter` | Actions for the picked rule |
| `/` | Search (try `25565`, `minecraft`, `off`, `udp off`) |
| `A` / `E` | Add / edit a rule |
| `T` | Switch the rule on or off |
| `D` | Remove the rule (asks first) |
| `W` | Start or stop the web UI |
| `M` | More actions |
| `?` | Help |
| `Q` | Quit (your forwards keep working) |

These work too, and they're all in the `M` menu:

| Key | What it does |
| --- | --- |
| `I` | Show visitors' real IPs to your server for this rule (see further down) |
| `R` | Re-apply your rules to the firewall |
| `F` | IP forwarding on/off |
| `B` | Apply rules on boot on/off |
| `S` | Backups |
| `L` | Live firewall rules |
| `P` | Change the web UI port |
| `C` | Copy the web UI sign-in link |
| `V` | Show the web address and sign-in token (hidden on screen by default) |
| `N` | Simple or detailed view |
| `O` | Change the colors |
| `X` | Remove every rule (you have to type `REMOVE ALL`) |
| `G` | WireGuard setup |
| `U` | Classic whiptail menus |

### Simple view and colors

Press `N` if you'd rather read sentences than codes. The header turns into something like
"Forwarding is on. Connected through Tailscale (this server is 100.64.0.1 on it).", and each rule
reads `On   Minecraft   port 25565 → 10.66.0.2:25565   TCP+UDP`. Press `N` again to go back.

`O` cycles through a few color sets: Classic, Readable (bright and high contrast), Light terminal
(for white backgrounds), Ocean, and Plain (no colors at all, good for screen readers). Both choices
are saved, so the TUI opens the way you left it.

If colors don't show up in PuTTY, set Connection → Data → Terminal-type string to
`xterm-256color`. Newer versions of iptable-ui handle this on their own.

### Whiptail mode

If you like the blue menus from `raspi-config`, install whiptail
(`apt install whiptail`, or `dnf install newt` on Fedora) and press `U`, or start with
`iptable-ui --whiptail`. It covers the basics: rules, forwarding, apply on boot and the web UI. For
backups, search, live rules and WireGuard setup, pick "Switch to the full TUI".

## The web UI

The terminal prints a sign-in link when iptable-ui starts. Click it, or press `C` in the TUI to
copy it, and the page opens already signed in. The address and token are partly hidden on screen,
like `http://203.•••.•••.•••:8787`, so a screenshot doesn't give them away. Press `V` to show them in
full, which is handy in PuTTY since it can't open links. The token changes every time iptable-ui
starts.

In the browser you can do everything the TUI does. It also has:

- a theme menu at the top (twelve themes, saved for every browser you use),
- a search box (press `/` to jump to it),
- live speeds on each rule,
- Backups, Live firewall rules and Settings at the bottom of the page.

The web UI runs on port 8787. You can change that under Settings or with `P` in the TUI. The page
follows you to the new port. Remember to allow the new port in your firewall and in your VPS
provider's panel.

**Please don't leave it wide open.** It's plain HTTP. Either bind it to localhost with
`--web-address 127.0.0.1:8787` and reach it over an SSH tunnel
(`ssh -L 8787:127.0.0.1:8787 you@your-vps`), or put it behind a reverse proxy with HTTPS, or at the
very least only allow your own IP to reach that port.

## Making sure it survives a reboot

Two settings matter here. Both show at the top of the TUI and the web UI.

- **IP forwarding** has to be on, or no forward will pass any traffic. iptable-ui saves the setting
  in `/etc/sysctl.d/99-iptable-ui-forward.conf`, so it survives reboots. If some other config file
  would switch it off again at boot, iptable-ui tells you which file.
- **Apply rules on boot.** Firewall rules only live in memory, so a reboot wipes them. Turn this on
  (`B`) and a small systemd service puts your rules back every time the server starts.

You'll also see **Re-apply rules** (`R`, or `iptable-ui reconcile` on the command line). Normally
you never need it, because every change is applied as you make it. It's for when something else
wiped the firewall: another script, a ufw reload, Docker restarting, or an `iptables -F`.

## Backups

iptable-ui backs up its database:

- when it starts,
- every 5 minutes while it's running, if something changed,
- whenever you press "Back up now".

It also takes one before a restore and before "remove all rules", so both can be undone.

Backups land in `~/iptable-ui-backups` of the user who ran `sudo`, for example
`/home/ubuntu/iptable-ui-backups`. The files belong to that user, so you can grab them with
WinSCP, FileZilla or `scp` without needing root. You can move the folder in Settings, or with `O`
on the TUI backup screen.

From the web UI you can download any backup, upload one (say, from your old server), and restore.
In the TUI (`S`):

- `N` makes a backup,
- `Enter` restores one,
- `D` gives you a download link that works for 10 minutes,
- `I` imports a backup file that's already on the server.

A restore replaces all your rules and settings and applies them straight away. The newest 100
automatic backups are kept; the ones you make by hand stay until you delete them. IP forwarding,
apply on boot and your WireGuard config live outside the database, so they're not part of a
backup.

## Seeing what's happening

- **Speeds.** The TUI header and the web UI show how fast each adapter is receiving (RX) and
  sending (TX). Each forward has its own speed too: ▼ is traffic going to your server, ▲ is traffic
  going back to visitors. In the TUI you'll see it on wide screens and in a rule's `Enter` menu.
- **Live firewall rules** (`L`, or the button in the web UI) shows the forwards exactly as the
  kernel has them, with packet counters. It's the same as running
  `sudo iptables -t nat -L IPTUI_DNAT -n -v --line-numbers`, just easier to read. If the counters
  go up when someone connects, traffic is reaching your VPS.
- **Search** works in both UIs. Type part of a name, port or IP, or a keyword: `on`, `off`, `tcp`,
  `udp`, `real`, `masked`. Words combine, so `udp off` finds switched-off rules that carry UDP.

## Showing visitors' real IPs

By default your home server sees every connection as coming from the VPS. That's the setup that
just works. If you need the real addresses, for example for bans on a game server or for
meaningful logs, switch on "real client IP" for that rule: `I` in the TUI, or the "Use real IP"
button in the web UI. It's off by default for a reason. Your home machine then has to send its
replies back through the tunnel, or the forward stops working.

This works when the destination is the WireGuard peer itself. On the home machine, change
`/etc/wireguard/wg0.conf` like this:

```ini
[Interface]
Address = 10.66.0.2/24
PrivateKey = <HOME_PRIVATE_KEY>
# Don't send all traffic through the VPS, only the replies.
Table = off
PostUp = ip route add default dev wg0 table 51820; ip rule add from 10.66.0.2 table 51820 priority 100
PostDown = ip rule del from 10.66.0.2 table 51820 priority 100; ip route flush table 51820

[Peer]
PublicKey = <VPS_PUBLIC_KEY>
Endpoint = <VPS_PUBLIC_IP>:51820
# Replies can go to any visitor address.
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Then run `sudo wg-quick down wg0 && sudo wg-quick up wg0`. Only replies from `10.66.0.2` use the
tunnel. The rest of the home machine's internet stays as it was.

It won't work for a machine elsewhere on your home network, since that one replies through your
router, or with Tailscale, unless you set up exit nodes. Leave those rules on the default.

## Coming from another script

If you've been forwarding ports with a script (yours or someone else's), you don't have to clean
up first. On startup iptable-ui reads the firewall, imports forwards it recognizes, rebuilds them
in its own rules and removes the old copies, so nothing runs twice. A TCP rule and a UDP rule for
the same port and destination become one TCP+UDP rule. Rules it doesn't recognize, like ones with
extra conditions or comments, are left alone.

You'll see the list of forwards it's about to take over before anything happens, and you can say
no. If you say yes, stop using the old script on that server afterwards. The script can't see
iptable-ui's rules, and removing rules by line number will hit the wrong ones.

Changed your mind? A copy of the full firewall is saved before every change in
`/var/lib/iptable-ui/backups/`. Put one back with `sudo iptables-restore < <file>`.

## Commands and options

| Command | What it does |
| --- | --- |
| `iptable-ui` | Start the terminal UI and the web UI |
| `iptable-ui setup` | Run the setup wizard, then start |
| `iptable-ui list` | Print your rules (doesn't need root) |
| `iptable-ui reconcile` | Re-apply your saved rules to the firewall |
| `iptable-ui install` | Copy this binary to `/usr/local/bin/iptable-ui` |
| `iptable-ui wireguard status` | Check WireGuard and IP forwarding |
| `iptable-ui wireguard install` | Install the WireGuard tools |
| `iptable-ui wireguard guide` | Step-by-step WireGuard setup by hand |

| Option | What it does |
| --- | --- |
| `--public-if ens3` | Set the internet-facing adapter instead of detecting it |
| `--wg-if tailscale0` | Set the VPN adapter instead of detecting it |
| `--web-address 127.0.0.1:8787` | Where the web UI listens (overrides the saved port) |
| `--no-web` | Don't start the web UI |
| `--whiptail` | Start in whiptail mode |
| `--no-wizard` | Don't offer the setup wizard |
| `--db /path/rules.db` | Use another database (default `/var/lib/iptable-ui/rules.db`) |

The adapter detection is usually right. It looks at your default route for the internet side, and
at where your rules actually route to for the VPN side. If it guesses wrong, say on a VPS with two
network cards, set it with `--public-if` or `--wg-if`.

## When something doesn't work

**A forward doesn't connect.** Go through these in order:

1. Is IP forwarding on? It's at the top of both UIs.
2. Is the VPN up? Look for `UP` next to your VPN adapter. Can the VPS reach the home machine? Try
   `ping 10.66.0.2` from the VPS.
3. Does your VPS provider have its own firewall in their panel? Open the public port there too.
4. Is the service at home actually listening, and does the home machine's firewall allow
   connections from the VPN?
5. Open Live firewall rules and connect from outside. If the packet counter doesn't move, the
   traffic never reached the VPS. If it does move, the problem is on the home side.

**I switched a rule off but the port still works.** Already-open connections are cut off as soon
as you switch a rule off. If new connections still get through, another script is probably
forwarding the same port. iptable-ui warns you about that. Restart iptable-ui and it takes that
rule over.

**My forwards are gone after a reboot.** Turn on apply on boot (`B`).

**The web UI won't load.** Check the port is allowed in your firewall and at your VPS provider,
and that the web UI is on (`W`). If you see `<this-server-ip>` in the link, put in your VPS's
public IP yourself.

**Removing or editing a rule doesn't cut open connections right away.** Install `conntrack`
(`apt install conntrack`) and iptable-ui will close them immediately. Without it they end once
they go idle.

## How it works

iptable-ui keeps its rules in its own chains (`IPTUI_DNAT`, `IPTUI_FWD`, `IPTUI_SNAT`,
`IPTUI_MSS`) and hooks them in at the top of the built-in ones. Every change rebuilds those chains
in a single `iptables-restore` call. That means a change is never half applied, it's quick even with
lots of rules, and rules from Docker, ufw or anything else are never touched.

For each forward it:

- redirects the public port to your server,
- allows that traffic through toward the tunnel and the replies back,
- rewrites the source address so replies return through the tunnel (unless you asked for real
  client IPs),
- clamps TCP packet sizes so big downloads don't stall on the tunnel's smaller MTU.

Switching a rule off also drops connections that were already open, so off really means off.

Rules and settings live in a SQLite database at `/var/lib/iptable-ui/rules.db`.

## Building from source

You'll need Go 1.23 or newer.

```bash
git clone https://github.com/HeresJohnny320/iptable-UI.git
cd iptable-UI
go test ./...
./build-linux.sh amd64   # or arm64; the binary ends up in dist/
```

## Contributing

Bug reports and pull requests are welcome. If something didn't work on your setup, open an issue
and mention your distro, which VPN you use, and what `iptable-ui list` shows.
