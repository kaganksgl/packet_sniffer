# Packet Sniffer

A raw-socket packet sniffer for Linux, written in C, with a small desktop app for
driving it. It captures TCP and UDP traffic, decodes the Ethernet, IP and transport
headers, hex-dumps the payload, and streams the result into a live view while
writing everything to a log file.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)
![Language: C](https://img.shields.io/badge/Language-C-orange.svg)

> **Capture only traffic you are authorised to monitor.** Intercepting other
> people's communications without consent is a criminal offence in most countries,
> including on networks you are otherwise entitled to use. See
> [Legal and privacy](#legal-and-privacy).

## Features

- Captures live traffic from a raw `AF_PACKET` socket, no libpcap dependency
- Decodes Ethernet, IPv4, TCP and UDP headers field by field, including TCP flags
- Hex-dumps packet payloads
- Filters by source and destination IP, source and destination port, protocol, and
  network interface, in any combination
- Desktop app with a filter form, live output pane, packet counter and log export
- Runs without root once the binary is granted `CAP_NET_RAW`, and falls back to a
  `pkexec` prompt if it is not
- Logs are written with `0600` permissions, since captured payloads are sensitive

## Requirements

- **Linux.** The capture uses `AF_PACKET` raw sockets, which are Linux specific.
- **gcc** and **make**
- **Python 3** with **Tkinter**, for the desktop app:
  - Fedora: `sudo dnf install python3-tkinter`
  - Debian/Ubuntu: `sudo apt install python3-tk`
  - Arch: `sudo pacman -S tk`
- **libcap** (`setcap`), optional, to capture without a password prompt each time
- **polkit** (`pkexec`), used as the fallback when the capability is not granted

## Install

```bash
git clone https://github.com/kaganksgl/packet_sniffer.git
cd packet_sniffer
./install.sh
```

`install.sh` builds the sniffer, installs a **Packet Sniffer** launcher on your
desktop and in the application menu, installs the app icon, and grants the binary
`CAP_NET_RAW` so that capturing does not ask for a password every time. Granting the
capability is the only step that authenticates, and it happens once.

To use a stock system icon instead of the bundled one:

```bash
./install.sh --no-icon
```

If you would rather not install anything, `make` builds the binary on its own and
`./run.sh` starts the desktop app from the source directory.

## Using the desktop app

Launch it from the desktop shortcut, from the application menu, or with `./run.sh`.

Fill in the filters you want and leave the rest empty, since an empty field matches
anything. Press **Start capture**. Packets appear in the output pane as they arrive
and the counter tracks how many matched.

Captures are written to `~/.local/share/packet-sniffer/logs/capture-<timestamp>.log`.
**Save log as…** exports a copy, and **Open log folder** opens the directory.

The filter fields map directly onto the command line options:

| Field | Option | Notes |
| --- | --- | --- |
| Source IP | `--sip` | IPv4, dotted notation |
| Destination IP | `--dip` | IPv4, dotted notation |
| Source port | `--sport` | 1-65535 |
| Destination port | `--dport` | 1-65535 |
| Source interface | `--sif` | Matches packets whose source MAC is that interface's |
| Destination interface | `--dif` | Matches packets whose destination MAC is that interface's |
| Protocol | `--tcp` / `--udp` | Leave on *Any* to capture both |

The interface filters compare MAC addresses rather than binding the socket, so the
sniffer still listens on every interface and drops what does not match.

## Using it from the command line

```bash
# every TCP packet heading for port 443
./sniffer --tcp --dport 443 --logfile mycapture.log

# UDP between two hosts
./sniffer --udp --sip 192.168.1.10 --dip 8.8.8.8

# everything, to the default sniffer_log.txt
./sniffer
```

```
usage: ./sniffer [options]
  --sip ADDR      only packets from this IPv4 address
  --dip ADDR      only packets to this IPv4 address
  --sport PORT    only packets from this port
  --dport PORT    only packets to this port
  --sif NAME      only packets whose source MAC is this interface's
  --dif NAME      only packets whose destination MAC is this interface's
  --tcp           only TCP packets
  --udp           only UDP packets
  --logfile PATH  where to write the capture (default sniffer_log.txt)
  --help          show this message
```

Filters are validated before the capture starts, so a malformed address or an
out-of-range port is reported rather than silently matching nothing. Everything
except the capture itself works unprivileged, which means `--help` and argument
errors work without any special permissions.

## Permissions

Capturing raw packets needs the `CAP_NET_RAW` capability. There are three ways to
get it, in descending order of preference:

1. **Grant it to the binary once** with `make setcap` (this is what `install.sh`
   does). The sniffer then runs as your normal user with no further prompts.
2. **Let the app ask.** Without the capability, the desktop app launches each
   capture through `pkexec`, which authenticates every time.
3. **Run it under `sudo`.** Works, but the whole program then runs as root.

## How it works

`packet_sniffer.c` opens an `AF_PACKET`/`SOCK_RAW` socket bound to `ETH_P_ALL`, so
the kernel hands it every frame the machine sees. Each frame is bounds-checked,
matched against the active filters, and, if it survives, decoded field by field into
the log file.

`sniffer_gui.py` is a Tk front-end. It builds the argument list from the form,
launches the binary as a child process, and tails the log file in a background
thread so the output pane updates as packets arrive.

| File | Purpose |
| --- | --- |
| `packet_sniffer.c` | The sniffer: raw socket, filtering, packet decoding, logging |
| `sniffer_gui.py` | Desktop interface: filter form, start/stop, live output |
| `run.sh` | Launcher used by the shortcut; rebuilds the binary if the source changed |
| `install.sh` | Build, install the launcher and icon, grant the capability |
| `Makefile` | `make`, `make setcap`, `make clean` |
| `packet-sniffer.svg` | Application icon |

The build enables the stack protector, fortified libc calls, full RELRO and PIE.

## Security notes

- **The binary carries `CAP_NET_RAW` after install.** File capabilities apply to
  anyone who runs the binary, not only to you, so `install.sh` sets it to mode `750`.
  Do not loosen that or install it into a shared multi-user path.
- **Capture logs contain raw payloads:** plaintext HTTP, DNS queries, cookies,
  credentials. They are created `0600` under `~/.local/share/packet-sniffer/logs/`.
  Treat them as sensitive and never commit one to a repository.
- **`--logfile` refuses to follow a symlink**, so a planted link cannot redirect the
  log over another file when the sniffer runs under `sudo`.
- **Logs are not rotated or size-capped.** A long capture on a busy link writes
  hundreds of megabytes; keep an eye on free space.
- The parser reads untrusted input, and frames are bounds-checked before any header
  is dereferenced. If you find a memory-safety problem, please open an issue.

## Legal and privacy

This is not legal advice, but it matters before you run this:

- **Intercepting communications you are not a party to, without consent, is a crime
  in most jurisdictions**, and that holds even on a network you are entitled to use,
  such as an office, campus or cafe network. Relevant law includes the US Wiretap Act
  (18 U.S.C. § 2511), the EU ePrivacy Directive together with the GDPR, and in Turkey
  arts. 132-137 of the Turkish Penal Code along with KVKK no. 6698.
- **Captured payloads are personal data** under the GDPR and KVKK. Keeping the logs
  makes you a data controller, with the duties that follow.
- **Reasonable uses:** your own machine and its traffic, a lab or home network you
  own, a network you have written authorisation to test, and CTF or coursework
  environments.

## Contributing

Issues and pull requests are welcome. The C source is a single file and the GUI is a
single Python module, so changes stay easy to review.

## License

Released under the [MIT License](LICENSE). Provided as is, without warranty of any
kind. You are responsible for ensuring that your use of this software complies with
the laws that apply to you.
