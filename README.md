# Packet Sniffer

A raw-socket TCP/UDP packet sniffer (`packet_sniffer.c`) with a small desktop front-end.

> Capture traffic only on networks and devices you own or have explicit permission
> to monitor. See [Legal and privacy](#legal-and-privacy).

## Install

```bash
./install.sh
```

This builds the sniffer, installs a **Packet Sniffer** shortcut on the desktop and in
the application menu, and grants the binary `cap_net_raw` so captures do not need a
password every time (one authentication prompt during install).

To drop the bundled icon and use a stock system one instead:

```bash
./install.sh --no-icon
```

That removes the installed icon files; deleting `packet-sniffer.svg` from this folder
makes the change permanent.

## Files

| File | Purpose |
| --- | --- |
| `packet_sniffer.c` | The sniffer itself: raw `AF_PACKET` socket, filters, log writer |
| `sniffer_gui.py` | Tk desktop interface: filter form, start/stop, live output |
| `run.sh` | Launcher used by the shortcut; rebuilds the binary if the C file changed |
| `install.sh` | Build + install the desktop entry + grant capture permission |
| `Makefile` | `make`, `make setcap`, `make clean` |
| `packet-sniffer.svg` | The app icon (a magnifier over a stream of captured bytes) |

## Using the app

Fill in any filters you want (empty means "match anything"), pick a protocol, and
press **Start capture**. Decoded packets stream into the output pane as they arrive,
and are written to `~/.local/share/packet-sniffer/logs/capture-<timestamp>.log`.

The filter fields map onto the sniffer's own options:

| Field | Option |
| --- | --- |
| Source / Destination IP | `--sip` / `--dip` |
| Source / Destination port | `--sport` / `--dport` |
| Source / Destination interface | `--sif` / `--dif` (matches the interface's MAC address) |
| Protocol | `--tcp` / `--udp` |

## Running without the GUI

```bash
./sniffer --tcp --dport 443 --logfile mycapture.log
./sniffer --help
```

Needs `cap_net_raw` (see `make setcap`) or `sudo`. Everything except the capture
itself works unprivileged, so `--help` and argument errors are reported without it.

Filters are validated up front: a malformed address or an out-of-range port is
rejected with a message rather than silently matching nothing.

## Security notes

- **The binary carries `cap_net_raw`.** File capabilities apply to whoever runs the
  binary, not just to you, so anyone with execute access on this machine could
  capture traffic with it. `install.sh` sets it to mode `750` for that reason.
  Do not relax those permissions or install it into a shared multi-user path.
- **Logs contain raw payloads** - plaintext HTTP, DNS queries, cookies, credentials.
  They are created mode `600` under `~/.local/share/packet-sniffer/logs/`. Treat them
  as sensitive, and do not commit one to a repository.
- **`--logfile` refuses to follow a symlink**, so a planted link cannot redirect
  the log over another file when the sniffer is run under `sudo`.
- **Logs are not rotated or size-capped.** A long capture on a busy link writes
  hundreds of MB; watch your free disk space.
- **The parser reads untrusted input.** Frames are bounds-checked before the
  Ethernet, IP, TCP and UDP headers are dereferenced, and the build enables the
  stack protector, fortified libc calls, full RELRO and PIE.
- The sniffer keeps `cap_net_raw` for its whole run rather than dropping it after
  the socket is open. That capability is not root, and the open raw socket already
  grants the same access, so dropping it would add little here.

## Legal and privacy

Not legal advice, but the parts worth knowing before you use or publish this:

- **Intercepting communications you are not a party to, without consent, is a crime
  in most jurisdictions.** This is the case even on a network you connect to
  legitimately, such as an office, campus or cafe network. Relevant law includes
  the US Wiretap Act (18 U.S.C. § 2511), the EU ePrivacy Directive together with
  the GDPR, and in Turkey arts. 132-137 of the Turkish Penal Code plus KVKK
  no. 6698.
- **Captured payloads are personal data** under the GDPR and KVKK. Storing the logs
  makes you a data controller, with the retention and disclosure duties that follow.
- **Safe uses:** your own machine and its traffic, a lab or home network you own, a
  network you have written authorisation to test, and CTF or coursework
  environments.
- **Publishing the tool is fine.** A packet sniffer is standard network diagnostic
  software of the same class as `tcpdump` and Wireshark, and GitHub's Acceptable
  Use Policies permit security research tooling. It is use, not publication, that
  carries the legal risk.
- **This repository has no LICENSE file.** Without one, default copyright applies
  and nobody may legally use, copy or modify the code, which is probably not what
  you want on a public repo.

## Disclaimer

Provided as is, without warranty of any kind. You are responsible for ensuring that
your use of this software complies with the laws that apply to you.
