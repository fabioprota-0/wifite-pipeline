# wifite-pipeline

**Turn [wifite](https://github.com/kimocoder/wifite2) from a sequential script into a parallel pipeline: capture â†’ crack â†’ record â†’ connect.**

> âš ï¸ **AUTHORIZED USE ONLY.** This tool captures WPA handshakes, cracks passwords
> and joins networks. Doing any of that without **written authorization** is a
> crime in most jurisdictions â€” even if you fail to get in. Use it only on
> networks you own, on dedicated labs (TryHackMe, Hack The Box, VulnHub), or
> under a signed engagement contract. See [Authorized use](#authorized-use).

---

## Quick start (PortuguÃªs BR)

```bash
git clone https://github.com/fabioprota-0/wifite-pipeline.git
cd wifite-pipeline
sudo bash scripts/install.sh       # instala dependencias e o comando `wp`

wp doctor                          # confere adaptadores, wordlists e ferramentas
wp run --capture-interface wlan0 \
       --connect-interface wlan1 \
       --auto-connect \
       --i-have-authorization
```

Isso abre **4 painÃ©is** no tmux. Detalhes em [The four panes](#the-four-panes).

---

## The problem this solves

Wifite is excellent at capturing, but its flow is **sequential**: it captures a
handshake, stops attacking, tries to crack it against a wordlist, and only then
moves to the next target. On a 2-core laptop that means minutes â€” often hours â€”
where your adapter is doing nothing but waiting on a CPU-bound crack.

```
wifite today:   capture â”€â”€â–º crack â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º capture â”€â”€â–º crack â”€â”€â–º ...
                            (adapter idle)                          (adapter idle)

wifite-pipeline: capture â”€â”€â–º capture â”€â”€â–º capture â”€â”€â–º ...        (never stops)
                            â”‚           â”‚
                            â””â”€â–º crack â”€â”€â”´â”€â–º crack â”€â”€â–º ...        (in parallel)
```

`wifite-pipeline` wraps wifite instead of forking it. It runs wifite with
**`--skip-crack`** (a real wifite flag: *"skip cracking captured
handshakes/pmkid"*), watches the capture directory, and cracks each new capture
in a separate worker while wifite keeps attacking.

## The four panes

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ 1  wifite (capture)           â”‚ 2  cracker (cracking)         â”‚
â”‚    sudo wifite --skip-crack   â”‚    wp crack --loop            â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ 3  queue                      â”‚ 4  solved + import            â”‚
â”‚    wp queue --live            â”‚    wp results --live          â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

| Pane | Process | Job |
|---|---|---|
| 1 | `wifite --skip-crack` | Captures handshakes / PMKID and never blocks on cracking |
| 2 | `wp crack --loop` | Watches for new captures, cracks each one, records results |
| 3 | `wp queue --live` | What is pending, cracking, exhausted |
| 4 | `wp results --live` | Passwords found, plus how to import what you already know |

`wp run` builds this layout in one tmux session. Prefer separate windows? Use
`wp run --no-tmux` and it prints the four commands to paste.

## Requirements

| Requirement | Why |
|---|---|
| Kali Linux (or Debian-based) | Tested platform |
| **Adapter 1** â€” monitor mode + injection | Used by wifite for capture |
| **Adapter 2** â€” a *separate physical* adapter | Kept in managed mode, used only to join the cracked network |
| Python 3.9+ | Runtime â€” **no pip packages needed** |
| `wifite`, `aircrack-ng` | Capture and fallback cracking |
| `hashcat`, `hcxtools` | Preferred cracking engine and `.22000` conversion |
| `nmcli` (network-manager) | Joining the cracked network |

> **About the second adapter.** In a VM, both adapters must be USB and passed
> through to the guest (*Devices â†’ USB* in VirtualBox). A laptop's **internal**
> WiFi card is PCIe, not USB, so it normally **cannot** be passed through and
> **cannot** serve as the second adapter. `wp doctor` checks this and tells you.
>
> No second adapter? Everything still works except auto-connect. Just omit
> `--connect-interface` and use `wp connect` later.

## Install

```bash
git clone https://github.com/fabioprota-0/wifite-pipeline.git
cd wifite-pipeline
sudo bash scripts/install.sh
```

`install.sh` installs the system tools and puts `wp` on your `PATH`. Manual
route:

```bash
sudo apt update
sudo apt install -y wifite aircrack-ng hashcat hcxtools network-manager seclists
pipx install .          # or: pip install --user .
```

Nothing is installed system-wide by Python: the package is pure standard
library and has **zero dependencies**.

## Usage

### Check the environment first

```bash
wp doctor
```

Reports every external tool, every wireless adapter and its current mode,
whether the two adapter roles are valid, which wordlists exist and which
directories are being watched. Fix anything in red before attacking.

### Full pipeline

```bash
sudo wp run \
  --capture-interface wlan0 \
  --connect-interface wlan1 \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --auto-connect \
  --i-have-authorization
```

Extra arguments after the options are passed straight to wifite:

```bash
sudo wp run --capture-interface wlan0 -- --wpa --pmkid --no-wps -5
```

### Try it with no hardware at all

```bash
python3 scripts/demo.py
```

Runs the whole pipeline against **fake captures** â€” real watcher, real queue,
real cache, real import/export, real UI. Only the cracking itself is simulated.
This is the fastest way to understand the tool and to test changes.

## Command reference

| Command | Purpose |
|---|---|
| `wp run` | Build the 4-pane tmux session (normal use) |
| `wp crack --loop` | The engine: watch + crack + record (pane 2) |
| `wp crack --once` | Process the current queue and exit |
| `wp watch` | Only watch and enqueue |
| `wp queue [--live]` | Show the queue (pane 3) |
| `wp results [--live]` | Show solved networks (pane 4) |
| `wp import FILE` | Import passwords you already have |
| `wp export FILE` | Export results (`txt`, `json`, `csv`, `wifite`) |
| `wp connect` | Join a cracked network via the second adapter |
| `wp doctor` | Environment diagnosis |
| `wp config [--init]` | Show or create the config file |

Useful flags: `--engine {auto,hashcat,aircrack}`, `--mask-fallback`,
`--watch-dir` (repeatable), `--state-dir`, `--auto-connect`, `-v`.

## Importing what you already know

`wp import` accepts four formats and figures out which one it is:

```bash
wp import senhas.txt        # ssid:senha   or   AA:BB:CC:DD:EE:FF:senha
wp import cracked.json      # [{"ssid": ..., "bssid": ..., "password": ...}]
wp import cracked.csv       # header: ssid,bssid,password,method
wp import cracked.txt       # wifite's own aligned BSSID/ESSID/PSK table
```

Anything imported is treated as solved: if that network is captured again it
**never enters the cracking queue**. This is the single biggest time saver â€”
re-testing a lab you already broke costs zero CPU.

## Results

Three formats are rewritten automatically on every find, in
`~/.local/share/wifite-pipeline/results/`:

```
cracked.txt    CasaDoRafa:minhaSenha123        # ssid:password, one per line
cracked.json   [{ssid, bssid, password, method, capture, found_at}, ...]
cracked.csv    ssid,bssid,password,method,found_at
```

Passwords are **never** written to the event log â€” only the fact that a
password was found. The database lives in the same state directory and is
safely shared by all four panes (SQLite in WAL mode).

## How it decides what to crack

| Step | Detail |
|---|---|
| **Detect** | Watches `hs/`, `pmkid/` and the working directory for `.cap`, `.pcap`, `.pcapng`, `.22000`, `.16800`, `.pmkid` |
| **Wait for stability** | A file being written by `airodump-ng` exists and *grows*. Inspecting it early gives a false "no handshake". A file is only processed after its size and mtime stop changing |
| **Identify** | Parses ESSID/BSSID from the filename, then `tshark`, then `aircrack-ng` |
| **Cache check** | If that SSID or BSSID was already cracked, it is marked solved immediately and never queued |
| **Convert** | `hcxpcapngtool` turns the capture into hashcat mode `22000` |
| **Crack** | `hashcat -m 22000`, then the same wordlist with rules, then the next wordlist; `aircrack-ng` as fallback |
| **Record** | Writes the three result files, fires a desktop notification, optionally connects |

The cracking engine is probed for real with `hashcat -I` before being trusted:
inside a VM with no GPU and no OpenCL runtime, hashcat reports no devices and
the pipeline silently falls back to `aircrack-ng`.

## Authorized use

This project ships a deliberate speed bump: `wp run` and `wp crack` refuse to
start until you confirm authorization.

```bash
wp run --i-have-authorization
# or set "authorized_use_acknowledged": true in ~/.config/wifite-pipeline/config.json
```

That flag is not security â€” it is a reminder that the interesting part of this
tool is also the part that is illegal without permission.

Good places to practise legally: **TryHackMe**, **Hack The Box**, **VulnHub**
VMs (run as a second VM on VirtualBox's internal network), and your own router.

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
```

45 tests, standard library only â€” no pytest required. They cover BSSID
normalization, queue atomicity, the password cache, all four import formats,
export round-trips, and capture filename parsing.

On Windows, one test is skipped: `:` is an illegal filename character there,
and real captures use `:`-separated BSSIDs.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `wp doctor` shows no adapters | In a VM, pass the USB adapter through to the guest |
| Adapter stuck in monitor mode | `sudo airmon-ng stop wlan0mon`, then use the *other* adapter to connect |
| `connect: nmcli ausente` | `sudo apt install network-manager` |
| Capture never enters the queue | The file never stabilised, or no handshake/PMKID was validated. Check `wp watch -v` |
| hashcat finds nothing but aircrack does | hashcat has no OpenCL backend â€” install `pocl-opencl-icd`, or use `--engine aircrack` |
| `sudo: wp: command not found` | The `wp` wrapper lives in `/usr/local/bin/wp`, which is in sudo's `secure_path`. If you installed with `pipx` or `pip install --user` instead, `wp` lands in `~/.local/bin` (not in sudo's PATH): use `sudo env "PATH=$PATH" wp ...` or `sudo python3 bin/wp ...` |
| Nothing cracks | WPA cracking is ~5â€“20 k candidates/s per CPU core. Order of wordlists matters far more than engine speed |

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full list of planned
improvements â€” targeted wordlist generation from the SSID, hashcat potfile
integration, multi-adapter capture, reporting, and more.

## Credits and licence

Built on the shoulders of [wifite2](https://github.com/kimocoder/wifite2) by
kimocoder and derv82, [aircrack-ng](https://aircrack-ng.org/),
[hashcat](https://hashcat.net/), [hcxtools](https://github.com/ZerBea/hcxtools)
and [SecLists](https://github.com/danielmiessler/SecLists).

`wifite-pipeline` is an independent orchestrator: it contains no wifite source
code and invokes wifite as a separate program. Licensed **MIT** â€” see
[LICENSE](LICENSE).
