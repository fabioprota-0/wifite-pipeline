# Roadmap

Improvement ideas for `wifite-pipeline`, ordered by **impact per hour of work**.
Nothing here is committed to a release date; this is a menu.

Legend: 🟢 high impact / low effort · 🟡 high impact / medium effort ·
🔵 nice to have · 🔴 research-grade

---

## 1. Cracking quality

The single biggest lever. WPA cracking is ~5–20 k candidates/s per CPU core, so
*which* candidates you try matters far more than how fast you try them.

| # | Idea | Notes |
|---|---|---|
| 1.1 | 🟢 **Targeted wordlist from the SSID** | Generate candidates from the network name: `CasaDoRafa` → `casadarafa`, `CasaDoRafa2024`, `CasaDoRafa@123`, leetspeak variants. This breaks far more home routers than `rockyou` does, in seconds instead of hours. Implement with a small permutation generator + `hashcat --stdout` with rules. |
| 1.2 | 🟢 **Read hashcat's potfile as a result source** | Today the pipeline only knows about cracks *it* started. If you crack something manually, or resume a previous potfile, `wp` never learns. Reading `--potfile-path` on each poll makes results converge automatically. |
| 1.3 | 🟢 **Curated wordlist ordering by hit rate** | Order by measured efficiency, not by size: `best110` → `Top1M` → `rockyou` → `10M`. Add a `wp wordlist stats` command that records how many hits each list produced, so the order becomes data-driven over time. |
| 1.4 | 🟡 **Default-country phone/date masks** | Many consumer routers ship an 8–11 digit numeric PSK. `--mask-fallback` currently only tries 8 digits. Configurable masks per country (BR mobile numbers, CPF-shaped, dates) would cover a large slice. |
| 1.5 | 🟡 **Attack chains as a declarative config** | Let the user define an ordered strategy in the config file: `[best64 rules on Top1M] → [SSID permutations] → [8-digit mask] → [rockyou+OneRule]`, with per-stage time budgets. This is the natural evolution of `wordlists` + `hashcat_rules`. |
| 1.6 | 🔵 **Distributed cracking** | Submit `.22000` files to a cracking server or to a rented GPU box, poll for results. `wifite` already integrates wpa-sec; a generic hook would cover self-hosted setups. |
| 1.7 | 🔵 **WPA3-SAE awareness** | Detect SAE/transition-mode captures (`hcxpcapngtool` output type) and use mode 22000's SAE path, marking clearly that CPU-only cracking of SAE is impractical. |
| 1.8 | 🔴 **Automatic rule mining** | Feed previously cracked passwords back into a rule generator (like `wang`-style analysis) so the pipeline learns the local password culture. |

## 2. Capture quality

| # | Idea | Notes |
|---|---|---|
| 2.1 | 🟢 **PMKID-first policy** | PMKID needs no client and no deauth — it is faster and stealthier than a 4-way handshake. Queue PMKID captures ahead of handshakes so the cheap win lands first. |
| 2.2 | 🟢 **Adapter health watchdog** | Adapters silently drop out of monitor mode, or get reclaimed by NetworkManager. Detect the mode change and warn (or restore) instead of quietly capturing nothing for an hour. |
| 2.3 | 🟡 **Multi-adapter capture** | wifite has `--dual-interface`; the pipeline could go further — one adapter per channel, so a wide sweep is possible without channel hopping. |
| 2.4 | 🟡 **`tshark`-based handshake quality score** | A 4-way handshake with a partial EAPOL pair cracks unreliably. Score the capture (message 1+2 vs 2+3 vs 3+4) and retry weak ones instead of burning CPU on them. |
| 2.5 | 🔵 **Wigle/honeypot detection** | wifite2 has `--detect-honeypots`; surfacing that in the queue view would stop you chasing decoys. |

## 3. Orchestration and UX

| # | Idea | Notes |
|---|---|---|
| 3.1 | 🟢 **`wp top` — live TUI dashboard** | One screen replacing panes 3 and 4: queue, active crack, rate, ETA, last find. The current views are deliberately dependency-free ANSI; a real TUI is the obvious upgrade. |
| 3.2 | 🟢 **Desktop/Telegram notification on find** | `notify-send` already fires locally. Add an optional webhook (Telegram/Discord) so a long unattended run reaches you. |
| 3.3 | 🟡 **`wp report` — engagement report** | Markdown/HTML from the database: networks seen, captures, times to crack, wordlist that succeeded, findings with remediation advice. This is what turns a tool into something you can hand a client. |
| 3.4 | 🟡 **Resume across reboots, properly** | The queue already survives; `hashcat --restore` and per-stage checkpoints would make a multi-hour crack survive a crash without losing progress. |
| 3.5 | 🟡 **`--dry-run` for the real pipeline** | `scripts/demo.py` simulates the whole flow; folding it into the CLI (`wp run --dry-run`) would let people validate a config before touching a radio. |
| 3.6 | 🔵 **Scheduling and scoping** | Run only between certain hours, only on listed BSSIDs, with a global time budget — useful for engagements with a defined window. |
| 3.7 | 🔵 **Configuration profiles** | Named profiles (`--profile home-lab`, `--profile client-x`) carrying interfaces, wordlists and connect policy. |

## 4. Engineering and safety

| # | Idea | Notes |
|---|---|---|
| 4.1 | 🟢 **GitHub Actions CI** | Run the unittest suite on every push. Included in `.github/workflows/tests.yml`. |
| 4.2 | 🟢 **Sanitised debug bundle** | `wp doctor --bundle` producing a tar with tool versions, adapter modes and logs — with SSIDs/passwords redacted. Makes bug reports actually actionable. |
| 4.3 | 🟡 **Encrypt the results database** | It holds real network passwords in plain SQLite. Optional passphrase (SQLCipher or an age-encrypted export) would make the default safe on a shared machine. |
| 4.4 | 🟡 **Structured logging** | JSON lines alongside the SQLite events, for shipping into a SIEM or a report generator. |
| 4.5 | 🔵 **Property-based tests for the importers** | The four import formats are parsing untrusted text. Hypothesis-style fuzzing of `_parse_text_line` would harden them cheaply. |
| 4.6 | 🔵 **Package for Kali** | A `kali-tools-wireless` style metapackage or a Debian `.deb` via `kali-meta`. |

## 5. Explicitly out of scope

Things that sound appealing but do not fit this tool's purpose:

- **Automatic attack of any network in range.** The tool captures what wifite
  captures; it does not choose victims, and the authorization gate exists on
  purpose.
- **Deauth floods or denial-of-service features.** Not a cracking aid.
- **Persisting cracked credentials anywhere but local disk by default.**
  Uploading captures to third-party cracking services (wpa-sec) stays opt-in
  and manual.
- **Evading detection by network operators.** Out of scope.

---

## Contributing

The most valuable contributions right now, in order:

1. **Real capture files** with unusual filename patterns. Every naming variant
   found in the wild is a bug we can prevent — see
   `wifite_pipeline/capture.py::NAME_PATTERNS`, which already carries a
   regression test for one such bug.
2. **Field reports** of which wordlist actually cracked a network. That data
   drives idea 1.3.
3. **Adapter compatibility notes** — which chipsets survive long monitor-mode
   sessions, which need power management disabled.
