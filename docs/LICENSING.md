# Licensing

## This project: MIT

`wifite-pipeline` is released under the **MIT License**. The full text is in
[LICENSE](../LICENSE).

> **Why this file exists:** the MIT text in `LICENSE` is kept *verbatim and
> alone*. Earlier it carried an extra explanatory note at the bottom, and that
> was enough to make GitHub's license detector report the repository as
> `Other` instead of `MIT`. Keeping `LICENSE` pure, and putting prose here,
> means the repository shows the correct license badge in its sidebar.

## The tools it orchestrates

`wifite-pipeline` contains **no source code** from the tools it drives. It
invokes them as separate programs over the command line, which is why MIT is
the appropriate license here.

| Tool | License | How it is used |
|---|---|---|
| [wifite2](https://github.com/kimocoder/wifite2) | GPL | Executed via `subprocess` (`wifite --skip-crack`) |
| [aircrack-ng](https://aircrack-ng.org/) | GPL | Executed via `subprocess` |
| [hashcat](https://hashcat.net/) | MIT | Executed via `subprocess` |
| [hcxtools](https://github.com/ZerBea/hcxtools) | MIT | Executed via `subprocess` |
| [SecLists](https://github.com/danielmiessler/SecLists) | MIT | Read-only wordlist data |
| [NetworkManager/nmcli](https://networkmanager.dev/) | GPL/LGPL | Executed via `subprocess` |

Running a GPL program as a subprocess does **not** make the caller a derivative
work. This is the same arrangement used by many freely licensed wrappers.

> ⚠️ **If you copy wifite source code into this project**, the combined work
> becomes subject to the GPL and `LICENSE` must be replaced accordingly.
