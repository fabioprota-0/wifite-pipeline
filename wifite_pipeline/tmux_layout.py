"""Monta os 4 paineis do tmux.

Layout:

    +---------------------------+---------------------------+
    | 1  wifite (captura)       | 2  cracker (quebra)       |
    |    --skip-crack           |    wp crack --loop        |
    +---------------------------+---------------------------+
    | 3  fila                   | 4  resolvidas + importar  |
    |    wp queue --live        |    wp results --live      |
    +---------------------------+---------------------------+

Por que tmux e nao 4 janelas soltas de terminal: no tmux cada painel tem um
processo proprio com o seu proprio log, tudo morre junto com a sessao, e o
resultado e reproduzivel numa linha (`wp run`). Quatro janelas de terminal
exigem adivinhar o emulador instalado (xfce4-terminal, gnome-terminal, konsole,
xterm...) e ficam orfas se voce fechar a principal.

O modo `--no-tmux` existe para quem prefere janelas separadas; ele imprime os
quatro comandos prontos para colar.
"""

from __future__ import annotations

import contextlib
import shutil
import subprocess
from dataclasses import dataclass

from .config import Settings

TMUX = "tmux"


@dataclass
class Pane:
    index: int
    title: str
    command: str
    description: str


def build_panes(settings: Settings, wifite_args: str = "", wordlist: str | None = None,
                python: str = "wp") -> list[Pane]:
    """Os quatro comandos, na ordem em que serao criados."""
    wl = f" --wordlist {wordlist}" if wordlist else ""

    pane1 = f"sudo wifite --skip-crack {wifite_args}".strip()
    return [
        Pane(1, "wifite", pane1,
             "captura handshakes/PMKID (nao quebra: a quebra e do painel 2)"),
        Pane(2, "cracker", f"{python} crack --loop{wl}",
             "vigia as capturas e quebra assim que cada uma fica pronta"),
        Pane(3, "fila", f"{python} queue --live",
             "o que esta na fila, quebrando, esgotado"),
        Pane(4, "resolvidas", f"{python} results --live",
             "senhas encontradas e como importar as que voce ja tem"),
    ]


def tmux_available() -> bool:
    return shutil.which(TMUX) is not None


def session_exists(name: str) -> bool:
    try:
        proc = subprocess.run([TMUX, "has-session", "-t", name],
                              capture_output=True, timeout=10)
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def kill_session(name: str) -> None:
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run([TMUX, "kill-session", "-t", name], capture_output=True, timeout=10)


def _tmux(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([TMUX, *args], capture_output=True, text=True,
                          errors="replace", timeout=20)


def launch(settings: Settings, panes: list[Pane], attach: bool = True,
           recreate: bool = False, workdir: str | None = None) -> int:
    """Cria a sessao com os paineis e (opcionalmente) anexa a ela."""
    if not tmux_available():
        print("tmux nao encontrado. Instale com: sudo apt install tmux")
        return 1

    name = settings.tmux_session
    if session_exists(name):
        if not recreate:
            print(f"A sessao tmux '{name}' ja existe. Anexando...")
            print("  (para recriar do zero: wp run --recreate)")
            if attach:
                return subprocess.call([TMUX, "attach-session", "-t", name])
            return 0
        kill_session(name)

    # Painel 1 vira a janela inicial da sessao.
    first = panes[0]
    args: list[str] = ["new-session", "-d", "-s", name, "-n", "pipeline"]
    if workdir:
        args += ["-c", workdir]
    args += [first.command]
    result = _tmux(*args)
    if result.returncode != 0:
        print(f"Falha ao criar a sessao tmux: {result.stderr.strip()}")
        return 1
    _tmux("set-option", "-t", name, "pane-border-status", "top")
    _tmux("set-option", "-t", name, "pane-border-format", " #{pane_title} ")
    _tmux("select-pane", "-t", f"{name}:0.0", "-T", first.title)

    # Painel 2 a direita do 1; 3 e 4 na linha de baixo.
    splits = [("-h", 2), ("-v", 3), ("-h", 4)]
    for flag, pane in splits:
        cmd = _tmux("split-window", flag, "-t", name, "-c", workdir or ".", pane.command)
        if cmd.returncode != 0:
            print(f"aviso: falha ao criar o painel {pane.index}: {cmd.stderr.strip()}")
    for pane in panes:
        idx = pane.index - 1
        _tmux("select-pane", "-t", f"{name}:0.{idx}", "-T", pane.title)

    _tmux("select-layout", "-t", name, "tiled")
    _tmux("select-pane", "-t", f"{name}:0.0")

    print(f"Sessao tmux '{name}' criada com {len(panes)} paineis.")
    for pane in panes:
        print(f"  [{pane.index}] {pane.title:<12} {pane.description}")

    if attach:
        return subprocess.call([TMUX, "attach-session", "-t", name])
    print(f"\nAnexe quando quiser com:  tmux attach -t {name}")
    return 0


def print_manual_layout(panes: list[Pane]) -> None:
    """Modo --no-tmux: quatro comandos prontos para colar em quatro terminais."""
    print("\nModo sem tmux: abra 4 terminais e cole um comando em cada.\n")
    for pane in panes:
        print(f"--- Terminal {pane.index}: {pane.title} ---")
        print(f"    # {pane.description}")
        print(f"    {pane.command}\n")
