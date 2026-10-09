"""Renderizacao no terminal: fila, resultados e eventos.

Sem dependencias externas de proposito. O wifite usa `rich`, mas exigir uma
biblioteca para desenhar quatro tabelas seria um custo alto demais para o
beneficio -- e o pipeline precisa rodar numa Kali recem-instalada, inclusive
com `pip` indisponivel.

Respeitamos `NO_COLOR` e a ausencia de TTY: quando a saida nao e um terminal,
emitemos texto puro (util para `wp results > arquivo.txt`).
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from collections.abc import Iterable, Sequence

from .state import (
    STATUS_CRACKING,
    STATUS_ERROR,
    STATUS_EXHAUSTED,
    STATUS_FOUND,
    STATUS_PENDING,
    STATUS_SKIPPED,
    State,
)


def color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("WP_FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


class C:
    """Codigos ANSI, desligados automaticamente quando nao ha terminal."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"


def paint(text: str, *codes: str) -> str:
    if not color_enabled() or not codes:
        return text
    return "".join(codes) + text + C.RESET


STATUS_STYLE = {
    STATUS_PENDING: ("na fila", C.YELLOW),
    STATUS_CRACKING: ("quebrando", C.CYAN),
    STATUS_FOUND: ("ACHADA", C.GREEN + C.BOLD),
    STATUS_EXHAUSTED: ("esgotada", C.RED),
    STATUS_SKIPPED: ("pulada", C.GREY),
    STATUS_ERROR: ("erro", C.MAGENTA),
}


def term_width(default: int = 100) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except OSError:
        return default


def truncate(text: str, width: int) -> str:
    text = text or ""
    if width <= 1:
        return text[:width]
    if len(text) <= width:
        return text
    return text[: width - 1] + "\u2026"


def table(headers: Sequence[str], rows: Iterable[Sequence[str]],
          widths: Sequence[int] | None = None) -> str:
    rows = [list(map(str, r)) for r in rows]
    if widths is None:
        widths = []
        for i, h in enumerate(headers):
            longest = len(str(h))
            for r in rows:
                if i < len(r):
                    longest = max(longest, len(r[i]))
            widths.append(min(longest, 40))
    header_line = "  ".join(paint(str(h).ljust(w)[:w], C.BOLD) for h, w in zip(headers, widths, strict=False))
    sep = paint("  ".join("-" * w for w in widths), C.GREY)
    body = []
    for r in rows:
        cells = []
        for i, w in enumerate(widths):
            value = str(r[i]) if i < len(r) else ""
            cells.append(truncate(value, w).ljust(w))
        body.append("  ".join(cells))
    return "\n".join([header_line, sep, *body])


# ---------------------------------------------------------------------------
# Telas
# ---------------------------------------------------------------------------
def banner() -> str:
    art = [
        "  wifite-pipeline  ",
        "  captura -> quebra -> resultado -> conexao",
    ]
    return paint(art[0], C.BOLD, C.CYAN) + "\n" + paint(art[1], C.GREY)


def queue_view(state: State, limit: int = 25) -> str:
    counts = state.counts()
    header = (
        f"{paint('FILA', C.BOLD)}   "
        f"na fila: {paint(str(counts[STATUS_PENDING]), C.YELLOW)}   "
        f"quebrando: {paint(str(counts[STATUS_CRACKING]), C.CYAN)}   "
        f"achadas: {paint(str(counts[STATUS_FOUND]), C.GREEN)}   "
        f"esgotadas: {paint(str(counts[STATUS_EXHAUSTED]), C.RED)}"
    )
    targets = state.list_targets(limit=limit)
    if not targets:
        return header + "\n\n" + paint("  Nenhum alvo ainda. O painel do wifite precisa capturar algo.", C.GREY)

    rows = []
    for t in targets:
        label, style = STATUS_STYLE.get(t.status, (t.status, ""))
        rows.append([
            str(t.id),
            (t.ssid or "<oculta>"),
            t.bssid,
            paint(label, style),
            (t.method or "-"),
        ])
    return header + "\n\n" + table(["#", "SSID", "BSSID", "ESTADO", "METODO"], rows,
                                   widths=[4, 26, 17, 10, 16])


def results_view(state: State, limit: int = 40) -> str:
    found = state.results()[:limit]
    header = paint(f"RESOLVIDAS ({len(state.results())})", C.BOLD, C.GREEN)
    if not found:
        return (header + "\n\n" + paint("  Nada quebrado ainda.", C.GREY) + "\n\n"
                + paint("  Para importar senhas ja conhecidas:", C.GREY) + "\n"
                + paint("    wp import minhas-senhas.txt", C.CYAN))

    rows = []
    for t in found:
        rows.append([
            (t.ssid or "<oculta>"),
            t.bssid,
            t.password or "",
            (t.method or "-"),
            t.updated_at.replace("T", " ")[:16],
        ])
    body = table(["SSID", "BSSID", "SENHA", "METODO", "QUANDO"], rows,
                 widths=[24, 17, 22, 14, 16])
    footer = paint("\n  exportar: wp export senhas.json    importar: wp import arquivo.txt", C.GREY)
    return header + "\n\n" + body + "\n" + footer


def events_view(state: State, limit: int = 15) -> str:
    events = state.recent_events(limit)
    if not events:
        return paint("  sem eventos", C.GREY)
    lines = []
    for e in events:
        style = {"success": C.GREEN, "error": C.RED, "warn": C.YELLOW}.get(e["level"], C.GREY)
        lines.append(f"  {paint(e['ts'].replace('T', ' ')[:19], C.GREY)}  "
                     f"{paint(e['level'][:7].ljust(7), style)}  {e['message']}")
    return "\n".join(lines)


def notify_desktop(title: str, message: str) -> None:
    """Avisa a area de trabalho, se houver como. Silencioso se nao houver."""
    if not shutil.which("notify-send"):
        return
    try:
        import subprocess
        subprocess.run(["notify-send", title, message], timeout=5,
                       capture_output=True, check=False)
    except (OSError, subprocess.SubprocessError):
        pass


# ---------------------------------------------------------------------------
# Modo ao vivo (usado pelos paineis 3 e 4)
# ---------------------------------------------------------------------------
def live_loop(render, interval: float = 2.0, iterations: int | None = None) -> None:
    """Redesenha a tela periodicamente. Ctrl+C sai limpo."""
    count = 0
    while iterations is None or count < iterations:
        frame = render()
        if color_enabled():
            sys.stdout.write("\033[2J\033[H")   # limpa + cursor no topo
        sys.stdout.write(banner() + "\n\n" + frame + "\n")
        sys.stdout.write(paint(f"\n  atualiza a cada {interval:.0f}s  |  Ctrl+C para sair", C.GREY) + "\n")
        sys.stdout.flush()
        count += 1
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            break


def rule(width: int | None = None) -> str:
    return paint("-" * (width or min(term_width(), 100)), C.GREY)
