"""Vigia os diretorios do wifite e enfileira cada captura nova.

Cuidado que a maioria dos scripts caseiros esquece: quando o airodump-ng esta
gravando, o arquivo `.cap` existe e **cresce** -- inspecionar nesse momento da
um falso negativo ("sem handshake") porque o 4-way handshake talvez ainda nao
tenha sido escrito. Por isso so tratamos um arquivo depois que ele fica
**estavel** (mesmo tamanho e mesma data em duas varreduras seguidas).
"""

from __future__ import annotations

import signal
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from . import capture as capture_mod
from .config import Settings
from .state import State, Target


class Watcher:
    """Varre os diretorios configurados e enfileira capturas novas."""

    def __init__(self, settings: Settings, state: State,
                 on_new: Optional[Callable[[Target], None]] = None,
                 verbose: bool = False):
        self.settings = settings
        self.state = state
        self.on_new = on_new
        self.verbose = verbose
        # Assinatura (tamanho, mtime) da ultima varredura, para detectar estabilidade.
        self._signatures: Dict[str, Tuple[int, float]] = {}
        self._stop = threading.Event()

    # -- log --------------------------------------------------------------
    def _say(self, message: str, level: str = "info") -> None:
        if self.verbose or level != "debug":
            print(f"[watcher] {message}", flush=True)

    # -- varredura --------------------------------------------------------
    def scan_once(self) -> List[Target]:
        """Uma passada completa. Devolve apenas os alvos recem-enfileirados."""
        added: List[Target] = []
        for directory in self.settings.watch_dirs:
            d = Path(directory)
            if not d.is_dir():
                continue
            for pattern in self.settings.capture_globs:
                for path in sorted(d.glob(pattern)):
                    if not path.is_file():
                        continue
                    if not self._is_stable(path):
                        continue
                    target = self._process(path)
                    if target is not None:
                        added.append(target)
        return added

    def _is_stable(self, path: Path) -> bool:
        """True quando o arquivo parou de crescer entre duas varreduras."""
        key = str(path)
        try:
            st = path.stat()
        except OSError:
            return False
        sig = (st.st_size, st.st_mtime)
        previous = self._signatures.get(key)
        self._signatures[key] = sig
        if previous is None:
            return False          # primeira vez que vemos: espere a proxima
        if previous != sig:
            return False          # ainda sendo escrito
        if st.st_size == 0:
            return False          # arquivo vazio nao serve
        return True

    def _process(self, path: Path) -> Optional[Target]:
        """Inspeciona o arquivo e, se valido, enfileira. None se nao servir."""
        info = capture_mod.inspect(path)
        if not info.valid:
            self._say(f"ignorado (sem handshake/PMKID valido): {path.name}", "debug")
            return None

        # Duplicata? O proprio banco responde: a chave e (bssid, capture_path).
        existing = [t for t in self.state.find_by_bssid(info.bssid or "")
                    if t.capture_path == str(path)]
        if existing:
            return None

        # Melhoria central: se essa rede ja foi quebrada antes, nem entra na fila.
        known = self.state.known_password(info.essid, info.bssid)
        if known:
            target_id = self.state.enqueue(
                bssid=info.bssid or "", ssid=info.essid, channel=info.channel,
                capture_path=str(path), note="rede ja conhecida",
            )
            if target_id:
                self.state.set_status(target_id, "found", password=known, method="cache")
                self._say(f"{info.essid or info.bssid}: senha ja conhecida, pulando quebra")
            return None

        target_id = self.state.enqueue(
            bssid=info.bssid or "", ssid=info.essid, channel=info.channel,
            capture_path=str(path), note=f"via {info.source}",
        )
        if target_id is None:
            return None

        target = self.state.get(target_id)
        self._say(f"nova captura ({info.kind}): {info.essid or info.bssid} -> fila #{target_id}")
        if target and self.on_new:
            try:
                self.on_new(target)
            except Exception as exc:      # callback do usuario nunca derruba o watcher
                self._say(f"callback falhou: {exc}", "debug")
        return target

    # -- laco -------------------------------------------------------------
    def run_forever(self, interval: Optional[float] = None) -> None:
        delay = interval if interval is not None else self.settings.poll_interval
        self._install_signal_handlers()
        self._say(f"vigia ativo em: {', '.join(self.settings.watch_dirs)}")
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception as exc:
                self._say(f"erro na varredura: {exc}")
            self._stop.wait(delay)
        self._say("encerrado")

    def _install_signal_handlers(self) -> None:
        def handler(signum, frame):   # noqa: ARG001
            self._stop.set()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass  # fora da thread principal

    def stop(self) -> None:
        self._stop.set()
