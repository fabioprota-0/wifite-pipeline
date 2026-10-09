"""Configuracao central, caminhos padrao e deteccao de dependencias externas.

Nada aqui depende de bibliotecas de terceiros: apenas a stdlib. As ferramentas
que o projeto orquestra sao binarios do sistema, descobertos em tempo de
execucao por `which` -- nunca presumimos um caminho absoluto fixo.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

APP_NAME = "wifite-pipeline"
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"

# Estado do pipeline (fila, resultados, eventos). Fica fora do repositorio.
DEFAULT_STATE_DIR = Path(os.environ.get("WP_STATE_DIR", Path.home() / ".local" / "share" / APP_NAME))

# ---------------------------------------------------------------------------
# Ferramentas externas
# ---------------------------------------------------------------------------
# required=True  -> sem ela o pipeline nao funciona
# required=False -> habilita um recurso extra; a ausencia apenas desabilita
TOOLS: Dict[str, Dict[str, object]] = {
    "wifite": {
        "required": True,
        "apt": "wifite",
        "why": "captura de handshakes/PMKID (estagio 1)",
    },
    "hcxpcapngtool": {
        "required": False,
        "apt": "hcxtools",
        "why": "converte .cap/.pcapng para o formato 22000 do hashcat",
    },
    "hashcat": {
        "required": False,
        "apt": "hashcat",
        "why": "quebra em modo 22000, o mais rapido em CPU/GPU",
    },
    "aircrack-ng": {
        "required": False,
        "apt": "aircrack-ng",
        "why": "quebra alternativa e validacao de handshake",
    },
    "aireplay-ng": {
        "required": False,
        "apt": "aircrack-ng",
        "why": "deauth (usado pelo proprio wifite)",
    },
    "nmcli": {
        "required": False,
        "apt": "network-manager",
        "why": "conectar a rede quebrada pelo segundo adaptador",
    },
    "iw": {
        "required": False,
        "apt": "iw",
        "why": "listar adaptadores e confirmar modo monitor",
    },
    "airmon-ng": {
        "required": False,
        "apt": "aircrack-ng",
        "why": "colocar adaptador em modo monitor",
    },
    "tshark": {
        "required": False,
        "apt": "tshark",
        "why": "validacao extra dos arquivos de captura",
    },
}


def find_tool(name: str) -> Optional[str]:
    """Caminho absoluto do binario, ou None se ausente."""
    return shutil.which(name)


def tool_available(name: str) -> bool:
    return find_tool(name) is not None


def missing_required_tools() -> List[str]:
    return [n for n, m in TOOLS.items() if m["required"] and not find_tool(n)]


@dataclass
class Settings:
    """Configuracao efetiva do pipeline, com padroes sensatos para Kali."""

    # --- Onde procurar capturas -------------------------------------------
    # O wifite grava handshakes em `hs/` relativo ao diretorio de trabalho.
    # Em vez de confiar cegamente nisso, varremos uma lista de diretorios.
    watch_dirs: List[str] = field(
        default_factory=lambda: [
            str(Path.cwd() / "hs"),
            str(Path.cwd() / "pmkid"),
            str(Path.cwd()),
        ]
    )
    # Globs de extensoes que consideramos uma captura.
    capture_globs: List[str] = field(
        default_factory=lambda: ["*.cap", "*.pcap", "*.pcapng", "*.22000", "*.16800", "*.pmkid"]
    )

    # --- Wordlists ---------------------------------------------------------
    # Ordem de prioridade: a primeira que existir e for valida e usada.
    # O wifite distribui sua propria wordlist "probable" no repositorio.
    wordlists: List[str] = field(
        default_factory=lambda: [
            "/usr/share/wordlists/wifite-probable.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz",
            "/usr/share/seclists/Passwords/Common-Credentials/best110.txt",
        ]
    )

    # --- Diretorios de estado ---------------------------------------------
    state_dir: str = str(DEFAULT_STATE_DIR)

    # --- Adaptadores -------------------------------------------------------
    # Adaptador 1: usado pelo wifite para captura (modo monitor + injecao).
    capture_interface: Optional[str] = None
    # Adaptador 2: mantido gerenciado, usado APENAS para conectar na rede quebrada.
    connect_interface: Optional[str] = None
    # Conectar automaticamente assim que a senha for descoberta.
    auto_connect: bool = False
    # Perfil de conexao criado pelo nmcli (facilita desconectar depois).
    connection_prefix: str = "wp"

    # --- Cracker -----------------------------------------------------------
    # Motor preferido: "hashcat" (mais rapido) ou "aircrack" (fallback sempre presente).
    cracker_engine: str = "auto"
    # Regras do hashcat aplicadas depois da wordlist limpa (aumenta muito a cobertura).
    hashcat_rules: List[str] = field(default_factory=lambda: ["/usr/share/hashcat/rules/best64.rule"])
    # Timeout por wordlist, em segundos. 0 = sem limite.
    crack_timeout: int = 0
    # Tentar ataque de mascara (8 digitos) apos esgotar as wordlists.
    mask_fallback: bool = False

    # --- Comportamento -----------------------------------------------------
    # Intervalo de varredura do watcher, em segundos.
    poll_interval: float = 2.0
    # Reenfileirar alvos marcados como "exhausted" quando uma palavra nova chega.
    retry_exhausted: bool = False
    # Sessao tmux usada pelo modo `wp run`.
    tmux_session: str = "wp"
    # Tocar um som / notificar no desktop quando encontrar uma senha.
    notify: bool = True

    # --- Seguranca ---------------------------------------------------------
    # Trava de uso autorizado: `wp run` recusa iniciar sem `--i-have-authorization`
    # ou sem este campo ligado no config. Ver README, secao "Uso autorizado".
    authorized_use_acknowledged: bool = False

    # ------------------------------------------------------------------
    @property
    def state_path(self) -> Path:
        return Path(self.state_dir)

    @property
    def db_path(self) -> Path:
        return self.state_path / "pipeline.db"

    @property
    def results_dir(self) -> Path:
        return self.state_path / "results"

    @property
    def log_dir(self) -> Path:
        return self.state_path / "logs"

    def ensure_dirs(self) -> List[str]:
        """Cria os diretorios de estado. Devolve a lista de problemas (vazia = ok).

        Nao levanta excecao de proposito: `wp doctor` precisa rodar justamente
        quando os diretorios estao inacessiveis, para poder dizer o que esta
        errado. Quem decide se o problema e fatal e o chamador.
        """
        problems: List[str] = []
        for p in (self.state_path, self.results_dir, self.log_dir):
            try:
                p.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                problems.append(f"{p}: {exc.strerror or exc}")
        return problems

    def existing_wordlists(self) -> List[str]:
        """Somente as wordlists que realmente existem no disco, na ordem dada."""
        out = []
        for w in self.wordlists:
            if w and Path(w).is_file():
                out.append(w)
        return out

    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Settings":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Settings":
        """Carrega do disco, tolerando arquivo ausente ou corrompido."""
        cfg = path or CONFIG_FILE
        if not cfg.is_file():
            return cls()
        try:
            return cls.from_dict(json.loads(cfg.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            # Config invalido nunca deve impedir o trabalho: caimos nos padroes.
            return cls()

    def save(self, path: Optional[Path] = None) -> Path:
        cfg = path or CONFIG_FILE
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return cfg


def resolve_wordlist(explicit: Optional[str], settings: Settings) -> Optional[str]:
    """Wordlist escolhida: a explicita, senao a primeira da lista que existir."""
    if explicit:
        return explicit if Path(explicit).is_file() else None
    found = settings.existing_wordlists()
    return found[0] if found else None
