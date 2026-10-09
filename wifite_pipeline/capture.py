"""Leitura, identificacao e conversao dos arquivos de captura.

O wifite nomeia os arquivos com o ESSID e o BSSID embutidos, mas o formato
exato mudou entre versoes e depende de qual ferramenta gerou o arquivo
(airodump-ng, hcxdumptool, hcxpcapngtool). Em vez de assumir um padrao unico,
tentamos varias estrategias em ordem de custo:

    1. nome do arquivo   (instantaneo, sem I/O extra)
    2. tshark            (rapido, se instalado)
    3. aircrack-ng       (lento, mas quase sempre presente)

Nunca inventamos uma senha nem presumimos sucesso: um arquivo so entra na fila
se conseguirmos identificar BSSID e, se possivel, ESSID.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

MAC = r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"

# Uma unica lista de extensoes, reutilizada em todos os padroes. Antes essa
# lista estava duplicada e o primeiro padrao ficou sem as extensoes de hash --
# resultado: `handshake_Rede_AA-BB-...-01.22000` caia no padrao generico e o
# prefixo "handshake_" era engolido como se fosse parte do nome da rede.
SUFFIX_ALT = r"cap|pcap|pcapng|22000|16800|pmkid"

# Prefixos que ferramentas colocam no nome e que NUNCA sao nome de rede.
TOOL_PREFIXES = ("handshake_", "airodump-", "pmkid_", "hcx")

# Tokens que, sozinhos, sao claramente resto de nome de arquivo e nao um SSID.
# Ex.: `handshake_AA-BB-CC-DD-EE-01-01.22000` nao tem nome de rede nenhum e
# acabaria produzindo o "SSID" literal "handshake".
TOOL_TOKENS = {"handshake", "airodump", "pmkid"}

# Formatos de nome ja vistos em campo, do mais especifico ao mais generico.
NAME_PATTERNS = [
    # handshake_<essid>_<bssid>-01.cap   (airodump via wifite)
    re.compile(rf"^handshake_(?P<essid>.+?)_(?P<bssid>{MAC})(?:-\d+)?\.(?:{SUFFIX_ALT})$", re.I),
    # <essid>_<bssid>.22000 / .pmkid / .cap
    re.compile(rf"^(?P<essid>.+?)_(?P<bssid>{MAC})(?:-\d+)?\.(?:{SUFFIX_ALT})$", re.I),
    # <bssid>_<essid>.cap  (ordem invertida, aparece em scripts de terceiros)
    re.compile(rf"^(?P<bssid>{MAC})_(?P<essid>.+?)\.(?:{SUFFIX_ALT})$", re.I),
    # <bssid>.22000  (saida pura do hcxpcapngtool)
    re.compile(rf"^(?P<bssid>{MAC})\.(?:{SUFFIX_ALT})$", re.I),
]

HASH_SUFFIXES = {".22000", ".16800", ".pmkid"}
PCAP_SUFFIXES = {".cap", ".pcap", ".pcapng"}


@dataclass
class CaptureInfo:
    """O que conseguimos descobrir sobre um arquivo de captura."""

    path: Path
    bssid: str | None = None
    essid: str | None = None
    channel: int | None = None
    has_handshake: bool = False
    has_pmkid: bool = False
    source: str = "desconhecida"   # de onde vieram os metadados

    @property
    def valid(self) -> bool:
        """Um alvo so serve se tivermos o BSSID e alguma coisa para quebrar."""
        return bool(self.bssid) and (self.has_handshake or self.has_pmkid
                                     or self.path.suffix.lower() in HASH_SUFFIXES)

    @property
    def kind(self) -> str:
        if self.has_pmkid:
            return "pmkid"
        if self.has_handshake:
            return "handshake"
        if self.path.suffix.lower() in HASH_SUFFIXES:
            return "hash"
        return "desconhecido"


def normalize_bssid(value: str | None) -> str | None:
    if not value:
        return None
    raw = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(raw) != 12:
        return None
    raw = raw.upper()
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2))


def clean_essid(essid: str | None) -> str | None:
    """Descarta restos de nome de arquivo que nao sao nome de rede.

    Rede de seguranca: se algum padrao deixar escapar um "handshake_" ou um
    "handshake" solto para dentro do ESSID, isso viraria um alvo com nome errado
    no banco -- e o cache de senhas conhecidas (que casa por SSID) pararia de
    funcionar. Foi exatamente essa a causa de um bug real de deteccao.
    """
    if not essid:
        return None
    cleaned = essid.strip()
    lowered = cleaned.lower()
    if lowered in TOOL_TOKENS:
        return None
    for prefix in TOOL_PREFIXES:
        if lowered.startswith(prefix):
            cleaned = cleaned[len(prefix):].strip()
            break
    return cleaned or None


def from_filename(path: Path) -> tuple[str | None, str | None]:
    """Extrai (bssid, essid) apenas do nome do arquivo."""
    name = path.name
    for pattern in NAME_PATTERNS:
        m = pattern.match(name)
        if m:
            groups = m.groupdict()
            return normalize_bssid(groups.get("bssid")), clean_essid(groups.get("essid"))
    return None, None


def _run(cmd: list[str], timeout: int = 30) -> str:
    """Executa um comando devolvendo stdout+stderr; nunca levanta excecao."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              errors="replace")
        return (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


def probe_with_tshark(path: Path) -> tuple[str | None, str | None, bool, bool] | None:
    """(bssid, essid, tem_handshake, tem_pmkid) via tshark, ou None se indisponivel."""
    if not shutil.which("tshark"):
        return None
    bssid = essid = None
    out = _run(["tshark", "-r", str(path), "-Y", "wlan.fc.type_subtype == 0x08",
                "-T", "fields", "-e", "wlan.bssid", "-e", "wlan.ssid", "-c", "5"])
    for line in out.splitlines():
        parts = line.split("\t")
        if parts and MAC_RE_FULL.match(parts[0].strip()):
            bssid = normalize_bssid(parts[0].strip())
            if len(parts) > 1 and parts[1].strip():
                essid = parts[1].strip()
            break
    eapol = _run(["tshark", "-r", str(path), "-Y", "eapol", "-T", "fields",
                  "-e", "wlan.bssid", "-c", "5"])
    has_hs = any(MAC_RE_FULL.match(line.strip()) for line in eapol.splitlines() if line.strip())
    has_pmkid = "PMKID" in _run(["tshark", "-r", str(path), "-Y", "eapol.type == 2",
                                 "-T", "fields", "-e", "eapol.keydes.type", "-c", "5"])
    if bssid or has_hs or has_pmkid:
        return bssid, essid, has_hs, has_pmkid
    return None


MAC_RE_FULL = re.compile(rf"^{MAC}$")


def probe_with_aircrack(path: Path) -> tuple[str | None, str | None, bool, bool] | None:
    """Mesma informacao, porem via aircrack-ng (presente praticamente sempre)."""
    if not shutil.which("aircrack-ng"):
        return None
    out = _run(["aircrack-ng", str(path)], timeout=60)
    bssid = essid = None
    for line in out.splitlines():
        m = re.search(rf"(?P<bssid>{MAC})\s+(?P<essid>.+?)\s*$", line.strip())
        if m and bssid is None and "BSSID" not in line:
            bssid = normalize_bssid(m.group("bssid"))
            candidate = m.group("essid").strip()
            if candidate and not candidate.startswith("<"):
                essid = candidate
    has_hs = bool(re.search(r"\b1 handshake\b", out))
    has_pmkid = "PMKID" in out.upper()
    if bssid or has_hs or has_pmkid:
        return bssid, essid, has_hs, has_pmkid
    return None


def inspect(path: Path, deep: bool = True) -> CaptureInfo:
    """Descobre tudo que pudermos sobre um arquivo de captura."""
    path = Path(path)
    info = CaptureInfo(path=path)

    # 1) nome do arquivo -- custo zero
    bssid, essid = from_filename(path)
    if bssid or essid:
        info.bssid, info.essid = bssid, essid
        info.source = "nome do arquivo"
    if path.suffix.lower() in HASH_SUFFIXES:
        # Um .22000 ja e um hash pronto para o hashcat: nada a validar.
        info.source = info.source if info.bssid else "extensao"
        return info

    if not deep:
        return info

    # 2) tshark -- rapido e confiavel
    probed = probe_with_tshark(path)
    # 3) aircrack-ng -- mais lento, mas quase sempre disponivel
    if probed is None:
        probed = probe_with_aircrack(path)

    if probed:
        p_bssid, p_essid, has_hs, has_pmkid = probed
        info.bssid = info.bssid or p_bssid
        info.essid = info.essid or p_essid
        info.has_handshake = has_hs
        info.has_pmkid = has_pmkid
        if info.source == "desconhecida":
            info.source = "conteudo do arquivo"
    return info


def to_22000(capture: Path, out_dir: Path) -> Path | None:
    """Converte .cap/.pcapng para o formato 22000 do hashcat.

    Devolve o caminho do hash, ou None se a conversao nao produziu nada util
    (por exemplo, arquivo sem handshake valido). Se o arquivo ja for 22000,
    devolve ele mesmo.
    """
    capture = Path(capture)
    if capture.suffix.lower() in HASH_SUFFIXES:
        return capture
    if not shutil.which("hcxpcapngtool"):
        return None

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{capture.stem}.22000"
    _run(["hcxpcapngtool", "-o", str(target), str(capture)], timeout=120)

    # O hcxpcapngtool cria o arquivo mesmo sem achar nada; conteudo vazio = falha.
    if target.is_file() and target.stat().st_size > 0:
        return target
    if target.is_file():
        target.unlink(missing_ok=True)
    return None


def is_capture_file(path: Path, globs: list[str] | None = None) -> bool:
    """Decide se vale a pena inspecionar este arquivo."""
    path = Path(path)
    if not path.is_file():
        return False
    if globs:
        return any(path.match(g) for g in globs)
    return path.suffix.lower() in (HASH_SUFFIXES | PCAP_SUFFIXES)
