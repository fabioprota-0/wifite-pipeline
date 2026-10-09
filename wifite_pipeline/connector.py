"""Conectar na rede recem-quebrada usando o SEGUNDO adaptador.

Este e o estagio que o wifite nao tem. A regra de ouro:

    Adaptador 1 -> modo monitor + injecao (o wifite toma conta dele)
    Adaptador 2 -> modo gerenciado, intocado, so para conectar

Se voce tentar conectar pelo adaptador que esta em modo monitor, o NetworkManager
e o wifite vao brigar pelo dispositivo e os dois falham. Por isso exigimos um
adaptador dedicado a conexao e nunca deixamos o codigo escolher o mesmo.

Dentro de uma maquina virtual este adaptador precisa estar passado por USB para
o guest (Dispositivos -> USB no VirtualBox). A placa WiFi interna do notebook e
PCIe, nao USB, entao em regra **nao** pode ser usada como segundo adaptador.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

WIRELESS_MARKERS = ("wlan", "wlp", "wlx", "ath", "wl")


@dataclass
class ConnectResult:
    ok: bool
    interface: str | None = None
    profile: str | None = None
    ip_address: str | None = None
    detail: str = ""


def _run(cmd: list[str], timeout: int = 60) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              errors="replace")
        return (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return "__TIMEOUT__"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"__ERROR__ {exc}"


def list_interfaces() -> list[str]:
    """Adaptadores de rede sem fio visiveis no sistema."""
    out: list[str] = []
    netdir = Path("/sys/class/net")
    if netdir.is_dir():
        for entry in sorted(netdir.iterdir()):
            name = entry.name
            # Um adaptador sem fio tem o subdiretorio 'wireless' (ou 'phy80211').
            if (entry / "wireless").exists() or (entry / "phy80211").exists():
                out.append(name)
    if not out:
        # Reserva: alguns drivers antigos nao expoem /sys/class/net/<if>/wireless.
        blob = _run(["iw", "dev"])
        out = re.findall(r"Interface\s+(\S+)", blob)
    return out


def interface_state(interface: str) -> str:
    """'managed', 'monitor', 'unavailable'..."""
    blob = _run(["iw", "dev", interface, "info"])
    m = re.search(r"type\s+(\w+)", blob)
    return m.group(1) if m else "desconhecido"


def interface_ip(interface: str) -> str | None:
    blob = _run(["ip", "-4", "addr", "show", interface])
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", blob)
    return m.group(1) if m else None


def connect(ssid: str, password: str, interface: str,
            profile: str | None = None, timeout: int = 60) -> ConnectResult:
    """Associa-se a rede pelo `nmcli`, sem tocar no adaptador de captura."""
    if not shutil.which("nmcli"):
        return ConnectResult(False, interface=interface,
                             detail="nmcli ausente (instale network-manager)")

    if interface_state(interface) == "monitor":
        return ConnectResult(
            False, interface=interface,
            detail=(f"{interface} esta em modo monitor. Use `airmon-ng stop {interface}` "
                    "ou escolha outro adaptador para conectar."),
        )

    profile = profile or f"wp-{re.sub(r'[^A-Za-z0-9_.-]', '_', ssid)}"
    cmd = ["nmcli", "device", "wifi", "connect", ssid,
           "password", password, "ifname", interface, "name", profile]
    out = _run(cmd, timeout=timeout)

    if out == "__TIMEOUT__":
        return ConnectResult(False, interface=interface, profile=profile,
                             detail="timeout ao conectar")
    lowered = out.lower()
    if "error" in lowered or "failed" in lowered or "no network with ssid" in lowered:
        return ConnectResult(False, interface=interface, profile=profile,
                             detail=out.strip()[:300])

    ip = interface_ip(interface)
    return ConnectResult(True, interface=interface, profile=profile, ip_address=ip,
                         detail="conectado")


def disconnect(profile: str) -> bool:
    if not shutil.which("nmcli"):
        return False
    out = _run(["nmcli", "connection", "down", profile])
    return "__ERROR__" not in out and "Error" not in out


def forget(profile: str) -> bool:
    """Remove o perfil salvo (apaga a senha do gerenciador de conexoes)."""
    if not shutil.which("nmcli"):
        return False
    out = _run(["nmcli", "connection", "delete", profile])
    return "Error" not in out


def validate_second_adapter(capture_if: str | None,
                            connect_if: str | None) -> list[str]:
    """Problemas que impedem a conexao automatica. Lista vazia = tudo certo."""
    problems: list[str] = []
    interfaces = list_interfaces()
    if not interfaces:
        problems.append("nenhum adaptador sem fio detectado")
        return problems
    if not connect_if:
        problems.append(
            "adaptador de conexao nao definido (use --connect-interface). "
            f"Disponiveis: {', '.join(interfaces) or 'nenhum'}"
        )
        return problems
    if connect_if not in interfaces:
        problems.append(f"adaptador de conexao '{connect_if}' nao existe "
                        f"(disponiveis: {', '.join(interfaces)})")
    if capture_if and connect_if == capture_if:
        problems.append(
            f"'{connect_if}' esta definido para captura E para conexao: "
            "os dois papeis precisam de adaptadores fisicos diferentes"
        )
    if not shutil.which("nmcli"):
        problems.append("nmcli ausente (apt install network-manager)")
    return problems
