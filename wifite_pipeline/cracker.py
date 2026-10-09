"""Motor de quebra: hashcat (preferido) com queda automatica para aircrack-ng.

Decisao de projeto importante: **nunca assumimos que o hashcat funciona**.
Dentro de uma maquina virtual, sem GPU e possivelmente sem runtime OpenCL, o
hashcat pode nao ter nenhum backend disponivel. Por isso:

  * `hashcat_usable()` faz um teste real (`hashcat -I`) antes de confiar nele;
  * o aircrack-ng e o fallback garantido, porque ja e dependencia do wifite;
  * o resultado e sempre validado no arquivo de potfile/na saida, nunca
    inferido do codigo de retorno -- o hashcat devolve 1 tanto para "esgotou"
    quanto para "erro".

Sobre desempenho com CPU: quebrar WPA e caro por natureza (4096 iteracoes de
PBKDF2-HMAC-SHA1 por candidato). Num i3 de 2 nucleos espere algo entre 5 e 20
mil candidatos por segundo. Isso significa que a ordem das wordlists importa
muito mais do que a velocidade do motor.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

HASHCAT_MODE_WPA = "22000"

# aircrack-ng imprime "KEY FOUND! [ senha ]"
AIRCKACK_KEY_RE = re.compile(r"KEY FOUND!\s*\[\s*(?P<key>.+?)\s*\]")
# hashcat --show imprime "<hash>:<senha>"
HASHCAT_SHOW_RE = re.compile(r"^[0-9a-fA-F]+\*?[^:]*:(?P<key>.+)$")


@dataclass
class CrackResult:
    found: bool
    password: str | None = None
    engine: str | None = None
    wordlist: str | None = None
    elapsed: float = 0.0
    detail: str = ""


def hashcat_usable() -> bool:
    """O hashcat realmente consegue rodar aqui? (teste real, nao `which`)."""
    if not shutil.which("hashcat"):
        return False
    try:
        proc = subprocess.run(["hashcat", "-I"], capture_output=True, text=True,
                              timeout=25, errors="replace")
        blob = ((proc.stdout or "") + (proc.stderr or "")).lower()
    except (OSError, subprocess.SubprocessError):
        return False
    if "no devices found" in blob or "no opencl" in blob or "no backend" in blob:
        return False
    return "backend" in blob or "device" in blob or proc.returncode == 0


def _run(cmd: list[str], timeout: int | None = None) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              errors="replace")
        return (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return "__TIMEOUT__"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"__ERROR__ {exc}"


class Cracker:
    """Executa a quebra contra uma ou mais wordlists, em ordem de prioridade."""

    def __init__(self, engine: str = "auto", potfile: Path | None = None,
                 rules: list[str] | None = None, timeout: int = 0,
                 mask_fallback: bool = False, verbose: bool = False):
        self.verbose = verbose
        self.timeout = timeout
        self.rules = [r for r in (rules or []) if Path(r).is_file()]
        self.mask_fallback = mask_fallback
        self.potfile = Path(potfile) if potfile else Path.home() / ".local/share/wifite-pipeline/hashcat.potfile"
        self.potfile.parent.mkdir(parents=True, exist_ok=True)
        self.engine = self._resolve_engine(engine)

    @staticmethod
    def _resolve_engine(engine: str) -> str:
        if engine == "auto":
            return "hashcat" if hashcat_usable() else "aircrack"
        return engine

    # -- API publica ------------------------------------------------------
    def crack(self, hash_path: Path | None, wordlists: list[str],
              cap_path: Path | None = None, bssid: str | None = None,
              essid: str | None = None) -> CrackResult:
        """Tenta cada wordlist ate encontrar a senha."""
        started = time.time()
        usable = [w for w in wordlists if w and Path(w).is_file()]
        if not usable:
            return CrackResult(False, detail="nenhuma wordlist valida encontrada")

        for wordlist in usable:
            if self.engine == "hashcat" and hash_path:
                res = self._hashcat(hash_path, Path(wordlist))
                if res.found:
                    res.elapsed = time.time() - started
                    return res
                if "__ERROR__" in res.detail:
                    # hashcat quebrou no meio: caimos para o aircrack.
                    self.engine = "aircrack"
            if self.engine == "aircrack" and cap_path:
                res = self._aircrack(Path(cap_path), Path(wordlist), bssid, essid)
                if res.found:
                    res.elapsed = time.time() - started
                    return res

        if self.mask_fallback and self.engine == "hashcat" and hash_path:
            res = self._hashcat_mask(hash_path)
            if res.found:
                res.elapsed = time.time() - started
                return res

        return CrackResult(False, engine=self.engine,
                           detail=f"{len(usable)} wordlist(s) esgotada(s)",
                           elapsed=time.time() - started)

    # -- hashcat ----------------------------------------------------------
    def _hashcat(self, hash_path: Path, wordlist: Path) -> CrackResult:
        base = [
            "hashcat", "-m", HASHCAT_MODE_WPA, str(hash_path), str(wordlist),
            "--potfile-path", str(self.potfile),
            "--status", "--status-timer", "15",
            "--quiet",
        ]
        if self.verbose:
            base.remove("--quiet")
        # `-O` usa kernels otimizados: bem mais rapido, ao custo de limitar o
        # comprimento da senha. Para WPA esse limite (31 chars) e irrelevante.
        base.append("-O")
        # --force e necessario quando nao ha GPU dedicada (caso da VM).
        base.append("--force")

        # 1) tentativa limpa
        out = _run(base, timeout=self.timeout or None)
        if out == "__TIMEOUT__":
            return CrackResult(False, engine="hashcat", detail="timeout")

        hit = self._hashcat_lookup(hash_path)
        if hit:
            return CrackResult(True, password=hit, engine="hashcat",
                               wordlist=str(wordlist), detail="wordlist")

        # 2) tentativa com regras -- custo maior, cobertura muito maior
        for rule in self.rules:
            cmd = [*base, "-r", rule]
            out = _run(cmd, timeout=self.timeout or None)
            if out == "__TIMEOUT__":
                continue
            hit = self._hashcat_lookup(hash_path)
            if hit:
                return CrackResult(True, password=hit, engine="hashcat",
                                   wordlist=f"{wordlist} +r {Path(rule).name}",
                                   detail="wordlist+regra")

        return CrackResult(False, engine="hashcat", wordlist=str(wordlist),
                           detail="nao encontrada nesta wordlist")

    def _hashcat_mask(self, hash_path: Path) -> CrackResult:
        """Falha comum em roteadores: PSK de 8 digitos. ?d x8 = 100 milhoes."""
        cmd = ["hashcat", "-m", HASHCAT_MODE_WPA, str(hash_path), "-a", "3",
               "?d?d?d?d?d?d?d?d",
               "--potfile-path", str(self.potfile), "--quiet", "-O", "--force"]
        _run(cmd, timeout=self.timeout or None)
        hit = self._hashcat_lookup(hash_path)
        if hit:
            return CrackResult(True, password=hit, engine="hashcat", detail="mascara 8 digitos")
        return CrackResult(False, engine="hashcat", detail="mascara sem sucesso")

    def _hashcat_lookup(self, hash_path: Path) -> str | None:
        """Le a senha do potfile. Fonte da verdade: o potfile, nao o stdout."""
        if self.potfile.is_file():
            for line in self.potfile.read_text(encoding="utf-8", errors="replace").splitlines():
                if ":" in line:
                    _, _, pwd = line.rpartition(":")
                    if pwd:
                        return pwd
        out = _run(["hashcat", "-m", HASHCAT_MODE_WPA, str(hash_path),
                    "--potfile-path", str(self.potfile), "--show"])
        for line in out.splitlines():
            if ":" in line:
                _, _, pwd = line.rpartition(":")
                if pwd.strip():
                    return pwd.strip()
        return None

    # -- aircrack-ng ------------------------------------------------------
    def _aircrack(self, cap_path: Path, wordlist: Path, bssid: str | None,
                  essid: str | None) -> CrackResult:
        if not shutil.which("aircrack-ng"):
            return CrackResult(False, engine="aircrack", detail="aircrack-ng ausente")
        cmd = ["aircrack-ng", "-w", str(wordlist), str(cap_path)]
        if bssid:
            cmd += ["-b", bssid]
        if essid:
            cmd += ["-e", essid]
        out = _run(cmd, timeout=self.timeout or None)
        if out == "__TIMEOUT__":
            return CrackResult(False, engine="aircrack", detail="timeout")
        m = AIRCKACK_KEY_RE.search(out)
        if m:
            return CrackResult(True, password=m.group("key"), engine="aircrack",
                               wordlist=str(wordlist), detail="wordlist")
        return CrackResult(False, engine="aircrack", wordlist=str(wordlist),
                           detail="nao encontrada nesta wordlist")
