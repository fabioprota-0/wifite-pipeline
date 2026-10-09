"""Fila, resultados e eventos em SQLite.

Por que SQLite e nao JSON: os quatro paineis do tmux sao **processos
independentes** que leem e escrevem ao mesmo tempo. Um arquivo JSON exigiria
um esquema de lock caseiro e sujeito a corrupcao. O SQLite resolve isso com
transacoes reais.

Detalhes importantes de concorrencia:
  * `journal_mode=WAL` permite leitores simultaneos enquanto ha um escritor.
  * `busy_timeout` faz o processo **esperar** pelo lock em vez de estourar
    "database is locked" -- essencial com 4 paineis batendo no mesmo arquivo.
  * `claim_next()` usa `BEGIN IMMEDIATE`, garantindo que dois workers nunca
    peguem o mesmo alvo.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# ---------------------------------------------------------------------------
# Estados possiveis de um alvo
# ---------------------------------------------------------------------------
STATUS_PENDING = "pending"        # capturado, aguardando na fila
STATUS_CRACKING = "cracking"      # um worker esta testando agora
STATUS_FOUND = "found"            # senha descoberta
STATUS_EXHAUSTED = "exhausted"    # wordlists esgotadas sem sucesso
STATUS_SKIPPED = "skipped"        # ja conhecido (senha em cache)
STATUS_ERROR = "error"            # falha no processamento

ALL_STATUSES = (STATUS_PENDING, STATUS_CRACKING, STATUS_FOUND,
                STATUS_EXHAUSTED, STATUS_SKIPPED, STATUS_ERROR)

# Um BSSID e "AA:BB:CC:DD:EE:FF" (aceitamos separadores variados na entrada).
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:\-.]?[0-9a-fA-F]{2}){5}$")
_MAC_INLINE = r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"

# Colunas separadas por 2+ espacos: o formato do cracked.txt do wifite.
# Precisa ser testado ANTES do formato "chave:valor", porque o BSSID contem ':'
# e o rpartition pegaria o ultimo dois-pontos de dentro do proprio BSSID.
_TABLE_RE = re.compile(rf"^({_MAC_INLINE})\s{{2,}}(.+?)\s{{2,}}(\S+)\s*$")


def pseudo_bssid(ssid: str) -> str:
    """BSSID sintetico, estavel, derivado do SSID.

    Usado quando importamos uma senha sem BSSID conhecido. Precisa ser:
      * unico por SSID -- senao dois SSIDs diferentes colidem no indice unico;
      * estavel -- para que reimportar ATUALIZE a linha em vez de criar outra.

    O prefixo 02 marca o endereco como "administrado localmente", garantindo
    que ele nunca colida com um BSSID real de fabricante.
    """
    digest = hashlib.sha1(ssid.encode("utf-8", "replace")).hexdigest().upper()
    return "02:" + ":".join(digest[i:i + 2] for i in range(0, 10, 2))


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def normalize_bssid(value: Optional[str]) -> Optional[str]:
    """'aabbccddeeff' / 'AA-BB-...' -> 'AA:BB:CC:DD:EE:FF'. None se invalido."""
    if not value:
        return None
    raw = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(raw) != 12:
        return None
    raw = raw.upper()
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2))


@dataclass
class Target:
    """Uma rede capturada e seu progresso de quebra."""

    bssid: str
    ssid: Optional[str] = None
    channel: Optional[int] = None
    capture_path: Optional[str] = None
    hash_path: Optional[str] = None
    status: str = STATUS_PENDING
    password: Optional[str] = None
    method: Optional[str] = None
    attempts: int = 0
    id: Optional[int] = None
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    note: Optional[str] = None

    @property
    def label(self) -> str:
        name = self.ssid if self.ssid else "<oculta>"
        return f"{name} ({self.bssid})"

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Target":
        data = dict(row)
        data.pop("rowid", None)
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class ImportReport:
    added: int = 0
    updated: int = 0
    skipped: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.added + self.updated + self.skipped

    def summary(self) -> str:
        return (f"{self.added} novo(s), {self.updated} atualizado(s), "
                f"{self.skipped} ignorado(s), {len(self.errors)} erro(s)")


SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid        TEXT NOT NULL,
    ssid         TEXT,
    channel      INTEGER,
    capture_path TEXT,
    hash_path    TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    password     TEXT,
    method       TEXT,
    attempts     INTEGER NOT NULL DEFAULT 0,
    note         TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
-- Um mesmo BSSID pode ter varias capturas ao longo do tempo; a captura e parte
-- da identidade. Sem isso, recapturar a mesma rede sobrescreveria o historico.
CREATE UNIQUE INDEX IF NOT EXISTS idx_targets_unique
    ON targets (bssid, IFNULL(capture_path, ''));
CREATE INDEX IF NOT EXISTS idx_targets_status ON targets (status);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    level     TEXT NOT NULL,
    target_id INTEGER,
    message   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts DESC);
"""


class State:
    """Acesso ao banco de estado. Seguro para uso a partir de varios processos."""

    def __init__(self, db_path: Path, timeout: float = 30.0):
        self.db_path = Path(db_path)
        self.timeout = timeout
        # Uma conexao por thread: sqlite3 nao gosta de conexoes compartilhadas.
        self._local = threading.local()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    # -- conexao ----------------------------------------------------------
    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self.db_path), timeout=self.timeout,
                                   isolation_level=None)  # autocommit: controlamos nos
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=%d" % int(self.timeout * 1000))
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def __enter__(self) -> "State":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)

    # -- fila -------------------------------------------------------------
    def enqueue(self, bssid: str, ssid: Optional[str] = None, channel: Optional[int] = None,
                capture_path: Optional[str] = None, hash_path: Optional[str] = None,
                note: Optional[str] = None) -> Optional[int]:
        """Insere um alvo. Devolve o id, ou None se ja existia essa captura."""
        bssid = normalize_bssid(bssid) or bssid
        ts = now_iso()
        cur = self.conn.execute(
            """INSERT INTO targets (bssid, ssid, channel, capture_path, hash_path,
                                    status, note, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (bssid, IFNULL(capture_path, '')) DO NOTHING""",
            (bssid, ssid, channel, capture_path, hash_path, STATUS_PENDING, note, ts, ts),
        )
        if cur.rowcount == 0:
            return None
        target_id = cur.lastrowid
        self.log_event("info", f"enfileirado: {ssid or bssid}", target_id)
        return target_id

    def claim_next(self) -> Optional[Target]:
        """Pega o proximo alvo pendente e o marca como 'cracking'.

        Atomico: usa BEGIN IMMEDIATE para que dois workers concorrentes nunca
        recebam o mesmo alvo.
        """
        conn = self.conn
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM targets WHERE status = ? ORDER BY id LIMIT 1",
                (STATUS_PENDING,),
            ).fetchone()
            if row is None:
                conn.execute("COMMIT")
                return None
            conn.execute(
                "UPDATE targets SET status = ?, updated_at = ? WHERE id = ?",
                (STATUS_CRACKING, now_iso(), row["id"]),
            )
            conn.execute("COMMIT")
            target = Target.from_row(row)
            target.status = STATUS_CRACKING
            return target
        except sqlite3.Error:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    def set_status(self, target_id: int, status: str, *, password: Optional[str] = None,
                   method: Optional[str] = None, note: Optional[str] = None,
                   bump_attempts: bool = False) -> None:
        if status not in ALL_STATUSES:
            raise ValueError(f"status invalido: {status}")
        sets = ["status = ?", "updated_at = ?"]
        args: List[Any] = [status, now_iso()]
        if password is not None:
            sets.append("password = ?")
            args.append(password)
        if method is not None:
            sets.append("method = ?")
            args.append(method)
        if note is not None:
            sets.append("note = ?")
            args.append(note)
        if bump_attempts:
            sets.append("attempts = attempts + 1")
        args.append(target_id)
        self.conn.execute(f"UPDATE targets SET {', '.join(sets)} WHERE id = ?", args)

    def mark_found(self, target_id: int, password: str, method: str) -> None:
        self.set_status(target_id, STATUS_FOUND, password=password, method=method,
                        note=None, bump_attempts=True)
        # Higiene: o evento registra o fato, nunca a senha em claro.
        self.log_event("success", f"senha encontrada via {method}", target_id)

    # -- consultas --------------------------------------------------------
    def get(self, target_id: int) -> Optional[Target]:
        row = self.conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        return Target.from_row(row) if row else None

    def find_by_bssid(self, bssid: str) -> List[Target]:
        norm = normalize_bssid(bssid) or bssid
        rows = self.conn.execute(
            "SELECT * FROM targets WHERE bssid = ? ORDER BY id DESC", (norm,)
        ).fetchall()
        return [Target.from_row(r) for r in rows]

    def list_targets(self, status: Optional[str] = None, limit: int = 500) -> List[Target]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM targets WHERE status = ? ORDER BY id LIMIT ?", (status, limit)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM targets ORDER BY id LIMIT ?", (limit,)
            ).fetchall()
        return [Target.from_row(r) for r in rows]

    def results(self) -> List[Target]:
        rows = self.conn.execute(
            "SELECT * FROM targets WHERE status = ? AND password IS NOT NULL ORDER BY updated_at DESC",
            (STATUS_FOUND,),
        ).fetchall()
        return [Target.from_row(r) for r in rows]

    def known_password(self, ssid: Optional[str], bssid: Optional[str]) -> Optional[str]:
        """Senha ja descoberta para esta rede, em qualquer captura anterior.

        Melhoria central do pipeline: se a rede ja foi quebrada, nao gastamos
        CPU quebrando de novo -- pulamos direto para o resultado.
        """
        norm = normalize_bssid(bssid) if bssid else None
        row = None
        if norm:
            row = self.conn.execute(
                """SELECT password FROM targets
                   WHERE bssid = ? AND status = ? AND password IS NOT NULL
                   ORDER BY updated_at DESC LIMIT 1""",
                (norm, STATUS_FOUND),
            ).fetchone()
        if row is None and ssid:
            row = self.conn.execute(
                """SELECT password FROM targets
                   WHERE ssid = ? AND status = ? AND password IS NOT NULL
                   ORDER BY updated_at DESC LIMIT 1""",
                (ssid, STATUS_FOUND),
            ).fetchone()
        return row["password"] if row else None

    def counts(self) -> Dict[str, int]:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) AS n FROM targets GROUP BY status"
        ).fetchall()
        out = {s: 0 for s in ALL_STATUSES}
        for r in rows:
            out[r["status"]] = r["n"]
        out["total"] = sum(out[s] for s in ALL_STATUSES)
        return out

    def reset_stuck(self) -> int:
        """Devolve para 'pending' alvos presos em 'cracking'.

        Acontece quando um worker morre (Ctrl+C, queda de energia) no meio da
        quebra. Sem isso, o alvo ficaria travado para sempre.
        """
        cur = self.conn.execute(
            "UPDATE targets SET status = ?, updated_at = ?, note = ? WHERE status = ?",
            (STATUS_PENDING, now_iso(), "devolvido a fila (worker interrompido)", STATUS_CRACKING),
        )
        return cur.rowcount

    # -- segunda captura da mesma rede ------------------------------------
    def requeue_exhausted(self) -> int:
        cur = self.conn.execute(
            "UPDATE targets SET status = ?, updated_at = ? WHERE status = ?",
            (STATUS_PENDING, now_iso(), STATUS_EXHAUSTED),
        )
        return cur.rowcount

    # -- eventos ----------------------------------------------------------
    def log_event(self, level: str, message: str, target_id: Optional[int] = None) -> None:
        self.conn.execute(
            "INSERT INTO events (ts, level, target_id, message) VALUES (?, ?, ?, ?)",
            (now_iso(), level, target_id, message),
        )

    def recent_events(self, limit: int = 20) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    # -- import / export --------------------------------------------------
    def export_results(self, path: Path, fmt: str = "auto") -> Path:
        """Grava os resultados. Formatos: json, csv, txt (ssid:senha) ou wifite."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        rows = self.results()
        if fmt == "auto":
            fmt = {".json": "json", ".csv": "csv"}.get(path.suffix.lower(), "txt")

        if fmt == "json":
            payload = [
                {
                    "ssid": r.ssid, "bssid": r.bssid, "password": r.password,
                    "method": r.method, "channel": r.channel,
                    "capture": r.capture_path, "found_at": r.updated_at,
                }
                for r in rows
            ]
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt == "csv":
            with path.open("w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["ssid", "bssid", "password", "method", "found_at"])
                for r in rows:
                    w.writerow([r.ssid or "", r.bssid, r.password, r.method or "", r.updated_at])
        elif fmt == "wifite":
            # Espelha o formato tabular do cracked.txt do wifite, para
            # interoperabilidade com `wifite --cracked`.
            lines = [f"{'BSSID':<18} {'ESSID':<24} PSK"]
            for r in rows:
                lines.append(f"{r.bssid:<18} {(r.ssid or ''):<24} {r.password}")
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        else:  # txt
            lines = [f"{r.ssid or r.bssid}:{r.password}" for r in rows]
            path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return path

    def import_results(self, path: Path) -> ImportReport:
        """Importa senhas ja conhecidas de arquivos externos.

        Aceita, em ordem de tentativa:
          1. JSON  -- lista de objetos (formato nativo de `wp export`)
          2. CSV   -- cabecalho ssid,bssid,password,...
          3. texto -- "ssid:senha" ou "bssid:senha" por linha
          4. wifite -- tabela colunar do cracked.txt (BSSID ESSID PSK)
        """
        report = ImportReport()
        path = Path(path)
        if not path.is_file():
            report.errors.append(f"arquivo nao encontrado: {path}")
            return report

        text = path.read_text(encoding="utf-8", errors="replace")
        records = self._parse_import(path, text, report)
        for rec in records:
            self._apply_import(rec, report)
        return report

    def _parse_import(self, path: Path, text: str, report: ImportReport) -> List[dict]:
        suffix = path.suffix.lower()
        stripped = text.lstrip()

        # 1) JSON
        if suffix == ".json" or stripped.startswith("[") or stripped.startswith("{"):
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    data = [data]
                return [d for d in data if isinstance(d, dict)]
            except ValueError as exc:
                report.errors.append(f"JSON invalido: {exc}")

        # 2) CSV com cabecalho
        first_line = text.splitlines()[0] if text.splitlines() else ""
        if suffix == ".csv" or ("ssid" in first_line.lower() and "," in first_line):
            out = []
            for row in csv.DictReader(text.splitlines()):
                low = { (k or "").strip().lower(): (v or "").strip() for k, v in row.items() }
                if low.get("password") or low.get("psk") or low.get("senha"):
                    out.append(low)
            if out:
                return out

        # 3) e 4) texto linha a linha
        out = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            lowered = line.lower()
            if lowered.startswith("bssid") and "psk" in lowered:
                continue  # cabecalho da tabela do wifite
            rec = self._parse_text_line(line)
            if rec:
                out.append(rec)
        return out

    @staticmethod
    def _parse_text_line(line: str) -> Optional[dict]:
        """Interpreta uma linha de texto em {ssid, bssid, password}.

        A ORDEM das tentativas importa. A tabela vem primeiro porque o BSSID
        contem ':': se testassemos "chave:valor" antes, o `rpartition` cortaria
        o ultimo dois-pontos DENTRO do BSSID e destruiria a linha inteira.
        """
        # 1) Tabela do wifite: MAC, 2+ espacos, ESSID, 2+ espacos, PSK.
        m = _TABLE_RE.match(line)
        if m:
            return {"bssid": m.group(1), "essid": m.group(2).strip(), "password": m.group(3)}

        # 2) "chave:valor" pelo ULTIMO dois-pontos -- cobre "Rede:senha" e
        #    tambem "AA:BB:CC:DD:EE:FF:senha".
        if ":" in line:
            head, _, tail = line.rpartition(":")
            head, tail = head.strip(), tail.strip()
            if head and tail:
                if MAC_RE.match(head):
                    return {"bssid": head, "password": tail}
                return {"ssid": head, "password": tail}

        # 3) Colunas separadas apenas por espaco simples.
        parts = line.split()
        if len(parts) >= 3 and MAC_RE.match(parts[0]):
            return {"bssid": parts[0], "ssid": " ".join(parts[1:-1]), "password": parts[-1]}
        if len(parts) == 2:
            if MAC_RE.match(parts[0]):
                return {"bssid": parts[0], "password": parts[1]}
            return {"ssid": parts[0], "password": parts[1]}
        return None

    def _apply_import(self, rec: dict, report: ImportReport) -> None:
        ssid = (rec.get("ssid") or rec.get("essid") or "").strip() or None
        bssid = normalize_bssid(rec.get("bssid") or rec.get("mac"))
        password = rec.get("password") or rec.get("psk") or rec.get("senha") or ""
        password = str(password).strip()
        method = (rec.get("method") or "import").strip()

        if not password:
            report.skipped += 1
            return
        if not bssid and not ssid:
            report.errors.append("registro sem ssid e sem bssid")
            return

        # Sem BSSID: procuramos um alvo existente com o mesmo SSID.
        if not bssid:
            row = self.conn.execute(
                "SELECT id, status FROM targets WHERE ssid = ? ORDER BY id DESC LIMIT 1", (ssid,)
            ).fetchone()
            if row:
                self.set_status(row["id"], STATUS_FOUND, password=password, method=method)
                report.updated += 1
            else:
                # BSSID sintetico derivado do SSID: sem isso, dois SSIDs
                # diferentes sem BSSID colidiriam no indice unico.
                self._insert_imported(ssid, pseudo_bssid(ssid or ""), password, method)
                report.added += 1
            return

        rows = self.conn.execute("SELECT id, status FROM targets WHERE bssid = ?", (bssid,)).fetchall()
        if not rows:
            self._insert_imported(ssid, bssid, password, method)
            report.added += 1
            return

        changed = False
        for row in rows:
            if row["status"] != STATUS_FOUND:
                self.set_status(row["id"], STATUS_FOUND, password=password, method=method)
                changed = True
        report.updated += 1 if changed else 0
        report.skipped += 0 if changed else 1

    def _insert_imported(self, ssid: Optional[str], bssid: str, password: str, method: str) -> None:
        ts = now_iso()
        self.conn.execute(
            """INSERT INTO targets (bssid, ssid, status, password, method, note,
                                    created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (bssid, ssid, STATUS_FOUND, password, method, "importado de arquivo externo", ts, ts),
        )


def open_state(settings) -> State:  # pragma: no cover - conveniencia
    settings.ensure_dirs()
    return State(settings.db_path)
