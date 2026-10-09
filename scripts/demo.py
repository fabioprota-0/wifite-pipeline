#!/usr/bin/env python3
"""Demonstracao completa do pipeline, SEM hardware e SEM adaptador WiFi.

Serve para tres coisas:
  1. provar que a logica funciona antes de comprar/plugar qualquer coisa;
  2. servir de referencia de como cada peca se encaixa;
  3. permitir testar alteracoes sem depender de redes por perto.

O que e REAL aqui: o watcher, a fila SQLite, o cache de senhas conhecidas, a
importacao/exportacao e a renderizacao das telas.
O que e SIMULADO: apenas a quebra em si -- obviamente nao da para quebrar um
handshake falso com hashcat. O resultado e injetado no banco como se o cracker
tivesse encontrado.

Uso:
    python3 scripts/demo.py
    python3 scripts/demo.py --keep     (nao apaga a pasta no final)
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Permite rodar direto do repositorio, sem instalar.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wifite_pipeline import tui                                   # noqa: E402
from wifite_pipeline.config import Settings                        # noqa: E402
from wifite_pipeline.state import State                            # noqa: E402
from wifite_pipeline.watcher import Watcher                        # noqa: E402

# Capturas falsas: nomes no padrao que o wifite/airodump produzem.
# BSSID com HIFENS no nome do arquivo -- e assim que o airodump-ng nomeia de
# verdade (dois-pontos em nome de arquivo da problema). O parser aceita os dois.
FAKE_CAPTURES = [
    ("handshake_CasaDoRafa_AA-BB-CC-DD-EE-01-01.22000", "CasaDoRafa", "AA:BB:CC:DD:EE:01"),
    ("handshake_Escritorio_AA-BB-CC-DD-EE-02-01.22000", "Escritorio", "AA:BB:CC:DD:EE:02"),
    ("handshake_Padaria_AA-BB-CC-DD-EE-03-01.22000", "Padaria", "AA:BB:CC:DD:EE:03"),
    ("handshake_Vizinho_AA-BB-CC-DD-EE-04-01.22000", "Vizinho", "AA:BB:CC:DD:EE:04"),
]

# Senhas que "o cracker teria encontrado" -- e uma que ja sabemos de antemao,
# para demonstrar o cache (a rede nao entra na fila de quebra).
PRE_KNOWN = {"Padaria": "paoQuentinho2024"}
SIMULATED = {
    "CasaDoRafa": ("minhaSenha123", "hashcat"),
    "Escritorio": ("Corp@2024#TI", "hashcat+rules"),
    "Vizinho": None,                    # wordlists esgotadas
}


def header(title: str) -> None:
    print()
    print(tui.paint("=" * 78, tui.C.GREY))
    print(tui.paint(f"  {title}", tui.C.BOLD, tui.C.CYAN))
    print(tui.paint("=" * 78, tui.C.GREY))


def main() -> int:
    parser = argparse.ArgumentParser(description="demo do wifite-pipeline")
    parser.add_argument("--keep", action="store_true",
                        help="manter a pasta de demonstracao no final")
    parser.add_argument("--workdir",
                        help="onde criar a demonstracao (padrao: <tmp>/wifite-pipeline-demo)")
    args = parser.parse_args()

    # Nome DETERMINISTICO, nao mkdtemp: antivirus com protecao anti-ransomware
    # bloqueiam "cria pasta de nome aleatorio e escreve dentro". Alem disso, um
    # caminho fixo e mais facil de inspecionar depois.
    base = Path(args.workdir) if args.workdir else Path(tempfile.gettempdir()) / "wifite-pipeline-demo"
    shutil.rmtree(base, ignore_errors=True)
    work = base
    hs = work / "hs"
    hs.mkdir(parents=True, exist_ok=True)
    state_dir = work / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    print(tui.banner())
    print(tui.paint(f"\n  pasta de trabalho: {work}", tui.C.GREY))

    try:
        settings = Settings()
        settings.watch_dirs = [str(hs)]
        settings.state_dir = str(state_dir)
        settings.ensure_dirs()
        state = State(settings.db_path)

        # ------------------------------------------------------------------
        header("1. CRIANDO CAPTURAS FALSAS (o que o wifite teria gravado)")
        for name, essid, bssid in FAKE_CAPTURES:
            target = hs / name
            # Conteudo plausivel para um arquivo 22000 do hashcat.
            target.write_text(
                f"WPA*02*{'ab' * 16}*{bssid.replace(':', '')}*{'cd' * 16}*"
                f"{essid.encode().hex()}*{'00' * 32}*02\n",
                encoding="utf-8",
            )
            print(f"  criado: hs/{name}")
        print(tui.paint(f"\n  ({len(FAKE_CAPTURES)} arquivos)", tui.C.GREY))

        # ------------------------------------------------------------------
        header("2. IMPORTANDO UMA SENHA QUE JA CONHECEMOS")
        known_file = work / "senhas-conhecidas.txt"
        known_file.write_text("Padaria:paoQuentinho2024\n", encoding="utf-8")
        report = state.import_results(known_file)
        print(f"  {known_file.name}: {report.summary()}")
        print(tui.paint("  -> essa rede nunca vai gastar CPU sendo quebrada de novo",
                        tui.C.GREY))

        # ------------------------------------------------------------------
        header("3. O WATCHER DETECTA AS CAPTURAS")
        watcher = Watcher(settings, state, verbose=False)
        # Duas passadas: o watcher so aceita arquivo que parou de crescer.
        print("  varredura 1 (arquivos ainda 'instaveis', nada entra)...")
        added = watcher.scan_once()
        print(f"    -> {len(added)} enfileirado(s)")
        print("  varredura 2 (arquivos estaveis)...")
        added = watcher.scan_once()
        print(f"    -> {len(added)} enfileirado(s)")

        counts = state.counts()
        print(f"\n  fila: {counts['pending']} pendente(s)   "
              f"achadas direto: {counts['found']} (a que ja sabiamos)")

        # ------------------------------------------------------------------
        header("4. O CRACKER PROCESSA A FILA (quebra simulada)")
        while True:
            target = state.claim_next()
            if target is None:
                break
            label = target.ssid or target.bssid
            found = SIMULATED.get(label or "")
            if found:
                password, method = found
                state.mark_found(target.id, password, method)
                print(f"  #{target.id} {label:<14} "
                      + tui.paint(f"SENHA: {password}", tui.C.GREEN, tui.C.BOLD))
            else:
                state.set_status(target.id, "exhausted",
                                 note="4 wordlists esgotadas", bump_attempts=True)
                print(f"  #{target.id} {label:<14} "
                      + tui.paint("esgotada", tui.C.RED))

        # ------------------------------------------------------------------
        header("5. EXPORTANDO OS RESULTADOS")
        for fmt, fname in (("txt", "cracked.txt"), ("json", "cracked.json"),
                           ("csv", "cracked.csv"), ("wifite", "cracked-wifite.txt")):
            path = state.export_results(settings.results_dir / fname, fmt)
            print(f"  {fmt:<7} -> {path.relative_to(work)}")
        print()
        print(tui.paint("  conteudo de cracked.txt (SSID:senha):", tui.C.GREY))
        for line in (settings.results_dir / "cracked.txt").read_text(encoding="utf-8").splitlines():
            print(f"    {line}")

        # ------------------------------------------------------------------
        header("6. PAINEL 3 -- A FILA")
        print(tui.queue_view(state, limit=10))

        header("7. PAINEL 4 -- AS RESOLVIDAS")
        print(tui.results_view(state, limit=10))

        header("8. EVENTOS (repare: a senha nunca aparece aqui)")
        print(tui.events_view(state, limit=12))

        # ------------------------------------------------------------------
        header("9. PROVA DO CACHE: recapturar a rede ja conhecida")
        # Nova captura da Padaria (BSSID diferente, mesmo SSID).
        new_cap = hs / "handshake_Padaria_AA-BB-CC-DD-EE-99-01.22000"
        new_cap.write_text("WPA*02*deadbeef\n", encoding="utf-8")
        watcher.scan_once()
        watcher.scan_once()
        padaria = [t for t in state.list_targets() if t.ssid == "Padaria"]
        for t in padaria:
            mark = tui.paint("PULOU A QUEBRA", tui.C.GREEN) if t.method == "cache" \
                else tui.paint(f"metodo={t.method}", tui.C.GREY)
            print(f"  #{t.id} {t.bssid}  status={t.status:<9} {mark}")
        print(tui.paint("\n  A captura nova entrou ja resolvida, sem tocar na CPU.",
                        tui.C.GREY))

        header("RESUMO")
        c = state.counts()
        print(f"  alvos totais : {c['total']}")
        print(f"  senhas       : {c['found']}")
        print(f"  esgotadas    : {c['exhausted']}")
        print(f"  resultados   : {settings.results_dir}")
        state.close()
        print()
        print(tui.paint("  Demo concluida. Nada de hardware foi necessario.",
                        tui.C.BOLD, tui.C.GREEN))
        return 0
    finally:
        if args.keep:
            print(tui.paint(f"\n  mantido em: {work}", tui.C.GREY))
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    os.environ.setdefault("WP_FORCE_COLOR", "1")
    raise SystemExit(main())
