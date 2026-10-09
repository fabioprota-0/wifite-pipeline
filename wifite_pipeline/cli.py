"""Interface de linha de comando: `wp <comando>`.

Comandos:
    run       sobe os 4 paineis do tmux (o uso normal)
    crack     o motor: vigia capturas e quebra (painel 2)
    watch     apenas vigia e enfileira
    queue     mostra a fila (painel 3)
    results   mostra as senhas encontradas (painel 4)
    import    traz senhas ja conhecidas de um arquivo
    export    grava os resultados
    connect   conecta numa rede ja quebrada pelo segundo adaptador
    doctor    diagnostico do ambiente
    config    mostra ou cria o arquivo de configuracao
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__, connector, tui
from . import capture as capture_mod
from .config import (
    CONFIG_FILE,
    TOOLS,
    Settings,
    find_tool,
    is_compressed,
    missing_required_tools,
    resolve_wordlist,
)
from .cracker import Cracker
from .state import STATUS_EXHAUSTED, State
from .tmux_layout import build_panes, launch, print_manual_layout, tmux_available
from .watcher import Watcher

AUTH_HELP = (
    "Confirma que voce tem autorizacao por escrito para testar as redes alvo. "
    "Sem isso os comandos de ataque se recusam a iniciar."
)


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
def build_settings(args: argparse.Namespace) -> Settings:
    settings = Settings.load(Path(args.config) if getattr(args, "config", None) else None)

    if getattr(args, "state_dir", None):
        settings.state_dir = args.state_dir
    if getattr(args, "wordlist", None):
        # Wordlist explicita entra na frente de todas as outras.
        settings.wordlists = [args.wordlist] + [
            w for w in settings.wordlists if w != args.wordlist
        ]
    if getattr(args, "watch_dir", None):
        settings.watch_dirs = list(args.watch_dir)
    if getattr(args, "capture_interface", None):
        settings.capture_interface = args.capture_interface
    if getattr(args, "connect_interface", None):
        settings.connect_interface = args.connect_interface
    if getattr(args, "auto_connect", False):
        settings.auto_connect = True
    if getattr(args, "engine", None):
        settings.cracker_engine = args.engine
    if getattr(args, "mask_fallback", False):
        settings.mask_fallback = True
    if getattr(args, "tmux_session", None):
        settings.tmux_session = args.tmux_session
    if getattr(args, "i_have_authorization", False):
        settings.authorized_use_acknowledged = True

    # Atributo dinamico: nao e campo do dataclass, entao nao vai para o arquivo
    # de configuracao nem para o `wp config`. Serve de canal entre quem cria os
    # diretorios e quem decide se o problema e fatal.
    settings.dir_problems = settings.ensure_dirs()
    return settings


def open_state(settings: Settings) -> State:
    problems = getattr(settings, "dir_problems", [])
    if problems:
        print(tui.paint("nao consigo usar o diretorio de estado:", tui.C.RED))
        for p in problems:
            print(f"  {p}")
        print(tui.paint("\n  Aponte para um lugar gravavel com --state-dir CAMINHO.",
                        tui.C.GREY))
        raise SystemExit(2)
    try:
        return State(settings.db_path)
    except OSError as exc:
        print(tui.paint(f"falha ao abrir o banco {settings.db_path}: {exc}", tui.C.RED))
        print(tui.paint("  Use --state-dir CAMINHO para escolher outro lugar.", tui.C.GREY))
        raise SystemExit(2) from exc


def export_all(settings: Settings, state: State) -> list[Path]:
    """Regrava os tres formatos de resultado. Barato o bastante para cada achado."""
    written = []
    written.append(state.export_results(settings.results_dir / "cracked.txt", "txt"))
    written.append(state.export_results(settings.results_dir / "cracked.json", "json"))
    written.append(state.export_results(settings.results_dir / "cracked.csv", "csv"))
    return written


def require_authorization(settings: Settings) -> bool:
    if settings.authorized_use_acknowledged:
        return True
    print(tui.paint("BLOQUEADO: uso autorizado nao confirmado.", tui.C.RED, tui.C.BOLD))
    print()
    print("  Este pipeline captura handshakes, quebra senhas e entra na rede.")
    print("  Isso e crime quando feito sem autorizacao por escrito, mesmo que")
    print("  voce nao consiga entrar.")
    print()
    print("  Use apenas em: redes proprias, laboratorios (TryHackMe, HTB,")
    print("  VulnHub) ou engajamentos com contrato assinado.")
    print()
    print(f"  Para confirmar:  wp {sys.argv[1] if len(sys.argv) > 1 else 'run'} "
          "--i-have-authorization")
    print(f"  Ou defina \"authorized_use_acknowledged\": true em {CONFIG_FILE}")
    return False


# ---------------------------------------------------------------------------
# Comandos
# ---------------------------------------------------------------------------
def cmd_doctor(args: argparse.Namespace) -> int:
    settings = build_settings(args)
    ok = True

    print(tui.banner() + "\n")
    print(tui.paint("FERRAMENTAS", tui.C.BOLD))
    for name, meta in TOOLS.items():
        path = find_tool(name)
        required = bool(meta["required"])
        if path:
            mark = tui.paint("OK  ", tui.C.GREEN)
            detail = path
        elif required:
            mark = tui.paint("FALTA", tui.C.RED)
            detail = f"obrigatoria -- sudo apt install {meta['apt']}"
            ok = False
        else:
            mark = tui.paint("--  ", tui.C.GREY)
            detail = f"opcional ({meta['why']})"
        print(f"  [{mark}] {name:<14} {detail}")

    print("\n" + tui.paint("ADAPTADORES", tui.C.BOLD))
    interfaces = connector.list_interfaces()
    if not interfaces:
        print(tui.paint("  nenhum adaptador sem fio detectado", tui.C.RED))
        ok = False
    for iface in interfaces:
        state = connector.interface_state(iface)
        print(f"  {iface:<12} modo: {state}")
    if not interfaces:
        print(tui.paint("  Dica: em VM, passe o adaptador USB para o guest "
                        "(Dispositivos -> USB).", tui.C.GREY))

    print("\n" + tui.paint("PAPEIS", tui.C.BOLD))
    problems = connector.validate_second_adapter(settings.capture_interface,
                                                 settings.connect_interface)
    if settings.connect_interface:
        for p in problems:
            print(f"  {tui.paint('!', tui.C.YELLOW)} {p}")
    else:
        print(tui.paint("  conexao automatica desabilitada "
                        "(defina --connect-interface para habilitar)", tui.C.GREY))

    print("\n" + tui.paint("WORDLISTS", tui.C.BOLD))
    existing = settings.existing_wordlists()
    comprimidas = settings.compressed_wordlists()
    if not existing and not comprimidas:
        print(tui.paint("  nenhuma wordlist encontrada", tui.C.RED))
        print(tui.paint("  Instale o SecLists: sudo apt install seclists", tui.C.GREY))
    for w in settings.wordlists:
        if not Path(w).is_file():
            mark = tui.paint("--  ", tui.C.GREY)
        elif is_compressed(w):
            mark = tui.paint("GZ  ", tui.C.YELLOW)
        else:
            mark = tui.paint("OK  ", tui.C.GREEN)
        print(f"  [{mark}] {w}")
    if comprimidas:
        print(tui.paint("\n  Comprimidas sao IGNORADAS na quebra: o hashcat nao le .gz.", tui.C.YELLOW))
        for w in comprimidas:
            print(tui.paint(f"    para usar:  sudo gunzip -k {w}", tui.C.CYAN))

    print("\n" + tui.paint("DIRETORIOS VIGIADOS", tui.C.BOLD))
    for d in settings.watch_dirs:
        exists = Path(d).is_dir()
        mark = tui.paint("OK  ", tui.C.GREEN) if exists else tui.paint("--  ", tui.C.GREY)
        print(f"  [{mark}] {d}")

    print("\n" + tui.paint("ESTADO", tui.C.BOLD))
    dir_problems = getattr(settings, "dir_problems", [])
    if dir_problems:
        ok = False
        for problem in dir_problems:
            print(f"  {tui.paint('!', tui.C.RED)} nao consegui criar: {problem}")
        print(tui.paint("     aponte para um lugar gravavel com --state-dir CAMINHO",
                        tui.C.GREY))
    else:
        print(f"  [{tui.paint('OK  ', tui.C.GREEN)}] {settings.state_path} (gravavel)")
    print(f"  banco     : {settings.db_path}")
    print(f"  resultados: {settings.results_dir}")
    print(f"  tmux      : {'disponivel' if tmux_available() else 'AUSENTE (apt install tmux)'}")

    print()
    print(tui.paint("Ambiente pronto." if ok else "Corrija os itens em vermelho antes de atacar.",
                    tui.C.GREEN if ok else tui.C.YELLOW))
    return 0 if ok else 1


def cmd_watch(args: argparse.Namespace) -> int:
    settings = build_settings(args)
    state = open_state(settings)
    state.reset_stuck()
    watcher = Watcher(settings, state, verbose=args.verbose)
    if args.once:
        added = watcher.scan_once()
        print(f"{len(added)} alvo(s) enfileirado(s)")
        return 0
    watcher.run_forever(interval=args.interval)
    return 0


def _process_target(target, settings: Settings, state: State, cracker: Cracker,
                    verbose: bool, do_connect: bool) -> None:
    """O ciclo de um alvo: converter -> quebrar -> registrar -> (conectar)."""
    label = target.ssid or target.bssid
    print(f"\n>>> #{target.id} {label} ({target.bssid})")

    capture_path = Path(target.capture_path) if target.capture_path else None
    hash_path = capture_mod.to_22000(capture_path, settings.state_path / "hashes") \
        if capture_path else None
    if hash_path:
        print(f"    hash: {hash_path.name}")
    elif capture_path and capture_path.suffix.lower() not in capture_mod.HASH_SUFFIXES:
        print(tui.paint("    aviso: sem hcxpcapngtool -- vou usar o aircrack direto no .cap",
                        tui.C.YELLOW))

    cracker.engine = Cracker._resolve_engine(settings.cracker_engine)
    result = cracker.crack(
        hash_path=hash_path, wordlists=settings.existing_wordlists(),
        cap_path=capture_path, bssid=target.bssid, essid=target.ssid,
    )

    if result.found and result.password:
        state.mark_found(target.id, result.password, result.method or result.engine or "?")
        export_all(settings, state)
        print(tui.paint(f"    SENHA: {result.password}", tui.C.GREEN, tui.C.BOLD)
              + tui.paint(f"   ({result.engine}, {result.elapsed:.0f}s)", tui.C.GREY))
        if settings.notify:
            tui.notify_desktop("wifite-pipeline", f"{label}: {result.password}")
        if do_connect and settings.connect_interface:
            conn = connector.connect(target.ssid or "", result.password,
                                     settings.connect_interface,
                                     profile=f"{settings.connection_prefix}-{target.id}")
            if conn.ok:
                print(tui.paint(f"    conectado em {conn.interface} (IP {conn.ip_address})",
                                tui.C.GREEN))
            else:
                print(tui.paint(f"    falha ao conectar: {conn.detail}", tui.C.YELLOW))
        elif do_connect:
            print(tui.paint("    conexao automatica pedida, mas --connect-interface "
                            "nao foi definido", tui.C.YELLOW))
    else:
        state.set_status(target.id, STATUS_EXHAUSTED, note=result.detail, bump_attempts=True)
        print(tui.paint(f"    esgotada: {result.detail}", tui.C.RED))


def cmd_crack(args: argparse.Namespace) -> int:
    """O motor: vigia capturas novas e quebra cada uma."""
    settings = build_settings(args)
    if not require_authorization(settings):
        return 2
    if missing_required_tools():
        print(tui.paint(f"ferramentas obrigatorias ausentes: {', '.join(missing_required_tools())}",
                        tui.C.RED))
        return 1

    state = open_state(settings)
    freed = state.reset_stuck()
    if freed:
        print(f"{freed} alvo(s) presos em 'quebrando' devolvidos a fila")

    if not settings.existing_wordlists():
        print(tui.paint("nenhuma wordlist valida. Use --wordlist CAMINHO ou instale o seclists.",
                        tui.C.RED))
        for w in settings.compressed_wordlists():
            print(tui.paint(f"  {w} existe, mas esta comprimida: sudo gunzip -k {w}", tui.C.YELLOW))
        return 1

    cracker = Cracker(
        engine=settings.cracker_engine,
        potfile=settings.state_path / "hashcat.potfile",
        rules=settings.hashcat_rules,
        timeout=settings.crack_timeout,
        mask_fallback=settings.mask_fallback,
        verbose=args.verbose,
    )
    print(tui.banner())
    print(f"  motor de quebra : {cracker.engine}")
    print(f"  wordlists       : {len(settings.existing_wordlists())}")
    print(f"  conexao automatica: {'ligada em ' + str(settings.connect_interface) if settings.auto_connect and settings.connect_interface else 'desligada'}")
    print()

    watcher = Watcher(settings, state, verbose=args.verbose)
    do_connect = settings.auto_connect and bool(settings.connect_interface)

    while True:
        watcher.scan_once()
        target = state.claim_next()
        if target is None:
            if args.once:
                print("fila vazia")
                return 0
            if settings.retry_exhausted and settings.retry_exhausted:
                state.requeue_exhausted()
            time.sleep(args.interval)
            continue
        try:
            _process_target(target, settings, state, cracker, args.verbose, do_connect)
        except Exception as exc:                      # um alvo ruim nao mata o worker
            state.set_status(target.id, "error", note=str(exc))
            print(tui.paint(f"    erro: {exc}", tui.C.MAGENTA))
        if args.once:
            return 0


def cmd_queue(args: argparse.Namespace) -> int:
    settings = build_settings(args)
    state = open_state(settings)
    if args.live:
        tui.live_loop(lambda: tui.queue_view(state, limit=args.limit), interval=args.interval)
        return 0
    print(tui.banner() + "\n")
    print(tui.queue_view(state, limit=args.limit))
    return 0


def cmd_results(args: argparse.Namespace) -> int:
    settings = build_settings(args)
    state = open_state(settings)
    if args.export:
        paths = [state.export_results(Path(args.export),
                                      "auto" if args.format == "auto" else args.format)]
        for p in paths:
            print(f"gravado: {p}")
        return 0
    if args.live:
        tui.live_loop(lambda: tui.results_view(state, limit=args.limit), interval=args.interval)
        return 0
    print(tui.banner() + "\n")
    print(tui.results_view(state, limit=args.limit))
    print()
    print(tui.events_view(state, limit=10))
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    settings = build_settings(args)
    state = open_state(settings)
    report = state.import_results(Path(args.file))
    print(f"importado de {args.file}: {report.summary()}")
    for err in report.errors[:10]:
        print(tui.paint(f"  ! {err}", tui.C.YELLOW))
    export_all(settings, state)
    print(f"resultados atualizados em {settings.results_dir}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    settings = build_settings(args)
    state = open_state(settings)
    path = state.export_results(Path(args.file), "auto" if args.format == "auto" else args.format)
    print(f"gravado: {path}  ({len(state.results())} senha(s))")
    return 0


def cmd_connect(args: argparse.Namespace) -> int:
    settings = build_settings(args)
    state = open_state(settings)

    ssid, password = args.ssid, args.password
    if args.target_id is not None:
        target = state.get(args.target_id)
        if not target:
            print(f"alvo #{args.target_id} nao existe")
            return 1
        ssid, password = target.ssid, target.password
        if not password:
            print(f"alvo #{args.target_id} ainda nao tem senha")
            return 1
    if not ssid or not password:
        # Sem argumentos: pega o ultimo achado.
        found = state.results()
        if not found:
            print("nenhuma senha no banco ainda; informe --ssid e --password")
            return 1
        ssid, password = found[0].ssid, found[0].password

    iface = settings.connect_interface
    if not iface:
        interfaces = connector.list_interfaces()
        candidates = [i for i in interfaces if i != settings.capture_interface]
        if not candidates:
            print("nenhum adaptador disponivel para conectar "
                  "(use --connect-interface)")
            return 1
        iface = candidates[0]
        print(f"usando {iface} (defina --connect-interface para fixar)")

    result = connector.connect(ssid or "", password, iface)
    if result.ok:
        print(tui.paint(f"conectado a {ssid} por {result.interface} "
                        f"(IP {result.ip_address}, perfil {result.profile})", tui.C.GREEN))
        return 0
    print(tui.paint(f"falhou: {result.detail}", tui.C.RED))
    return 1


def cmd_run(args: argparse.Namespace) -> int:
    settings = build_settings(args)
    if not require_authorization(settings):
        return 2

    extra = " ".join(args.wifite_args) if args.wifite_args else ""
    if settings.capture_interface:
        extra = f"-i {settings.capture_interface} {extra}".strip()
    if args.dual_interface:
        extra = f"--dual-interface {extra}".strip()

    wordlist = resolve_wordlist(args.wordlist, settings)
    if args.wordlist and wordlist is None:
        motivo = "esta comprimida" if is_compressed(args.wordlist) else "nao existe"
        print(tui.paint(f"aviso: a wordlist {args.wordlist} {motivo}.", tui.C.YELLOW))
        if is_compressed(args.wordlist):
            print(tui.paint(f"  descompacte com: sudo gunzip -k {args.wordlist}", tui.C.GREY))
    panes = build_panes(settings, wifite_args=extra, wordlist=wordlist)
    if args.no_tmux:
        print_manual_layout(panes)
        return 0
    return launch(settings, panes, attach=not args.detached,
                  recreate=args.recreate, workdir=str(Path.cwd()))


def cmd_config(args: argparse.Namespace) -> int:
    settings = build_settings(args)
    if args.init:
        path = settings.save()
        print(f"configuracao gravada em {path}")
        return 0
    print(f"arquivo : {CONFIG_FILE}  ({'existe' if CONFIG_FILE.is_file() else 'nao existe, usando padroes'})")
    print(f"banco   : {settings.db_path}")
    print()
    for key, value in settings.to_dict().items():
        print(f"  {key:<32} {value}")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="arquivo de configuracao (JSON)")
    parser.add_argument("--state-dir", help="onde guardar banco e resultados")
    parser.add_argument("-v", "--verbose", action="store_true", help="saida detalhada")


def add_attack_opts(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-w", "--wordlist", help="wordlist a usar (tem prioridade sobre a lista)")
    parser.add_argument("--watch-dir", action="append", help="diretorio a vigiar (repetivel)")
    parser.add_argument("--capture-interface", help="adaptador do wifite (modo monitor)")
    parser.add_argument("--connect-interface", help="adaptador para conectar (modo gerenciado)")
    parser.add_argument("--auto-connect", action="store_true",
                        help="conectar automaticamente assim que a senha sair")
    parser.add_argument("--engine", choices=["auto", "hashcat", "aircrack"], default=None,
                        help="motor de quebra (padrao: auto)")
    parser.add_argument("--mask-fallback", action="store_true",
                        help="tentar mascara de 8 digitos apos as wordlists")
    parser.add_argument("--i-have-authorization", action="store_true", help=AUTH_HELP)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wp",
        description="wifite-pipeline: captura, quebra, registra e conecta -- em paralelo.",
        epilog="Use `wp doctor` para checar o ambiente antes de comecar.",
    )
    p.add_argument("--version", action="version", version=f"wifite-pipeline {__version__}")
    sub = p.add_subparsers(dest="command")

    pr = sub.add_parser("run", help="sobe os 4 paineis do tmux (uso normal)")
    add_common(pr)
    add_attack_opts(pr)
    pr.add_argument("--no-tmux", action="store_true", help="em vez do tmux, imprime 4 comandos")
    pr.add_argument("--detached", action="store_true", help="nao anexar a sessao tmux")
    pr.add_argument("--recreate", action="store_true", help="recriar a sessao se ja existir")
    pr.add_argument("--tmux-session", help="nome da sessao tmux (padrao: wp)")
    pr.add_argument("--dual-interface", action="store_true",
                    help="repassar --dual-interface ao wifite")
    pr.add_argument("wifite_args", nargs="*", help="argumentos extras repassados ao wifite")
    pr.set_defaults(func=cmd_run)

    pk = sub.add_parser("crack", help="motor: vigia capturas e quebra (painel 2)")
    add_common(pk)
    add_attack_opts(pk)
    pk.add_argument("--loop", action="store_true", help="rodar continuamente")
    pk.add_argument("--once", action="store_true", help="processar a fila e sair")
    pk.add_argument("--interval", type=float, default=2.0, help="intervalo de varredura")
    pk.set_defaults(func=cmd_crack)

    pw = sub.add_parser("watch", help="apenas vigiar capturas e enfileirar")
    add_common(pw)
    add_attack_opts(pw)
    pw.add_argument("--once", action="store_true", help="uma varredura e sai")
    pw.add_argument("--interval", type=float, default=None)
    pw.set_defaults(func=cmd_watch)

    pq = sub.add_parser("queue", help="mostra a fila (painel 3)")
    add_common(pq)
    pq.add_argument("--live", action="store_true")
    pq.add_argument("--interval", type=float, default=2.0)
    pq.add_argument("--limit", type=int, default=25)
    pq.set_defaults(func=cmd_queue)

    ps = sub.add_parser("results", help="mostra as senhas encontradas (painel 4)")
    add_common(ps)
    ps.add_argument("--live", action="store_true")
    ps.add_argument("--interval", type=float, default=3.0)
    ps.add_argument("--limit", type=int, default=40)
    ps.add_argument("--export", help="gravar em arquivo em vez de mostrar")
    ps.add_argument("--format", default="auto", choices=["auto", "txt", "json", "csv", "wifite"])
    ps.set_defaults(func=cmd_results)

    pi = sub.add_parser("import", help="importar senhas ja conhecidas")
    add_common(pi)
    pi.add_argument("file", help=".json, .csv, 'ssid:senha' por linha, ou cracked.txt do wifite")
    pi.set_defaults(func=cmd_import)

    pe = sub.add_parser("export", help="gravar os resultados")
    add_common(pe)
    pe.add_argument("file")
    pe.add_argument("--format", default="auto", choices=["auto", "txt", "json", "csv", "wifite"])
    pe.set_defaults(func=cmd_export)

    pc = sub.add_parser("connect", help="conectar numa rede ja quebrada")
    add_common(pc)
    pc.add_argument("--ssid")
    pc.add_argument("--password")
    pc.add_argument("--target-id", type=int)
    pc.add_argument("--capture-interface")
    pc.add_argument("--connect-interface")
    pc.set_defaults(func=cmd_connect)

    pd = sub.add_parser("doctor", help="diagnostico do ambiente")
    add_common(pd)
    add_attack_opts(pd)
    pd.set_defaults(func=cmd_doctor)

    pf = sub.add_parser("config", help="mostrar ou criar a configuracao")
    add_common(pf)
    pf.add_argument("--init", action="store_true", help="gravar os padroes em disco")
    pf.set_defaults(func=cmd_config)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        print()
        print("Comece por:  wp doctor")
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrompido pelo usuario")
        return 130


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())
