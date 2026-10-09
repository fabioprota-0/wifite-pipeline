#!/usr/bin/env bash
# Instalador do wifite-pipeline para Kali Linux / Debian.
#
#   sudo bash scripts/install.sh
#
# Instala as ferramentas de sistema que o pipeline orquestra e coloca o comando
# `wp` no PATH. Nao instala nada via pip: o projeto usa apenas a biblioteca
# padrao, entao nao ha ambiente virtual nem dependencia de terceiros.
set -euo pipefail

BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; OFF=$'\033[0m'
say()  { printf '%s\n' "${BOLD}==>${OFF} $*"; }
ok()   { printf '%s\n' "  ${GREEN}OK${OFF}   $*"; }
warn() { printf '%s\n' "  ${YELLOW}!!${OFF}   $*"; }
die()  { printf '%s\n' "  ${RED}ERRO${OFF} $*" >&2; exit 1; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WP_LAUNCHER="$REPO_DIR/bin/wp"

# ---------------------------------------------------------------------------
say "Verificando o sistema"
[[ $EUID -eq 0 ]] || die "rode com sudo: sudo bash scripts/install.sh"
command -v apt-get >/dev/null || die "este instalador assume apt (Kali/Debian)"
[[ -f "$WP_LAUNCHER" ]] || die "nao encontrei $WP_LAUNCHER -- rode o script de dentro do repositorio"
ok "apt disponivel"
ok "repositorio em $REPO_DIR"

# ---------------------------------------------------------------------------
# Obrigatorias: sem elas o pipeline nao captura nem quebra.
REQUIRED=(wifite aircrack-ng)
# Recomendadas: habilitam o caminho rapido (hashcat) e a conexao automatica.
RECOMMENDED=(hashcat hcxtools network-manager tmux)
# Extras que melhoram deteccao de handshake e fornecem wordlists.
EXTRAS=(tshark seclists iw)

say "Instalando obrigatorias: ${REQUIRED[*]}"
apt-get update -qq
apt-get install -y --no-install-recommends "${REQUIRED[@]}"
ok "obrigatorias instaladas"

say "Instalando recomendadas: ${RECOMMENDED[*]}"
apt-get install -y --no-install-recommends "${RECOMMENDED[@]}" \
  || warn "alguma recomendada falhou; o pipeline cai para o aircrack-ng"

say "Instalando extras: ${EXTRAS[*]}"
apt-get install -y --no-install-recommends "${EXTRAS[@]}" \
  || warn "algum extra falhou; nao e bloqueante"

# ---------------------------------------------------------------------------
say "Instalando o comando \`wp\`"
#
# Por que um wrapper em /usr/local/bin, e nao `pip install`:
#
#   1. `sudo wp ...` precisa funcionar. O sudo usa um PATH proprio
#      (secure_path), que NAO inclui ~/.local/bin -- onde o pipx instala.
#      /usr/local/bin esta nesse PATH.
#   2. O wrapper chama `bin/wp`, que ajusta o sys.path e importa o pacote
#      corretamente. Chamar `wifite_pipeline/cli.py` direto NAO funciona:
#      o modulo usa imports relativos e falha com
#      "attempted relative import with no known parent package".
#   3. O que esta no clone e o que roda: um `git pull` ja atualiza o comando.
#
cat >/usr/local/bin/wp <<EOF
#!/usr/bin/env bash
# Gerado por scripts/install.sh. Para remover: rm /usr/local/bin/wp
# Aponta para o clone em $REPO_DIR
exec python3 "$WP_LAUNCHER" "\$@"
EOF
chmod +x /usr/local/bin/wp
ok "/usr/local/bin/wp -> $WP_LAUNCHER"

# ---------------------------------------------------------------------------
say "Verificacao final"
command -v wp >/dev/null && ok "\`wp\` no PATH: $(command -v wp)" || die "\`wp\` nao foi encontrado"
wp --version >/dev/null 2>&1 && ok "o comando responde: $(wp --version)" \
  || die "o comando \`wp\` existe mas nao executou"

for t in wifite aircrack-ng hashcat hcxpcapngtool nmcli tmux iw tshark; do
  if command -v "$t" >/dev/null; then ok "$t"; else warn "$t ausente (recurso reduzido)"; fi
done

cat <<'FIM'

Proximo passo:

    sudo wp doctor

Ele confere adaptadores (inclusive se os papeis de captura e conexao sao
validos), wordlists e diretorios vigiados. Corrija o que aparecer em vermelho
antes de atacar.

Para experimentar sem hardware nenhum -- nao precisa de adaptador:

    python3 scripts/demo.py

FIM
