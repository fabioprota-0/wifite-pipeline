#!/usr/bin/env bash
# Instalador do wifite-pipeline para Kali Linux / Debian.
#
#   sudo bash scripts/install.sh
#
# Instala as ferramentas de sistema que o pipeline orquestra e coloca o comando
# `wp` no PATH. Nao instala nenhum pacote Python: o projeto usa apenas a
# biblioteca padrao, entao nao ha ambiente virtual nem `pip install` de terceiros.
set -euo pipefail

BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; GREY=$'\033[90m'; OFF=$'\033[0m'
say()  { printf '%s\n' "${BOLD}==>${OFF} $*"; }
ok()   { printf '%s\n' "  ${GREEN}OK${OFF}   $*"; }
warn() { printf '%s\n' "  ${YELLOW}!!${OFF}   $*"; }
die()  { printf '%s\n' "  ${RED}ERRO${OFF} $*" >&2; exit 1; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------------------
say "Verificando o sistema"
[[ $EUID -eq 0 ]] || die "rode com sudo: sudo bash scripts/install.sh"
command -v apt-get >/dev/null || die "este instalador assume apt (Kali/Debian)"
ok "apt disponivel"

# ---------------------------------------------------------------------------
# Obrigatorias: sem elas o pipeline nao captura nem quebra.
REQUIRED=(wifite aircrack-ng)
# Recomendadas: habilitam o caminho rapido (hashcat) e a conexao automatica.
RECOMMENDED=(hashcat hcxtools network-manager tmux)
# Extras que melhoram deteccao de handshake e wordlists.
EXTRAS=(tshark seclists iw)

say "Instalando ferramentas obrigatorias: ${REQUIRED[*]}"
apt-get update -qq
apt-get install -y --no-install-recommends "${REQUIRED[@]}"
ok "obrigatorias instaladas"

say "Instalando ferramentas recomendadas: ${RECOMMENDED[*]}"
apt-get install -y --no-install-recommends "${RECOMMENDED[@]}" || \
  warn "alguma recomendada falhou; o pipeline cai para o aircrack-ng"

say "Instalando extras: ${EXTRAS[*]}"
apt-get install -y --no-install-recommends "${EXTRAS[@]}" || \
  warn "algum extra falhou; nao e bloqueante"

# ---------------------------------------------------------------------------
say "Instalando o comando \`wp\`"
# Preferimos pipx (nao polui o Python do sistema, que na Kali e gerenciado pelo
# apt). Caindo para um wrapper em /usr/local/bin se pipx nao existir.
if command -v pipx >/dev/null; then
  pipx install --force "$REPO_DIR" >/dev/null
  ok "instalado via pipx"
else
  cat >/usr/local/bin/wp <<EOF
#!/usr/bin/env bash
# Wrapper gerado por scripts/install.sh -- roda direto da fonte, sem instalar.
exec python3 "$REPO_DIR/wifite_pipeline/cli.py" "\$@"
EOF
  chmod +x /usr/local/bin/wp
  warn "pipx ausente; criei um wrapper em /usr/local/bin/wp"
fi

# ---------------------------------------------------------------------------
say "Verificacao final"
command -v wp >/dev/null && ok "\`wp\` no PATH: $(command -v wp)" || die "\`wp\` nao foi encontrado no PATH"

for t in wifite aircrack-ng hashcat hcxpcapngtool nmcli tmux; do
  if command -v "$t" >/dev/null; then ok "$t"; else warn "$t ausente (recurso reduzido)"; fi
done

cat <<'FIM'

Proximo passo:

    wp doctor

Ele confere adaptadores (incluindo se os papeis de captura e conexao sao
validos), wordlists e diretorios vigiados. Se algo aparecer em vermelho,
corrija antes de atacar.

Para experimentar sem hardware nenhum:

    python3 scripts/demo.py

FIM
