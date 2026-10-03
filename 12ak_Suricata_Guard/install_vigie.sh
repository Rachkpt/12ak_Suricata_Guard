#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
#   VIGIE — Installateur automatique tout-en-un
#   Suricata + IPTABLES + Bot Telegram + Email + Service systemd
#   ────────────────────────────────────────────────────────────────
#   Outil développé et signé par : 12ak_H4ck 
#   Cette signature est immuable et ne doit pas être retirée.
# ════════════════════════════════════════════════════════════════════

set -uo pipefail

# ───────────────────────── COULEURS / STYLE ──────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; BLU='\033[0;34m'
CYA='\033[0;36m'; MAG='\033[0;35m'; BLD='\033[1m'; NC='\033[0m'
GREENM='\033[38;5;46m'

SIGNATURE="12ak_H4ck"
AUTHOR_FULL="12ak_H4ck"

# ───────────────────────── CHEMINS / FICHIERS ────────────────────────
WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_SCRIPT_SRC="${WORKDIR}/vigie.py"
RULES_SRC="${WORKDIR}/local.rules"

PY_SCRIPT_DST="/opt/vigie/vigie.py"
PY_VENV="/opt/vigie/venv"
CONFIG_DIR="/etc/vigie"
CONFIG_FILE="${CONFIG_DIR}/config.json"
SURICATA_RULES_DIR="/etc/suricata/rules"
SURICATA_YAML="/etc/suricata/suricata.yaml"
SYSTEMD_VIGIE="/etc/systemd/system/vigie.service"
LOGROTATE_FILE="/etc/logrotate.d/vigie"
INSTALL_LOG="/var/log/vigie_install.log"
UNINSTALL_SRC="${WORKDIR}/uninstall_vigie.sh"

# ───────────────────────── FONCTIONS UI ──────────────────────────────

log_install() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$INSTALL_LOG" 2>/dev/null || true
}

banner() {
    clear
    echo -e "${GREENM}"
    cat << "EOF"
   ███████╗██╗   ██╗██████╗ ██╗ ██████╗ █████╗ ████████╗ █████╗
   ██╔════╝██║   ██║██╔══██╗██║██╔════╝██╔══██╗╚══██╔══╝██╔══██╗
   ███████╗██║   ██║██████╔╝██║██║     ███████║   ██║   ███████║
   ╚════██║██║   ██║██╔══██╗██║██║     ██╔══██║   ██║   ██╔══██║
   ███████║╚██████╔╝██║  ██║██║╚██████╗██║  ██║   ██║   ██║  ██║
   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
              G U A R D   —   D E P L O Y   S Y S T E M
EOF
    echo -e "${NC}"
    echo -e "${CYA}   ──────────────────────────────────────────────────────────${NC}"
    echo -e "${BLD}${YEL}              >> Outil développé et signé par : ${GRN}${SIGNATURE}${NC}"
    echo -e "${CYA}                         (${AUTHOR_FULL})${NC}"
    echo -e "${CYA}   ──────────────────────────────────────────────────────────${NC}"
    echo ""
}

matrix_rain() {
    # Petite animation "pluie matrix" en fond d'écran, durée courte (non bloquante longtemps)
    local duration="${1:-2}"
    local cols
    cols=$(tput cols 2>/dev/null || echo 80)
    local end_time=$((SECONDS + duration))
    local chars="01アイウエオカキクケコサシスセソ12ak_H4ck"
    while [ $SECONDS -lt $end_time ]; do
        local line=""
        for ((i=0; i<cols/2; i++)); do
            line+="${chars:$((RANDOM % ${#chars})):1} "
        done
        echo -e "${GREENM}${line}${NC}"
        sleep 0.04
    done
}

step() {
    echo ""
    echo -e "${BLD}${BLU}▶ $1${NC}"
    log_install "STEP: $1"
}

ok() {
    echo -e "  ${GRN}✔${NC} $1"
    log_install "OK: $1"
}

warn() {
    echo -e "  ${YEL}⚠${NC} $1"
    log_install "WARN: $1"
}

fail() {
    echo -e "  ${RED}✘ ERREUR: $1${NC}"
    log_install "FAIL: $1"
}

die() {
    fail "$1"
    echo ""
    echo -e "${RED}${BLD}Installation interrompue. Consulte ${INSTALL_LOG} pour le détail.${NC}"
    exit 1
}

spinner_run() {
    # Exécute une commande en arrière-plan avec un spinner, log la sortie
    local msg="$1"; shift
    local logfile="/tmp/vigie_step_$$.log"
    ("$@") > "$logfile" 2>&1 &
    local pid=$!
    local sp='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    printf "  ${CYA}[..]${NC} %s " "$msg"
    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i+1) % ${#sp} ))
        printf "\r  ${CYA}[%s]${NC} %s " "${sp:$i:1}" "$msg"
        sleep 0.1
    done
    wait "$pid"
    local rc=$?
    if [ $rc -eq 0 ]; then
        printf "\r  ${GRN}[OK]${NC} %s\n" "$msg"
        log_install "OK: $msg"
    else
        printf "\r  ${RED}[KO]${NC} %s\n" "$msg"
        log_install "FAIL: $msg -- voir $logfile"
        echo -e "${RED}    └─ Détail erreur :${NC}"
        tail -n 15 "$logfile" | sed 's/^/      /'
    fi
    cat "$logfile" >> "$INSTALL_LOG" 2>/dev/null || true
    rm -f "$logfile"
    return $rc
}

ask() {
    # ask "Question" "default_value" -> écrit la réponse dans REPLY_VAL
    local question="$1"
    local default="${2:-}"
    local input=""
    if [ -n "$default" ]; then
        read -r -p "$(echo -e "  ${MAG}❓${NC} ${question} ${CYA}[${default}]${NC} : ")" input
        REPLY_VAL="${input:-$default}"
    else
        while [ -z "$input" ]; do
            read -r -p "$(echo -e "  ${MAG}❓${NC} ${question} : ")" input
            [ -z "$input" ] && echo -e "    ${YEL}→ Ce champ est obligatoire.${NC}"
        done
        REPLY_VAL="$input"
    fi
}

ask_secret() {
    local question="$1"
    local input=""
    while [ -z "$input" ]; do
        read -r -s -p "$(echo -e "  ${MAG}🔒${NC} ${question} : ")" input
        echo ""
        [ -z "$input" ] && echo -e "    ${YEL}→ Ce champ est obligatoire.${NC}"
    done
    REPLY_VAL="$input"
}

ask_yn() {
    # ask_yn "Question" "o" -> REPLY_YN = "o" ou "n"
    local question="$1"
    local default="${2:-o}"
    local input=""
    read -r -p "$(echo -e "  ${MAG}❓${NC} ${question} ${CYA}[o/n, défaut:${default}]${NC} : ")" input
    input="${input:-$default}"
    input="$(echo "$input" | tr '[:upper:]' '[:lower:]')"
    if [[ "$input" == "o" || "$input" == "oui" || "$input" == "y" || "$input" == "yes" ]]; then
        REPLY_YN="o"
    else
        REPLY_YN="n"
    fi
}

# ════════════════════════════════════════════════════════════════════
#   ÉTAPE 0 — VÉRIFICATIONS PRÉALABLES
# ════════════════════════════════════════════════════════════════════

check_prerequisites() {
    step "Vérifications préalables"

    if [ "$(id -u)" -ne 0 ]; then
        die "Ce script doit être exécuté en root (utilise : sudo bash $0)"
    fi
    ok "Exécution en root confirmée"

    if ! command -v apt-get >/dev/null 2>&1; then
        die "Ce script est conçu pour Ubuntu/Debian (apt-get non trouvé)"
    fi
    ok "Système basé sur apt détecté"

    if [ ! -f "$PY_SCRIPT_SRC" ]; then
        die "Fichier introuvable : $PY_SCRIPT_SRC (place vigie.py dans le même dossier que ce script)"
    fi
    ok "vigie.py trouvé"

    if [ ! -f "$RULES_SRC" ]; then
        die "Fichier introuvable : $RULES_SRC (place local.rules dans le même dossier que ce script)"
    fi
    ok "local.rules trouvé"

    if [ -z "${TERM:-}" ]; then
        export TERM=xterm
    fi

    . /etc/os-release 2>/dev/null || true
    ok "OS détecté : ${PRETTY_NAME:-inconnu}"
}

detect_interfaces() {
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -v '^lo$' | sed 's/@.*//' | sort -u
}

detect_default_iface() {
    ip route 2>/dev/null | awk '/^default/ {print $5; exit}'
}

# ════════════════════════════════════════════════════════════════════
#   ÉTAPE 1 — COLLECTE DES INFOS UTILISATEUR
# ════════════════════════════════════════════════════════════════════

collect_user_inputs() {
    step "Configuration interactive — réponds aux questions ci-dessous"
    echo -e "  ${CYA}Tes réponses sont enregistrées dans ${CONFIG_FILE} (accès root uniquement).${NC}"
    echo -e "  ${CYA}Rien à modifier à la main après l'installation.${NC}"
    echo ""

    # ── Interface réseau ──────────────────────────────────────────
    echo -e "${BLD}── Interface réseau à surveiller ──${NC}"
    local default_iface
    default_iface=$(detect_default_iface)
    echo -e "  Interfaces disponibles :"
    detect_interfaces | sed 's/^/    - /'
    ask "Quelle interface Suricata doit surveiller" "${default_iface:-eth0}"
    IFACE="$REPLY_VAL"

    # ── Seuil d'alerte ────────────────────────────────────────────
    echo ""
    echo -e "${BLD}── Seuil de blocage ──${NC}"
    echo -e "  ${CYA}Les scans NMAP et DDoS sont bloqués dès la 1re alerte ; le seuil concerne les autres alertes.${NC}"
    ask "Nombre d'alertes sur 10 minutes avant blocage automatique d'une IP" "5"
    ALERT_THRESHOLD="$REPLY_VAL"

    # ── Telegram ──────────────────────────────────────────────────
    echo ""
    echo -e "${BLD}── Bot Telegram ──${NC}"
    echo -e "  ${CYA}(Crée un bot via @BotFather sur Telegram si tu n'en as pas encore)${NC}"
    ask_yn "Veux-tu activer les alertes Telegram" "o"
    TELEGRAM_ENABLED="$REPLY_YN"
    if [ "$TELEGRAM_ENABLED" = "o" ]; then
        ask_secret "Token du bot Telegram (depuis @BotFather)"
        TELEGRAM_TOKEN="$REPLY_VAL"
        while true; do
            ask "Ton chat_id Telegram (numérique, depuis @userinfobot)" ""
            if [[ "$REPLY_VAL" =~ ^-?[0-9]+$ ]]; then
                TELEGRAM_CHAT_ID="$REPLY_VAL"
                break
            fi
            echo -e "    ${YEL}→ Le chat_id doit être un nombre (ex. 123456789).${NC}"
        done
    else
        TELEGRAM_TOKEN=""
        TELEGRAM_CHAT_ID="0"
    fi

    # ── Email ─────────────────────────────────────────────────────
    echo ""
    echo -e "${BLD}── Notifications Email ──${NC}"
    ask_yn "Veux-tu activer les notifications par email" "o"
    EMAIL_ENABLED="$REPLY_YN"
    if [ "$EMAIL_ENABLED" = "o" ]; then
        echo -e "  Fournisseur : 1) Gmail   2) Outlook   3) Custom SMTP"
        ask "Choix (1/2/3)" "1"
        case "$REPLY_VAL" in
            2) EMAIL_PROVIDER="outlook" ;;
            3) EMAIL_PROVIDER="custom" ;;
            *) EMAIL_PROVIDER="gmail" ;;
        esac

        ask "Adresse email expéditeur" ""
        EMAIL_FROM="$REPLY_VAL"

        if [ "$EMAIL_PROVIDER" = "gmail" ]; then
            echo -e "  ${CYA}→ Utilise un mot de passe d'application Gmail :${NC}"
            echo -e "  ${CYA}  https://myaccount.google.com/apppasswords${NC}"
        fi
        ask_secret "Mot de passe (ou mot de passe d'application)"
        EMAIL_PASSWORD="$REPLY_VAL"

        ask "Email(s) destinataire(s) (séparés par une virgule si plusieurs)" "$EMAIL_FROM"
        EMAIL_TO_RAW="$REPLY_VAL"

        if [ "$EMAIL_PROVIDER" = "custom" ]; then
            ask "Adresse du serveur SMTP" ""
            SMTP_HOST="$REPLY_VAL"
            ask "Port SMTP" "587"
            SMTP_PORT="$REPLY_VAL"
            ask_yn "Utiliser TLS" "o"
            SMTP_USE_TLS=$([ "$REPLY_YN" = "o" ] && echo "True" || echo "False")
        else
            SMTP_HOST="smtp.tonserveur.com"
            SMTP_PORT="587"
            SMTP_USE_TLS="True"
        fi
    else
        EMAIL_PROVIDER="gmail"
        EMAIL_FROM="disabled@example.com"
        EMAIL_PASSWORD="disabled"
        EMAIL_TO_RAW="disabled@example.com"
        SMTP_HOST="smtp.tonserveur.com"
        SMTP_PORT="587"
        SMTP_USE_TLS="True"
    fi

    # ── Whitelist IPs ────────────────────────────────────────────
    echo ""
    echo -e "${BLD}── Whitelist (IPs jamais bloquées) ──${NC}"
    echo -e "  ${CYA}127.0.0.1 et ::1 sont déjà protégées par défaut.${NC}"
    WHITELIST_RAW=""
    # Si tu es connecté en SSH, ton IP ne doit JAMAIS être bloquée (sinon tu te coupes toi-même)
    SSH_IP="${SSH_CLIENT%% *}"
    if [ -n "$SSH_IP" ]; then
        ask_yn "Ajouter ton IP SSH actuelle ($SSH_IP) à la whitelist (recommandé)" "o"
        [ "$REPLY_YN" = "o" ] && WHITELIST_RAW="$SSH_IP"
    fi
    ask "IPs supplémentaires à whitelister (séparées par une virgule, vide = aucune)" ""
    if [ -n "$REPLY_VAL" ]; then
        WHITELIST_RAW="${WHITELIST_RAW:+$WHITELIST_RAW,}$REPLY_VAL"
    fi

    echo ""
    echo -e "${GRN}${BLD}✔ Configuration collectée. Récapitulatif :${NC}"
    echo -e "    Interface réseau     : ${CYA}${IFACE}${NC}"
    echo -e "    Seuil blocage         : ${CYA}${ALERT_THRESHOLD} alertes${NC}"
    echo -e "    Telegram               : ${CYA}${TELEGRAM_ENABLED}${NC}"
    echo -e "    Email                  : ${CYA}${EMAIL_ENABLED} (${EMAIL_PROVIDER})${NC}"
    echo -e "    Whitelist supplémentaire : ${CYA}${WHITELIST_RAW:-aucune}${NC}"
    echo ""
    ask_yn "Confirmer et lancer l'installation" "o"
    if [ "$REPLY_YN" != "o" ]; then
        echo -e "${YEL}Installation annulée par l'utilisateur.${NC}"
        exit 0
    fi
}

# ════════════════════════════════════════════════════════════════════
#   ÉTAPE 2 — INSTALLATION DES PAQUETS SYSTÈME
# ════════════════════════════════════════════════════════════════════

install_system_packages() {
    step "Installation des paquets système (Suricata, iptables, Python...)"

    export DEBIAN_FRONTEND=noninteractive

    spinner_run "Mise à jour des dépôts (apt update)" apt-get update -y
    spinner_run "Installation de software-properties-common" apt-get install -y software-properties-common

    if ! command -v suricata >/dev/null 2>&1; then
        spinner_run "Ajout du PPA officiel Suricata (OISF)" add-apt-repository -y ppa:oisf/suricata-stable
        spinner_run "Mise à jour des dépôts après PPA" apt-get update -y
        spinner_run "Installation de Suricata" apt-get install -y suricata
    else
        ok "Suricata déjà installé, étape ignorée"
    fi

    spinner_run "Installation iptables / persistance / outils réseau" \
        apt-get install -y iptables iptables-persistent net-tools curl jq

    spinner_run "Installation Python3 / pip / venv" \
        apt-get install -y python3 python3-pip python3-venv

    if ! command -v suricata-update >/dev/null 2>&1; then
        spinner_run "Installation de suricata-update" pip3 install --break-system-packages suricata-update
    else
        ok "suricata-update déjà disponible"
    fi
}

# ════════════════════════════════════════════════════════════════════
#   ÉTAPE 3 — CONFIGURATION SURICATA
# ════════════════════════════════════════════════════════════════════

configure_suricata() {
    step "Configuration de Suricata (interface, règles, fast.log)"

    if [ ! -f "$SURICATA_YAML" ]; then
        die "Fichier $SURICATA_YAML introuvable — l'installation de Suricata a échoué"
    fi

    cp "$SURICATA_YAML" "${SURICATA_YAML}.bak.$(date +%s)"
    ok "Sauvegarde de suricata.yaml créée"

    # Configurer l'interface de capture (af-packet)
    if grep -q "^af-packet:" "$SURICATA_YAML"; then
        python3 - "$SURICATA_YAML" "$IFACE" << 'PYEOF'
import sys, re
path, iface = sys.argv[1], sys.argv[2]
with open(path) as f:
    content = f.read()
# Remplace la première interface déclarée sous af-packet par celle choisie
content = re.sub(r'(af-packet:\s*\n\s*-\s*interface:\s*)\S+', r'\1' + iface, content, count=1)
content = re.sub(r'(- interface:\s*)default', r'\1' + iface, content, count=1)
with open(path, 'w') as f:
    f.write(content)
PYEOF
        ok "Interface af-packet configurée sur : $IFACE"
    else
        warn "Section af-packet non trouvée automatiquement, vérifie suricata.yaml manuellement"
    fi

    # Vérifier / forcer l'activation du fast.log
    if grep -q "filename: fast.log" "$SURICATA_YAML"; then
        ok "fast.log déjà activé dans la configuration"
    else
        warn "fast.log non détecté explicitement — vérifie la section 'outputs' de suricata.yaml"
    fi

    # Copier les règles personnalisées
    mkdir -p "$SURICATA_RULES_DIR"
    cp "$RULES_SRC" "${SURICATA_RULES_DIR}/local.rules"
    ok "Règles personnalisées copiées vers ${SURICATA_RULES_DIR}/local.rules"

    # S'assurer que local.rules est chargé dans la liste des règles
    if grep -q "local.rules" "$SURICATA_YAML"; then
        ok "local.rules déjà référencé dans suricata.yaml"
    else
        if grep -q "^rule-files:" "$SURICATA_YAML"; then
            sed -i '/^rule-files:/a\  - local.rules' "$SURICATA_YAML"
            ok "local.rules ajouté à rule-files dans suricata.yaml"
        else
            warn "Section rule-files non trouvée — ajoute manuellement 'local.rules' à rule-files"
        fi
    fi

    spinner_run "Mise à jour des règles Suricata (suricata-update)" suricata-update || true

    spinner_run "Test de la configuration Suricata" \
        suricata -T -c "$SURICATA_YAML" -i "$IFACE"
}

# ════════════════════════════════════════════════════════════════════
#   ÉTAPE 4 — CONFIGURATION IPTABLES
# ════════════════════════════════════════════════════════════════════

configure_iptables() {
    step "Configuration de la chaîne iptables VIGIE"

    if ! iptables -L VIGIE -n >/dev/null 2>&1; then
        iptables -N VIGIE
        ok "Chaîne VIGIE créée"
    else
        ok "Chaîne VIGIE déjà existante"
    fi

    if ! iptables -C INPUT -j VIGIE >/dev/null 2>&1; then
        iptables -I INPUT -j VIGIE
        ok "Chaîne VIGIE reliée à INPUT"
    else
        ok "Chaîne déjà reliée à INPUT"
    fi

    spinner_run "Sauvegarde persistante des règles iptables" netfilter-persistent save || true
}

# ════════════════════════════════════════════════════════════════════
#   ÉTAPE 5 — DÉPLOIEMENT DU SCRIPT PYTHON (vigie.py)
# ════════════════════════════════════════════════════════════════════

write_config() {
    step "Écriture de la configuration (fichier root, mode 600)"

    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"

    # Les valeurs passent par l'environnement : pas d'interpolation dans le code Python,
    # donc un mot de passe contenant " ' ou \ ne peut plus casser la configuration.
    export SG_THRESHOLD="$ALERT_THRESHOLD"
    export SG_TG_ENABLED="$TELEGRAM_ENABLED"
    export SG_TG_TOKEN="$TELEGRAM_TOKEN"
    export SG_TG_CHAT_ID="$TELEGRAM_CHAT_ID"
    export SG_MAIL_ENABLED="$EMAIL_ENABLED"
    export SG_MAIL_PROVIDER="$EMAIL_PROVIDER"
    export SG_MAIL_FROM="$EMAIL_FROM"
    export SG_MAIL_PASSWORD="$EMAIL_PASSWORD"
    export SG_MAIL_TO="$EMAIL_TO_RAW"
    export SG_SMTP_HOST="$SMTP_HOST"
    export SG_SMTP_PORT="$SMTP_PORT"
    export SG_SMTP_TLS="$SMTP_USE_TLS"
    export SG_WHITELIST="$WHITELIST_RAW"
    export SG_IFACE="$IFACE"

    python3 - "$CONFIG_FILE" << 'PYEOF'
import ipaddress, json, os, sys

env = os.environ.get

def split(raw):
    return [x.strip() for x in raw.split(",") if x.strip()]

whitelist = split(env("SG_WHITELIST", ""))
bad = []
for ip in whitelist:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        bad.append(ip)
if bad:
    sys.exit(f"Adresse(s) IP invalide(s) dans la whitelist : {', '.join(bad)}")

try:
    chat_id = int(env("SG_TG_CHAT_ID", "0") or 0)
    threshold = int(env("SG_THRESHOLD", "5"))
except ValueError:
    sys.exit("Chat ID ou seuil non numérique")

cfg = {
    "alert_threshold": threshold,
    "alert_window_seconds": 600,
    "fast_log": "/var/log/suricata/fast.log",
    "interface": env("SG_IFACE", ""),
    "telegram_enabled": env("SG_TG_ENABLED") == "o",
    "telegram_token": env("SG_TG_TOKEN", ""),
    "telegram_chat_id": chat_id,
    "email_enabled": env("SG_MAIL_ENABLED") == "o",
    "email_provider": env("SG_MAIL_PROVIDER", "gmail"),
    "email_from": env("SG_MAIL_FROM", ""),
    "email_password": env("SG_MAIL_PASSWORD", ""),
    "email_to": split(env("SG_MAIL_TO", "")),
    "smtp_host": env("SG_SMTP_HOST", ""),
    "smtp_port": int(env("SG_SMTP_PORT", "587") or 587),
    "smtp_use_tls": env("SG_SMTP_TLS") == "True",
    "whitelist": whitelist,
}

path = sys.argv[1]
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
print("ok")
PYEOF
    local rc=$?
    unset SG_THRESHOLD SG_TG_ENABLED SG_TG_TOKEN SG_TG_CHAT_ID SG_MAIL_ENABLED SG_MAIL_PROVIDER \
          SG_MAIL_FROM SG_MAIL_PASSWORD SG_MAIL_TO SG_SMTP_HOST SG_SMTP_PORT SG_SMTP_TLS SG_WHITELIST SG_IFACE
    [ $rc -eq 0 ] || die "Configuration invalide (voir les messages ci-dessus)"

    chmod 600 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
    ok "Configuration enregistrée : $CONFIG_FILE (600, root)"
}

deploy_python_script() {
    step "Déploiement de vigie.py"

    mkdir -p "$(dirname "$PY_SCRIPT_DST")"
    cp "$PY_SCRIPT_SRC" "$PY_SCRIPT_DST"
    python3 -m py_compile "$PY_SCRIPT_DST" 2>/dev/null \
        && ok "Script Python validé syntaxiquement" \
        || die "Le script Python contient une erreur de syntaxe"
    rm -rf "$(dirname "$PY_SCRIPT_DST")/__pycache__"

    chmod 700 "$PY_SCRIPT_DST"
    chown root:root "$PY_SCRIPT_DST"
    ok "Script copié vers $PY_SCRIPT_DST (700, root:root)"

    # Script de désinstallation toujours disponible sur le serveur
    if [ -f "$UNINSTALL_SRC" ]; then
        cp "$UNINSTALL_SRC" "$(dirname "$PY_SCRIPT_DST")/uninstall_vigie.sh"
        chmod 700 "$(dirname "$PY_SCRIPT_DST")/uninstall_vigie.sh"
        ok "Désinstalleur copié dans $(dirname "$PY_SCRIPT_DST")/"
    fi

    # Rotation des journaux (copytruncate : le bot détecte aussi la troncature)
    cat > "$LOGROTATE_FILE" << LREOF
/var/log/vigie.log
/var/log/vigie_blocked.log
/var/log/vigie_service.log
{
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
LREOF
    ok "Rotation des logs configurée : $LOGROTATE_FILE"
}

setup_python_venv() {
    step "Création de l'environnement Python et installation des dépendances"

    spinner_run "Création du venv Python" python3 -m venv "$PY_VENV"
    spinner_run "Mise à jour pip dans le venv" "$PY_VENV/bin/pip" install --upgrade pip
    spinner_run "Installation python-telegram-bot" "$PY_VENV/bin/pip" install "python-telegram-bot>=20,<21"
}

# ════════════════════════════════════════════════════════════════════
#   ÉTAPE 6 — SERVICE SYSTEMD
# ════════════════════════════════════════════════════════════════════

create_systemd_service() {
    step "Création du service systemd vigie.service"

    cat > "$SYSTEMD_VIGIE" << SERVICEEOF
[Unit]
Description=Vigie - Bot Telegram/Email + Blocage IP auto (by ${SIGNATURE})
After=network.target suricata.service
Wants=suricata.service

[Service]
Type=simple
ExecStart=${PY_VENV}/bin/python3 ${PY_SCRIPT_DST}
Restart=always
RestartSec=5
User=root
StandardOutput=append:/var/log/vigie_service.log
StandardError=append:/var/log/vigie_service.log

[Install]
WantedBy=multi-user.target
SERVICEEOF

    ok "Fichier service créé : $SYSTEMD_VIGIE"

    spinner_run "Rechargement systemd" systemctl daemon-reload
    spinner_run "Activation de suricata.service au boot" systemctl enable suricata
    spinner_run "Activation de vigie.service au boot" systemctl enable vigie
}

start_services() {
    step "Démarrage des services"

    spinner_run "Redémarrage de Suricata" systemctl restart suricata
    sleep 2

    if systemctl is-active --quiet suricata; then
        ok "Suricata est actif"
    else
        warn "Suricata ne semble pas actif — vérifie : journalctl -u suricata -n 50"
    fi

    spinner_run "Démarrage de vigie" systemctl restart vigie
    sleep 2

    if systemctl is-active --quiet vigie; then
        ok "vigie est actif"
    else
        warn "vigie ne semble pas actif — vérifie : journalctl -u vigie -n 50"
    fi
}

# ════════════════════════════════════════════════════════════════════
#   RÉCAPITULATIF FINAL
# ════════════════════════════════════════════════════════════════════

final_summary() {
    echo ""
    echo -e "${GREENM}${BLD}"
    cat << "EOF"
   ╔═══════════════════════════════════════════════════════════╗
   ║   INSTALLATION TERMINEE AVEC SUCCES                       ║
   ╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "  ${BLD}Récapitulatif du déploiement :${NC}"
    echo -e "    🌐 Interface surveillée   : ${CYA}${IFACE}${NC}"
    echo -e "    📊 Seuil de blocage       : ${CYA}${ALERT_THRESHOLD} alertes${NC}"
    echo -e "    📁 Règles Suricata        : ${CYA}${SURICATA_RULES_DIR}/local.rules${NC}"
    echo -e "    🐍 Script Python          : ${CYA}${PY_SCRIPT_DST}${NC}"
    echo -e "    🔧 Service Suricata       : ${CYA}systemctl status suricata${NC}"
    echo -e "    🔧 Service Vigie          : ${CYA}systemctl status vigie${NC}"
    echo -e "    📋 Log d'installation     : ${CYA}${INSTALL_LOG}${NC}"
    echo -e "    📋 Log du service           : ${CYA}/var/log/vigie_service.log${NC}"
    echo ""
    echo -e "  ${BLD}Commandes utiles :${NC}"
    echo -e "    ${YEL}journalctl -u vigie -f${NC}      → suivre les logs en direct"
    echo -e "    ${YEL}iptables -S VIGIE${NC}           → voir les IPs bloquées"
    echo -e "    ${YEL}systemctl restart vigie${NC}     → redémarrer le bot"
    echo -e "    ${YEL}systemctl stop vigie${NC}        → arrêter le bot (les blocages restent)"
    echo -e "    ${YEL}bash /opt/vigie/uninstall_vigie.sh${NC}  → tout arrêter et supprimer"
    echo ""
    if [ "$TELEGRAM_ENABLED" = "o" ]; then
        echo -e "  ${GRN}→ Va sur Telegram et envoie /start à ton bot pour voir le menu.${NC}"
    fi
    echo ""
    echo -e "${CYA}   ──────────────────────────────────────────────────────────${NC}"
    echo -e "${BLD}${YEL}        Déploiement automatisé signé : ${GRN}${SIGNATURE}${NC}"
    echo -e "${CYA}                  (${AUTHOR_FULL})${NC}"
    echo -e "${CYA}   ──────────────────────────────────────────────────────────${NC}"
    echo ""
}

# ════════════════════════════════════════════════════════════════════
#   MAIN
# ════════════════════════════════════════════════════════════════════

main() {
    banner
    echo -e "  ${CYA}Initialisation du système de déploiement...${NC}"
    matrix_rain 2
    banner

    check_prerequisites
    collect_user_inputs

    echo ""
    echo -e "${MAG}${BLD}  >> Lancement de l'installation automatique...${NC}"
    matrix_rain 1
    echo ""

    install_system_packages
    configure_suricata
    configure_iptables
    write_config
    deploy_python_script
    setup_python_venv
    create_systemd_service
    start_services

    final_summary
}

main "$@"
