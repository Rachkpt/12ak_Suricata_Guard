#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
#   SURICATA GUARD — Installateur automatique tout-en-un
#   Suricata + IPTABLES + Bot Telegram + Email + Service systemd
#   ────────────────────────────────────────────────────────────────
#   Outil développé et signé par : 12ak_H4ck (Aledji Ar-Rachad)
#   Cette signature est immuable et ne doit pas être retirée.
# ════════════════════════════════════════════════════════════════════

set -uo pipefail

# ───────────────────────── COULEURS / STYLE ──────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; BLU='\033[0;34m'
CYA='\033[0;36m'; MAG='\033[0;35m'; BLD='\033[1m'; NC='\033[0m'
GREENM='\033[38;5;46m'

SIGNATURE="12ak_H4ck"
AUTHOR_FULL="Aledji Ar-Rachad"

# ───────────────────────── CHEMINS / FICHIERS ────────────────────────
WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_SCRIPT_SRC="${WORKDIR}/suricata_guard.py"
RULES_SRC="${WORKDIR}/local.rules"

PY_SCRIPT_DST="/opt/suricata-guard/suricata_guard.py"
PY_VENV="/opt/suricata-guard/venv"
SURICATA_RULES_DIR="/etc/suricata/rules"
SURICATA_YAML="/etc/suricata/suricata.yaml"
SYSTEMD_GUARD="/etc/systemd/system/suricata-guard.service"
INSTALL_LOG="/var/log/suricata_guard_install.log"

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
    local logfile="/tmp/suricata_guard_step_$$.log"
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
        die "Fichier introuvable : $PY_SCRIPT_SRC (place suricata_guard.py dans le même dossier que ce script)"
    fi
    ok "suricata_guard.py trouvé"

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
    echo -e "  ${CYA}Toutes ces infos seront injectées automatiquement dans le script.${NC}"
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
    ask "Nombre d'alertes avant blocage automatique d'une IP" "5"
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
        ask "Ton chat_id Telegram (numérique, depuis @userinfobot)" ""
        TELEGRAM_CHAT_ID="$REPLY_VAL"
    else
        TELEGRAM_TOKEN="DISABLED"
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
    ask "IPs supplémentaires à whitelister (séparées par une virgule, vide = aucune)" ""
    WHITELIST_RAW="$REPLY_VAL"

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
    step "Configuration de la chaîne iptables SURICATA_GUARD"

    if ! iptables -L SURICATA_GUARD -n >/dev/null 2>&1; then
        iptables -N SURICATA_GUARD
        ok "Chaîne SURICATA_GUARD créée"
    else
        ok "Chaîne SURICATA_GUARD déjà existante"
    fi

    if ! iptables -C INPUT -j SURICATA_GUARD >/dev/null 2>&1; then
        iptables -I INPUT -j SURICATA_GUARD
        ok "Chaîne SURICATA_GUARD reliée à INPUT"
    else
        ok "Chaîne déjà reliée à INPUT"
    fi

    spinner_run "Sauvegarde persistante des règles iptables" netfilter-persistent save || true
}

# ════════════════════════════════════════════════════════════════════
#   ÉTAPE 5 — DÉPLOIEMENT DU SCRIPT PYTHON (suricata_guard.py)
# ════════════════════════════════════════════════════════════════════

deploy_python_script() {
    step "Déploiement de suricata_guard.py avec ta configuration"

    mkdir -p "$(dirname "$PY_SCRIPT_DST")"
    cp "$PY_SCRIPT_SRC" "$PY_SCRIPT_DST"
    ok "Script copié vers $PY_SCRIPT_DST"

    # Construction de la liste EMAIL_TO en JSON-like Python list
    local email_to_py
    email_to_py=$(python3 -c "
import sys
raw = sys.argv[1]
items = [x.strip() for x in raw.split(',') if x.strip()]
print(repr(items))
" "$EMAIL_TO_RAW")

    # Construction du bloc whitelist supplémentaire
    local whitelist_py=""
    if [ -n "$WHITELIST_RAW" ]; then
        whitelist_py=$(python3 -c "
import sys
raw = sys.argv[1]
items = [x.strip() for x in raw.split(',') if x.strip()]
print('\n'.join(f'    \"{ip}\",' for ip in items))
" "$WHITELIST_RAW")
    fi

    local email_enabled_py="False"
    [ "$EMAIL_ENABLED" = "o" ] && email_enabled_py="True"

    # Injection des valeurs via Python (plus sûr que sed pour échapper les caractères spéciaux)
    python3 - "$PY_SCRIPT_DST" << PYEOF
import re

path = "$PY_SCRIPT_DST"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

replacements = {
    "__ALERT_THRESHOLD__": "$ALERT_THRESHOLD",
    "__TELEGRAM_TOKEN__": "$TELEGRAM_TOKEN",
    "__TELEGRAM_CHAT_ID__": "$TELEGRAM_CHAT_ID",
    "__EMAIL_ENABLED__": "$email_enabled_py",
    "__EMAIL_PROVIDER__": "$EMAIL_PROVIDER",
    "__EMAIL_FROM__": "$EMAIL_FROM",
    "__EMAIL_PASSWORD__": "$EMAIL_PASSWORD",
    "__EMAIL_TO__": '''$email_to_py''',
    "__SMTP_HOST__": "$SMTP_HOST",
    "__SMTP_PORT__": "$SMTP_PORT",
    "__SMTP_USE_TLS__": "$SMTP_USE_TLS",
    "__WHITELIST_IPS__": '''$whitelist_py''',
}

for placeholder, value in replacements.items():
    content = content.replace(placeholder, value)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
PYEOF

    if grep -q "__.*__" "$PY_SCRIPT_DST" 2>/dev/null && grep -qE "__[A-Z_]+__" "$PY_SCRIPT_DST"; then
        warn "Certains placeholders n'ont peut-être pas été remplacés, vérifie $PY_SCRIPT_DST"
    else
        ok "Tous les paramètres ont été injectés dans le script"
    fi

    python3 -c "import ast; ast.parse(open('$PY_SCRIPT_DST').read())" \
        && ok "Script Python validé syntaxiquement" \
        || die "Le script Python généré contient une erreur de syntaxe"

    chmod 700 "$PY_SCRIPT_DST"
    chown root:root "$PY_SCRIPT_DST"
    ok "Permissions sécurisées appliquées (700, root:root)"
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
    step "Création du service systemd suricata-guard.service"

    cat > "$SYSTEMD_GUARD" << SERVICEEOF
[Unit]
Description=Suricata Guard - Bot Telegram/Email + Blocage IP auto (by ${SIGNATURE})
After=network.target suricata.service
Wants=suricata.service

[Service]
Type=simple
ExecStart=${PY_VENV}/bin/python3 ${PY_SCRIPT_DST}
Restart=always
RestartSec=5
User=root
StandardOutput=append:/var/log/suricata_guard_service.log
StandardError=append:/var/log/suricata_guard_service.log

[Install]
WantedBy=multi-user.target
SERVICEEOF

    ok "Fichier service créé : $SYSTEMD_GUARD"

    spinner_run "Rechargement systemd" systemctl daemon-reload
    spinner_run "Activation de suricata.service au boot" systemctl enable suricata
    spinner_run "Activation de suricata-guard.service au boot" systemctl enable suricata-guard
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

    spinner_run "Démarrage de suricata-guard" systemctl restart suricata-guard
    sleep 2

    if systemctl is-active --quiet suricata-guard; then
        ok "suricata-guard est actif"
    else
        warn "suricata-guard ne semble pas actif — vérifie : journalctl -u suricata-guard -n 50"
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
    echo -e "    🔧 Service Guard          : ${CYA}systemctl status suricata-guard${NC}"
    echo -e "    📋 Log d'installation     : ${CYA}${INSTALL_LOG}${NC}"
    echo -e "    📋 Log du guard           : ${CYA}/var/log/suricata_guard_service.log${NC}"
    echo ""
    echo -e "  ${BLD}Commandes utiles :${NC}"
    echo -e "    ${YEL}journalctl -u suricata-guard -f${NC}      → suivre les logs en direct"
    echo -e "    ${YEL}iptables -L SURICATA_GUARD -n${NC}        → voir les IPs bloquées"
    echo -e "    ${YEL}systemctl restart suricata-guard${NC}     → redémarrer le bot"
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
    deploy_python_script
    setup_python_venv
    create_systemd_service
    start_services

    final_summary
}

main "$@"
