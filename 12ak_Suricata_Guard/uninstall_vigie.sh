#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
#   VIGIE — Désinstallation complète
#   Arrête le bot, retire TOUS les blocages iptables, supprime les fichiers.
#   ────────────────────────────────────────────────────────────────
#   Outil développé et signé par : 12ak_H4ck
# ════════════════════════════════════════════════════════════════════
#
#   Usage :
#     sudo bash uninstall_vigie.sh          # interactif (demande confirmation)
#     sudo bash uninstall_vigie.sh --yes    # sans question : garde Suricata et les logs
#
#   Ce qui est fait :
#     1. arrêt et désactivation du service vigie
#     2. suppression de TOUTES les règles de blocage (chaîne VIGIE)
#     3. suppression du script, de la configuration (contient les secrets) et du service
#     4. retrait de local.rules de Suricata
#   Optionnel (questions) : supprimer les logs, désinstaller Suricata lui-même.

set -uo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; CYA='\033[0;36m'; BLD='\033[1m'; NC='\033[0m'

INSTALL_DIR="/opt/vigie"
CONFIG_DIR="/etc/vigie"
SYSTEMD_VIGIE="/etc/systemd/system/vigie.service"
LOGROTATE_FILE="/etc/logrotate.d/vigie"
SURICATA_RULES_DIR="/etc/suricata/rules"
SURICATA_YAML="/etc/suricata/suricata.yaml"
CHAIN="VIGIE"
LOG_FILES=(/var/log/vigie.log /var/log/vigie_service.log
           /var/log/vigie_blocked.log /var/log/vigie_install.log)

ASSUME_YES=0
[ "${1:-}" = "--yes" ] && ASSUME_YES=1

ok()   { echo -e "  ${GRN}✔${NC} $1"; }
info() { echo -e "  ${CYA}→${NC} $1"; }
warn() { echo -e "  ${YEL}⚠${NC} $1"; }

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Ce script doit être lancé en root : sudo bash $0${NC}"
    exit 1
fi

ask_yn() {
    # ask_yn "Question" "n" -> code retour 0 si oui
    local question="$1" default="$2" input
    [ "$ASSUME_YES" -eq 1 ] && { [ "$default" = "o" ]; return; }
    read -r -p "  ❓ ${question} [o/n, défaut:${default}] : " input
    input="${input:-$default}"
    [[ "$(echo "$input" | tr '[:upper:]' '[:lower:]')" =~ ^(o|oui|y|yes)$ ]]
}

echo ""
echo -e "${BLD}Vigie — désinstallation${NC}"
echo "  Cela va arrêter le bot et retirer TOUTES les IPs bloquées."
echo ""

if [ "$ASSUME_YES" -eq 0 ]; then
    read -r -p "  Tape OUI en majuscules pour continuer : " confirm
    [ "$confirm" = "OUI" ] || { echo "Annulé."; exit 0; }
fi

# ── 1. Arrêt du service ─────────────────────────────────────────────
echo -e "\n${BLD}▶ Arrêt du bot${NC}"
if systemctl list-unit-files vigie.service >/dev/null 2>&1; then
    systemctl stop vigie 2>/dev/null && ok "Service vigie arrêté"
    systemctl disable vigie >/dev/null 2>&1 && ok "Démarrage automatique désactivé"
fi
if [ -f "$SYSTEMD_VIGIE" ]; then
    rm -f "$SYSTEMD_VIGIE"
    systemctl daemon-reload
    ok "Fichier service supprimé"
fi

# ── 2. Retrait de tous les blocages ─────────────────────────────────
echo -e "\n${BLD}▶ Retrait des blocages iptables${NC}"
if iptables -S "$CHAIN" >/dev/null 2>&1; then
    count=$(iptables -S "$CHAIN" | grep -c -- "-j DROP")
    iptables -F "$CHAIN"
    ok "$count règle(s) de blocage retirée(s)"
    # Détache la chaîne de INPUT / FORWARD (plusieurs liaisons possibles)
    for parent in INPUT FORWARD; do
        while iptables -D "$parent" -j "$CHAIN" 2>/dev/null; do :; done
    done
    iptables -X "$CHAIN" 2>/dev/null && ok "Chaîne $CHAIN supprimée"
else
    info "Chaîne $CHAIN absente, rien à retirer"
fi
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 && ok "Règles iptables sauvegardées (sans les blocages)"
fi

# ── 3. Fichiers de l'outil ──────────────────────────────────────────
echo -e "\n${BLD}▶ Suppression des fichiers${NC}"
if [ -d "$CONFIG_DIR" ]; then
    rm -rf "$CONFIG_DIR" && ok "Configuration $CONFIG_DIR supprimée (secrets effacés)"
fi
if [ -f "$LOGROTATE_FILE" ]; then
    rm -f "$LOGROTATE_FILE" && ok "Rotation des logs supprimée"
fi

# ── 4. Règles Suricata ──────────────────────────────────────────────
echo -e "\n${BLD}▶ Nettoyage de Suricata${NC}"
if [ -f "${SURICATA_RULES_DIR}/local.rules" ]; then
    rm -f "${SURICATA_RULES_DIR}/local.rules" && ok "local.rules retiré de $SURICATA_RULES_DIR"
fi
if [ -f "$SURICATA_YAML" ] && grep -q "^  - local.rules" "$SURICATA_YAML"; then
    cp "$SURICATA_YAML" "${SURICATA_YAML}.bak.uninstall.$(date +%s)"
    sed -i '/^  - local.rules$/d' "$SURICATA_YAML"
    ok "Référence à local.rules retirée de suricata.yaml (sauvegarde créée)"
    systemctl restart suricata 2>/dev/null && ok "Suricata redémarré avec la configuration nettoyée"
fi

# ── 5. Questions optionnelles ───────────────────────────────────────
echo ""
if ask_yn "Supprimer aussi les fichiers de logs de l'outil ?" "n"; then
    for f in "${LOG_FILES[@]}"; do rm -f "$f"; done
    ok "Logs supprimés"
else
    info "Logs conservés"
fi

if ask_yn "Désinstaller aussi Suricata lui-même (paquet + config) ?" "n"; then
    systemctl disable --now suricata >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get purge -y suricata >/dev/null 2>&1 \
        && ok "Suricata désinstallé" || warn "Échec de la désinstallation de Suricata (voir apt)"
else
    info "Suricata conservé (il tourne toujours, sans le bot)"
fi

# ── Vérification finale ─────────────────────────────────────────────
echo ""
echo -e "${BLD}Vérification :${NC}"
if systemctl is-active --quiet vigie 2>/dev/null; then
    warn "vigie tourne encore !"
else
    ok "Bot arrêté"
fi
remaining=$(iptables -S "$CHAIN" 2>/dev/null | grep -c -- "-j DROP" || true)
if [ "${remaining:-0}" -eq 0 ]; then
    ok "Aucun blocage actif"
else
    warn "$remaining blocage(s) restent : iptables -F $CHAIN"
fi

# Dernière étape : ce script se trouve lui-même dans INSTALL_DIR
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR" && ok "Dossier $INSTALL_DIR supprimé (script + venv)"
fi

echo ""
echo -e "${GRN}${BLD}Vigie est supprimé.${NC}"
echo "  Le script d'installation (install_vigie.sh) reste dans ton dossier de téléchargement."
echo ""
