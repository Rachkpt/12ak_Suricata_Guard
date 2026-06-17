#!/usr/bin/env python3
"""
suricata_guard.py 
━━━━━━━━━━━━━━━━━━━━━━━
✅ Monitore fast.log en temps réel (polling 50ms)
✅ NMAP / Attaques / DDoS → Blocage immédiat + Alerte Telegram + Mail
✅ PING / ICMP            → Silencieux (visible via /ping)
✅ Bot Telegram avec menu épinglé + commandes slash
✅ Notifications Email (Gmail ou SMTP custom)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Outil développé et signé par : 12ak_H4ck

   Cette signature fait partie intégrante de l'outil — ne pas retirer.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import re
import time
import subprocess
import logging
import os
import signal
import sys
import threading
import asyncio
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from collections import defaultdict
from datetime import datetime

# ─────────────────────── DÉPENDANCES ───────────────────────────
try:
    from telegram import (
        Update, BotCommand,
        ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
    )
    from telegram.ext import (
        ApplicationBuilder, CommandHandler, MessageHandler,
        ContextTypes, filters
    )
except ImportError:
    print("❌  pip install python-telegram-bot --break-system-packages")
    sys.exit(1)


# ╔══════════════════════════════════════════════════════════════╗
# ║                        CONFIG                               ║
# ╚══════════════════════════════════════════════════════════════╝

FAST_LOG        = "/var/log/suricata/fast.log"
LOG_FILE        = "/var/log/suricata_guard.log"
BLOCKED_LOG     = "/var/log/suricata_blocked.log"
IPTABLES        = "/sbin/iptables"
ALERT_THRESHOLD = __ALERT_THRESHOLD__
CHAIN           = "SURICATA_GUARD"

# ── SIGNATURE OUTIL (NE PAS MODIFIER) ───────────────────────────
TOOL_SIGNATURE   = "12ak_H4ck"
TOOL_AUTHOR_FULL = "Aledji Ar-Rachad"

# ── TELEGRAM ────────────────────────────────────────────────────
TELEGRAM_TOKEN   = "__TELEGRAM_TOKEN__"
TELEGRAM_CHAT_ID = __TELEGRAM_CHAT_ID__        # ton chat_id (int)

# ── EMAIL ────────────────────────────────────────────────────────
EMAIL_ENABLED    = __EMAIL_ENABLED__             # Active/désactive les mails

# Choix du provider : "gmail" | "outlook" | "custom"
EMAIL_PROVIDER   = "__EMAIL_PROVIDER__"

# Ton adresse mail expéditeur
EMAIL_FROM       = "__EMAIL_FROM__"

# Mot de passe (Gmail → mot de passe d'application, pas ton vrai mdp !)
# Gmail  : https://myaccount.google.com/apppasswords
# Outlook: ton mot de passe normal
EMAIL_PASSWORD   = "__EMAIL_PASSWORD__"

# Destinataire(s) — tu peux en mettre plusieurs séparés par des virgules
EMAIL_TO         = __EMAIL_TO__

# ── SMTP custom (uniquement si EMAIL_PROVIDER = "custom") ────────
SMTP_HOST        = "__SMTP_HOST__"
SMTP_PORT        = __SMTP_PORT__
SMTP_USE_TLS     = __SMTP_USE_TLS__

# ── Événements qui déclenchent un mail ──────────────────────────
MAIL_ON_BLOCK    = True    # IP bloquée (NMAP / DDoS / flood)
MAIL_ON_THRESHOLD= True    # Seuil d'alertes atteint
MAIL_ON_START    = True    # Démarrage du service
MAIL_ON_UNBLOCK  = True    # IP débloquée via Telegram

# ── Mots-clés blocage immédiat + alerte Telegram + mail ─────────
INSTANT_BLOCK_KEYWORDS = [
    "NMAP", "PORT SCAN", "SCAN FRAG", "SCAN SHELL",
    "HPING3", "HPING", "DDOS", "DOS", "FLOOD",
    "M-SPLOIT", "SHELL", "TROJAN", "RECON",
    "XMAS", "SYN FLOOD", "UDP FLOOD", "ICMP FLOOD",
    "SSH BRUTEFORCE", "SSH BRUTE-FORCE", "RDP BRUTEFORCE",
    "RDP BRUTE-FORCE", "SMB SCAN", "SMB BRUTEFORCE",
    "DNS AMPLIFICATION", "DNS AMP", "SLOWLORIS",
    "SSL SCAN", "TLS SCAN", "FTP BRUTEFORCE", "WEB BRUTEFORCE",
    "SQLI", "SQL INJECTION", "XSS", "WEBSHELL", "C2 ",
    "EXPLOIT", "BACKDOOR", "BOTNET",
]

# ── Silencieux : stocké mais pas de notif auto ───────────────────
SILENT_KEYWORDS = [
    "PING ICMP", "ICMP DÉTECTÉ", "ICMP DETECTE",
    "PING DETECTED", "ICMP", "PING",
]

WHITELIST = {
    "127.0.0.1",
    "::1",
__WHITELIST_IPS__
}

# ── Libellés des boutons (clavier fixe en bas) ───────────────────
BTN_LAST_ALERTS = "⚠️ 10 Dernières Alertes"
BTN_PING_NMAP   = "🔍 IPs Ping & NMAP"
BTN_MALICIOUS   = "🛑 IPs Malveillantes / Logs"
BTN_BLOCKED     = "🚫 IPs Bloquées"
BTN_UNBLOCK     = "🔓 Débloquer une IP"
BTN_REFRESH     = "🔄 Actualiser"
BTN_BACK        = "⬅️ Retour au Menu"
BTN_UNBLOCK_ALL = "🔓 TOUT Débloquer"
UNBLOCK_PREFIX  = "🔓 Débloquer "

# ╔══════════════════════════════════════════════════════════════╗
# ║                       LOGGING                               ║
# ╚══════════════════════════════════════════════════════════════╝

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("suricata_guard")

# ╔══════════════════════════════════════════════════════════════╗
# ║                      ÉTAT GLOBAL                            ║
# ╚══════════════════════════════════════════════════════════════╝

alert_count    = defaultdict(int)
blocked_ips    = set()
recent_alerts  = []
ping_alerts    = []
MAX_ALERTS_MEM = 100
MAX_PING_MEM   = 50

_bot_loop      = None
_telegram_app  = None

LINE_RE = re.compile(
    r"(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)"
    r".*?\[\*\*\]\s+\[.*?\]\s+(.+?)\s+\[\*\*\]"
    r".*?\{(.*?)\}\s+"
    r"([\d\.]+|[0-9a-fA-F:]+)(?::\d+)?"
    r"\s*->\s*"
    r"([\d\.]+|[0-9a-fA-F:]+)"
)

# ╔══════════════════════════════════════════════════════════════╗
# ║                    ENVOI EMAIL                              ║
# ╚══════════════════════════════════════════════════════════════╝

# Config SMTP selon provider
SMTP_CONFIGS = {
    "gmail":   {"host": "smtp.gmail.com",    "port": 587, "tls": True},
    "outlook": {"host": "smtp.outlook.com",  "port": 587, "tls": True},
    "custom":  {"host": SMTP_HOST,           "port": SMTP_PORT, "tls": SMTP_USE_TLS},
}


def send_email(subject: str, body_html: str):
    """Envoie un mail HTML dans un thread séparé pour ne pas bloquer."""
    if not EMAIL_ENABLED:
        return
    threading.Thread(
        target=_send_email_sync,
        args=(subject, body_html),
        daemon=True
    ).start()


def _send_email_sync(subject: str, body_html: str):
    """Envoi SMTP synchrone (exécuté dans un thread séparé)."""
    try:
        cfg = SMTP_CONFIGS.get(EMAIL_PROVIDER, SMTP_CONFIGS["custom"])

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = EMAIL_FROM
        msg["To"]      = ", ".join(EMAIL_TO)

        # Version texte simple (fallback)
        text_plain = re.sub(r"<[^>]+>", "", body_html).strip()
        msg.attach(MIMEText(text_plain, "plain", "utf-8"))
        msg.attach(MIMEText(body_html,  "html",  "utf-8"))

        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as server:
            server.ehlo()
            if cfg["tls"]:
                server.starttls(context=context)
                server.ehlo()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())

        log.info(f"📧 Mail envoyé : {subject}")

    except Exception as e:
        log.error(f"❌ Erreur envoi mail: {e}")


def make_email_block(ip: str, reason: str, ts: str) -> tuple:
    """Génère le sujet + corps HTML pour un mail de blocage."""
    subject = f"🚨 [Suricata] IP BLOQUÉE : {ip}"
    body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;">
      <div style="max-width:600px;margin:auto;background:#fff;border-radius:8px;
                  border-left:5px solid #e74c3c;padding:20px;">
        <h2 style="color:#e74c3c;">🚨 Alerte Suricata Guard</h2>
        <table style="width:100%;border-collapse:collapse;">
          <tr><td style="padding:8px;font-weight:bold;color:#555;">Statut</td>
              <td style="padding:8px;color:#e74c3c;font-weight:bold;">IP BLOQUÉE</td></tr>
          <tr style="background:#f9f9f9;">
              <td style="padding:8px;font-weight:bold;color:#555;">IP</td>
              <td style="padding:8px;font-family:monospace;font-size:16px;">{ip}</td></tr>
          <tr><td style="padding:8px;font-weight:bold;color:#555;">Raison</td>
              <td style="padding:8px;">{reason}</td></tr>
          <tr style="background:#f9f9f9;">
              <td style="padding:8px;font-weight:bold;color:#555;">Date/Heure</td>
              <td style="padding:8px;">{ts}</td></tr>
          <tr><td style="padding:8px;font-weight:bold;color:#555;">Action</td>
              <td style="padding:8px;color:#e74c3c;">DROP via iptables</td></tr>
        </table>
        <hr style="margin:20px 0;border:none;border-top:1px solid #eee;">
        <p style="color:#888;font-size:12px;">
          Pour débloquer : <code>sudo iptables -D {CHAIN} -s {ip} -j DROP</code><br>
          Ou via le bot Telegram → menu Débloquer.
        </p>
        <p style="color:#aaa;font-size:11px;">Suricata Guard v4.0 — {datetime.now().strftime('%Y')}</p>
      </div>
    </body></html>
    """
    return subject, body


def make_email_unblock(ip: str) -> tuple:
    subject = f"✅ [Suricata] IP DÉBLOQUÉE : {ip}"
    body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;">
      <div style="max-width:600px;margin:auto;background:#fff;border-radius:8px;
                  border-left:5px solid #2ecc71;padding:20px;">
        <h2 style="color:#2ecc71;">✅ IP Débloquée</h2>
        <p>L'IP <strong style="font-family:monospace;">{ip}</strong> a été débloquée
        via le bot Telegram le <strong>{datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</strong>.</p>
        <p style="color:#aaa;font-size:11px;">Suricata Guard v4.0</p>
      </div>
    </body></html>
    """
    return subject, body


def make_email_start() -> tuple:
    subject = "🛡️ [Suricata] Service démarré"
    body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;">
      <div style="max-width:600px;margin:auto;background:#fff;border-radius:8px;
                  border-left:5px solid #3498db;padding:20px;">
        <h2 style="color:#3498db;">🛡️ Suricata Guard v4.0 démarré</h2>
        <table style="width:100%;border-collapse:collapse;">
          <tr><td style="padding:8px;font-weight:bold;color:#555;">Date</td>
              <td style="padding:8px;">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</td></tr>
          <tr style="background:#f9f9f9;">
              <td style="padding:8px;font-weight:bold;color:#555;">Seuil blocage</td>
              <td style="padding:8px;">{ALERT_THRESHOLD} alertes</td></tr>
          <tr><td style="padding:8px;font-weight:bold;color:#555;">Log surveillé</td>
              <td style="padding:8px;font-family:monospace;">{FAST_LOG}</td></tr>
          <tr style="background:#f9f9f9;">
              <td style="padding:8px;font-weight:bold;color:#555;">Chaîne iptables</td>
              <td style="padding:8px;font-family:monospace;">{CHAIN}</td></tr>
        </table>
        <p style="color:#aaa;font-size:11px;">Suricata Guard v4.0 — by {TOOL_SIGNATURE}</p>
      </div>
    </body></html>
    """
    return subject, body


# ╔══════════════════════════════════════════════════════════════╗
# ║                  TELEGRAM HELPERS                           ║
# ╚══════════════════════════════════════════════════════════════╝

def tg_send(message: str):
    if _bot_loop is None or _telegram_app is None:
        return
    asyncio.run_coroutine_threadsafe(
        _telegram_app.bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=message,
            parse_mode="HTML"
        ),
        _bot_loop
    )


def get_blocked_ips_list() -> list:
    """
    Retourne la liste des IPs actuellement bloquées dans la chaîne
    SURICATA_GUARD en parsant la sortie de `iptables -L CHAIN -n -v`.

    On utilise -v (verbose) qui donne un format stable avec des colonnes
    alignées, et on repère la colonne IP source en cherchant le premier
    token qui ressemble à une adresse IP (ou "0.0.0.0/0" pour "any"),
    plutôt que de se fier à un index fixe — ça évite le bug où la
    chaîne pointait sur le mauvais champ ("--") au lieu de l'IP.
    """
    try:
        result = subprocess.run(
            [IPTABLES, "-L", CHAIN, "-n", "-v", "--line-numbers"],
            capture_output=True, text=True
        )
    except Exception as e:
        log.error(f"Erreur lecture iptables : {e}")
        return []

    ip_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
    ips = []
    for line in result.stdout.strip().split("\n"):
        if "DROP" not in line:
            continue
        parts = line.split()
        # On cherche, après les colonnes fixes (num/pkts/bytes/target/prot/opt/in/out),
        # le premier champ qui matche un format IP — c'est la source.
        for tok in parts:
            if ip_re.match(tok) and tok != "0.0.0.0/0":
                ips.append(tok)
                break
    return ips


def build_main_menu() -> ReplyKeyboardMarkup:
    keyboard = [
        [KeyboardButton(BTN_LAST_ALERTS), KeyboardButton(BTN_PING_NMAP)],
        [KeyboardButton(BTN_MALICIOUS),   KeyboardButton(BTN_BLOCKED)],
        [KeyboardButton(BTN_UNBLOCK),     KeyboardButton(BTN_REFRESH)],
    ]
    return ReplyKeyboardMarkup(
        keyboard, resize_keyboard=True, is_persistent=True
    )


def build_unblock_menu() -> ReplyKeyboardMarkup:
    """
    Clavier fixe en bas listant chaque IP bloquée comme un bouton
    "🔓 Débloquer X.X.X.X", plus un bouton pour tout débloquer et un
    retour au menu principal.
    """
    ips = get_blocked_ips_list()
    keyboard = []
    for ip in ips[:15]:
        keyboard.append([KeyboardButton(f"{UNBLOCK_PREFIX}{ip}")])
    if ips:
        keyboard.append([KeyboardButton(BTN_UNBLOCK_ALL)])
    keyboard.append([KeyboardButton(BTN_BACK)])
    return ReplyKeyboardMarkup(
        keyboard, resize_keyboard=True, is_persistent=True
    )


# ╔══════════════════════════════════════════════════════════════╗
# ║              CONSTRUCTEURS DE TEXTE (réutilisables)          ║
# ╚══════════════════════════════════════════════════════════════╝
# Ces fonctions retournent uniquement le texte du message — elles sont
# utilisées à la fois par les commandes slash (/ping, /nmap, /blocked...)
# et par le gestionnaire des boutons du clavier fixe, pour éviter toute
# duplication et garantir que les deux affichent toujours la même chose.

def text_last_alerts() -> str:
    if not recent_alerts:
        return "ℹ️  Aucune alerte pour l'instant."
    last10 = recent_alerts[-10:]
    lines = ["⚠️  <b>10 Dernières Alertes Suricata</b>\n"]
    for a in reversed(last10):
        status = "🚫 BLOQUÉ" if a["src"] in blocked_ips else "⚠️ Alerte"
        lines.append(
            f"🕐 <code>{a['time']}</code>\n"
            f"📌 {a['msg']}\n"
            f"🌐 <code>{a['src']}</code> → <code>{a['dst']}</code> [{a['proto']}]\n"
            f"{status}\n"
        )
    return "\n".join(lines)[:4000]


def text_ping() -> str:
    if not ping_alerts:
        return "✅  Aucun ping/ICMP détecté pour l'instant."
    last = ping_alerts[-10:]
    lines = ["🏓  <b>Alertes Ping / ICMP (silencieuses)</b>\n"]
    for a in reversed(last):
        status = "🚫 BLOQUÉ" if a["src"] in blocked_ips else "🟡 Libre"
        lines.append(
            f"🕐 <code>{a['time']}</code>\n"
            f"🌐 <code>{a['src']}</code> → <code>{a['dst']}</code>\n"
            f"📌 {a['msg']} | {status}\n"
        )
    return "\n".join(lines)[:4000]


def text_nmap() -> str:
    nmap = [
        a for a in recent_alerts
        if any(k in a["msg"].upper() for k in ["NMAP", "PORT SCAN", "SCAN FRAG", "XMAS"])
    ]
    if not nmap:
        return "✅  Aucun scan NMAP détecté pour l'instant."
    seen = {}
    for a in nmap:
        ip = a["src"]
        if ip not in seen:
            seen[ip] = {"msg": a["msg"], "time": a["time"], "count": 0}
        seen[ip]["count"] += 1
    lines = ["🗺️  <b>Scans NMAP Détectés</b>\n"]
    for ip, info in seen.items():
        status = "🚫 BLOQUÉ" if ip in blocked_ips else "⚠️ Libre"
        lines.append(
            f"🌐 <code>{ip}</code> [{status}]\n"
            f"   📌 {info['msg']}\n"
            f"   🔁 {info['count']} fois | 🕐 {info['time']}\n"
        )
    return "\n".join(lines)[:4000]


def text_ping_nmap() -> str:
    """Combine ping + nmap + tout type de scan/recon détecté."""
    all_ips = [
        a for a in recent_alerts
        if any(k in a["msg"].upper() for k in
               ["NMAP", "PORT SCAN", "SCAN", "PING", "ICMP", "XMAS", "RECON"])
    ]
    if not all_ips:
        return (
            "✅  Aucun scan ou ping détecté pour l'instant.\n"
            "<i>Ce menu se remplit automatiquement dès qu'un ping ou "
            "un scan (NMAP, etc.) est détecté par Suricata.</i>"
        )
    seen = {}
    for a in all_ips:
        ip = a["src"]
        if ip not in seen:
            seen[ip] = {"msg": a["msg"], "time": a["time"], "count": 0}
        seen[ip]["count"] += 1
    lines = ["🔍  <b>IPs Ping / NMAP Détectées</b>\n"]
    for ip, info in seen.items():
        status = "🚫 BLOQUÉ" if ip in blocked_ips else "⚠️ Libre"
        lines.append(
            f"🌐 <code>{ip}</code> [{status}]\n"
            f"   📌 {info['msg']}\n"
            f"   🔁 {info['count']} fois | 🕐 {info['time']}\n"
        )
    return "\n".join(lines)[:4000]


def text_malicious() -> str:
    try:
        result = subprocess.run(["tail", "-30", BLOCKED_LOG], capture_output=True, text=True)
        raw = result.stdout.strip()
    except Exception as e:
        return f"❌ Erreur lecture log: {e}"
    if not raw:
        return "✅  Aucun log de blocage trouvé pour l'instant."
    lines = ["🛑  <b>Log des IP Malveillantes</b>\n"]
    for line in raw.split("\n")[-10:]:
        parts = line.split("|")
        if len(parts) >= 4:
            lines.append(
                f"🕐 {parts[0].strip()}\n"
                f"🚫 <code>{parts[2].strip()}</code>\n"
                f"📌 {parts[3].strip()}\n"
            )
        else:
            lines.append(f"<code>{line}</code>\n")
    return "\n".join(lines)[:4000]


def text_blocked() -> str:
    ips = get_blocked_ips_list()
    if not ips:
        return "✅  Aucune IP bloquée actuellement."
    lines = [f"🚫  <b>IPs Bloquées ({len(ips)})</b>\n"]
    for i, ip in enumerate(ips, 1):
        lines.append(f"  #{i} → <code>{ip}</code>")
    return "\n".join(lines)[:4000]


def text_about() -> str:
    return (
        "🛡️  <b>Suricata Guard v4.0</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🔰 Développé et signé par : <b>{TOOL_SIGNATURE}</b>\n"
        f"👤 {TOOL_AUTHOR_FULL}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 IPs surveillées en temps réel via Suricata\n"
        f"🚫 Blocage automatique iptables\n"
        f"📊 Seuil de blocage : {ALERT_THRESHOLD} alertes"
    )


# ╔══════════════════════════════════════════════════════════════╗
# ║                 COMMANDES SLASH BOT                         ║
# ╚══════════════════════════════════════════════════════════════╝

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    msg = await update.message.reply_text(
        "🛡️  <b>Suricata Guard v4.0</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Utilise les boutons ci-dessous 👇 ou les commandes :\n"
        "/ping    — 🏓 Alertes Ping / ICMP\n"
        "/nmap    — 🗺️ Scans NMAP détectés\n"
        "/blocked — 🚫 IPs bloquées\n"
        "/logs    — 📋 Derniers logs\n"
        "/menu    — 📋 Ré-afficher ce menu\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🔰 by <b>{TOOL_SIGNATURE}</b>",
        reply_markup=build_main_menu(),
        parse_mode="HTML"
    )
    try:
        await ctx.bot.pin_chat_message(
            chat_id=update.effective_chat.id,
            message_id=msg.message_id,
            disable_notification=True
        )
    except Exception:
        pass


async def cmd_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️  <b>Suricata Guard</b> — Menu",
        reply_markup=build_main_menu(),
        parse_mode="HTML"
    )


async def cmd_ping(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(text_ping(), parse_mode="HTML", reply_markup=build_main_menu())


async def cmd_nmap(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(text_nmap(), parse_mode="HTML", reply_markup=build_main_menu())


async def cmd_blocked(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(text_blocked(), parse_mode="HTML", reply_markup=build_main_menu())


async def cmd_logs(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not recent_alerts:
        await update.message.reply_text("ℹ️  Aucune alerte enregistrée.", reply_markup=build_main_menu())
        return
    last10 = recent_alerts[-10:]
    lines = ["📋  <b>10 Derniers Logs Suricata</b>\n"]
    for a in reversed(last10):
        status = "🚫 BLOQUÉ" if a["src"] in blocked_ips else "⚠️ Alerte"
        lines.append(
            f"🕐 <code>{a['time']}</code>\n"
            f"📌 {a['msg']}\n"
            f"🌐 <code>{a['src']}</code> → <code>{a['dst']}</code> [{a['proto']}] | {status}\n"
        )
    await update.message.reply_text(
        "\n".join(lines)[:4000], parse_mode="HTML", reply_markup=build_main_menu()
    )


async def cmd_about(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        text_about(), parse_mode="HTML", reply_markup=build_main_menu()
    )


# ╔══════════════════════════════════════════════════════════════╗
# ║         GESTIONNAIRE DES BOUTONS (clavier fixe en bas)       ║
# ╚══════════════════════════════════════════════════════════════╝
# Avec un ReplyKeyboardMarkup, Telegram envoie le libellé du bouton
# comme un simple message texte — on le traite donc ici comme du
# "routing" sur le contenu du texte reçu, et on répond avec un
# NOUVEAU message (impossible d'éditer le précédent comme avec un
# clavier inline), en renvoyant systématiquement le clavier adapté.

async def button_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()

    if text == BTN_LAST_ALERTS:
        await update.message.reply_text(
            text_last_alerts(), parse_mode="HTML", reply_markup=build_main_menu()
        )

    elif text == BTN_PING_NMAP:
        await update.message.reply_text(
            text_ping_nmap(), parse_mode="HTML", reply_markup=build_main_menu()
        )

    elif text == BTN_MALICIOUS:
        await update.message.reply_text(
            text_malicious(), parse_mode="HTML", reply_markup=build_main_menu()
        )

    elif text == BTN_BLOCKED:
        await update.message.reply_text(
            text_blocked(), parse_mode="HTML", reply_markup=build_main_menu()
        )

    elif text == BTN_REFRESH:
        await update.message.reply_text(
            "🔄  Menu actualisé.", reply_markup=build_main_menu()
        )

    elif text == BTN_UNBLOCK:
        ips = get_blocked_ips_list()
        if not ips:
            await update.message.reply_text(
                "✅  Aucune IP bloquée pour le moment.",
                reply_markup=build_main_menu()
            )
        else:
            await update.message.reply_text(
                "🔓  <b>Choisis une IP à débloquer :</b>",
                parse_mode="HTML",
                reply_markup=build_unblock_menu()
            )

    elif text == BTN_BACK:
        await update.message.reply_text(
            "🛡️  Menu principal.", reply_markup=build_main_menu()
        )

    elif text == BTN_UNBLOCK_ALL:
        subprocess.run([IPTABLES, "-F", CHAIN], capture_output=True)
        blocked_ips.clear()
        alert_count.clear()
        log.info("Toutes les IPs débloquées via Telegram.")
        if MAIL_ON_UNBLOCK:
            s, b = make_email_unblock("TOUTES")
            send_email(s, b)
        await update.message.reply_text(
            "✅  Toutes les IPs ont été débloquées !",
            parse_mode="HTML",
            reply_markup=build_main_menu()
        )

    elif text.startswith(UNBLOCK_PREFIX):
        ip_to_unblock = text.replace(UNBLOCK_PREFIX, "").strip()
        subprocess.run(
            [IPTABLES, "-D", CHAIN, "-s", ip_to_unblock, "-j", "DROP"],
            capture_output=True
        )
        blocked_ips.discard(ip_to_unblock)
        alert_count.pop(ip_to_unblock, None)
        log.info(f"IP {ip_to_unblock} débloquée via Telegram.")
        if MAIL_ON_UNBLOCK:
            s, b = make_email_unblock(ip_to_unblock)
            send_email(s, b)

        remaining = get_blocked_ips_list()
        if remaining:
            await update.message.reply_text(
                f"✅  IP <code>{ip_to_unblock}</code> débloquée !\n"
                f"🔓  Il reste {len(remaining)} IP(s) bloquée(s).",
                parse_mode="HTML",
                reply_markup=build_unblock_menu()
            )
        else:
            await update.message.reply_text(
                f"✅  IP <code>{ip_to_unblock}</code> débloquée !\n"
                f"🎉  Plus aucune IP bloquée.",
                parse_mode="HTML",
                reply_markup=build_main_menu()
            )

    else:
        # Texte non reconnu (l'utilisateur a tapé autre chose qu'un bouton)
        await update.message.reply_text(
            "❓  Utilise les boutons ci-dessous 👇 ou tape /menu.",
            reply_markup=build_main_menu()
        )

# ╔══════════════════════════════════════════════════════════════╗
# ║                      IPTABLES                               ║
# ╚══════════════════════════════════════════════════════════════╝

def run_cmd(cmd: list) -> bool:
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        log.error(f"Échec: {' '.join(cmd)} → {e.stderr.decode().strip()}")
        return False


def setup_chain():
    subprocess.run([IPTABLES, "-N", CHAIN], capture_output=True)
    res = subprocess.run([IPTABLES, "-C", "INPUT", "-j", CHAIN], capture_output=True)
    if res.returncode != 0:
        run_cmd([IPTABLES, "-I", "INPUT",   "1", "-j", CHAIN])
        run_cmd([IPTABLES, "-I", "FORWARD", "1", "-j", CHAIN])
    log.info(f"Chaîne iptables '{CHAIN}' prête.")


def block_ip(ip: str, reason: str, alert_msg: str = ""):
    """Bloque IP + envoie Telegram + envoie Mail simultanément."""
    if ip in blocked_ips or ip in WHITELIST:
        return
    blocked_ips.add(ip)
    alert_count.pop(ip, None)

    run_cmd([IPTABLES, "-A", CHAIN, "-s", ip, "-j", "DROP"])
    log.warning(f"BLOQUÉ  {ip:<20} | {reason}")

    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    with open(BLOCKED_LOG, "a") as f:
        f.write(f"{datetime.now().isoformat()} | BLOCKED | {ip} | {reason}\n")

    # ── Telegram (immédiat) ──
    tg_send(
        f"🚨 <b>ALERTE — IP BLOQUÉE</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 IP     : <code>{ip}</code>\n"
        f"📌 Détect : {alert_msg or reason}\n"
        f"🔒 Action : DROP immédiat\n"
        f"🕐 {ts}"
    )

    # ── Email (thread séparé pour ne pas ralentir) ──
    if MAIL_ON_BLOCK:
        s, b = make_email_block(ip, alert_msg or reason, ts)
        send_email(s, b)


# ╔══════════════════════════════════════════════════════════════╗
# ║                    CLASSIFIERS                              ║
# ╚══════════════════════════════════════════════════════════════╝

def is_instant_block(msg: str) -> bool:
    msg_up = msg.upper()
    return any(kw in msg_up for kw in INSTANT_BLOCK_KEYWORDS)


def is_silent(msg: str) -> bool:
    msg_up = msg.upper()
    return any(kw in msg_up for kw in SILENT_KEYWORDS)


# ╔══════════════════════════════════════════════════════════════╗
# ║                    PROCESS LINE                             ║
# ╚══════════════════════════════════════════════════════════════╝

def process_line(line: str):
    m = LINE_RE.search(line)
    if not m:
        return

    ts     = m.group(1)
    msg    = m.group(2).strip()
    proto  = m.group(3).strip()
    src_ip = m.group(4).strip()
    dst_ip = m.group(5).strip()

    entry = {"time": ts, "msg": msg, "proto": proto, "src": src_ip, "dst": dst_ip}

    # ── PING silencieux ──
    if is_silent(msg):
        ping_alerts.append(entry)
        if len(ping_alerts) > MAX_PING_MEM:
            ping_alerts.pop(0)
        recent_alerts.append(entry)
        if len(recent_alerts) > MAX_ALERTS_MEM:
            recent_alerts.pop(0)
        log.info(f"PING silencieux {src_ip:<20} (/ping pour voir)")
        return

    recent_alerts.append(entry)
    if len(recent_alerts) > MAX_ALERTS_MEM:
        recent_alerts.pop(0)

    if src_ip in WHITELIST or src_ip in blocked_ips:
        return

    # ── Blocage immédiat ──
    if is_instant_block(msg):
        log.warning(f"INSTANT BLOCK {src_ip:<20} | {msg}")
        block_ip(src_ip, f"INSTANT [{msg}]", msg)
        return

    # ── Compteur seuil ──
    alert_count[src_ip] += 1
    count = alert_count[src_ip]
    log.info(f"Alerte {count:>3}/{ALERT_THRESHOLD}  {src_ip:<20} | {msg}")
    if count >= ALERT_THRESHOLD:
        block_ip(src_ip, f"SEUIL ({count} alertes) [{msg}]", msg)


# ╔══════════════════════════════════════════════════════════════╗
# ║                   MONITOR LOOP                              ║
# ╚══════════════════════════════════════════════════════════════╝

def monitor_loop():
    log.info(f"En attente de {FAST_LOG}...")
    while not os.path.exists(FAST_LOG):
        time.sleep(2)
    log.info(f"Surveillance active : {FAST_LOG}")
    with open(FAST_LOG, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                process_line(line)
            else:
                time.sleep(0.05)   # polling 50ms


# ╔══════════════════════════════════════════════════════════════╗
# ║                        MAIN                                 ║
# ╚══════════════════════════════════════════════════════════════╝

def graceful_exit(sig, frame):
    log.info("Arrêt propre. Les règles iptables restent en place.")
    sys.exit(0)


async def post_init(app):
    global _bot_loop
    _bot_loop = asyncio.get_running_loop()
    await app.bot.set_my_commands([
        BotCommand("start",   "Demarrer et epingler le menu"),
        BotCommand("menu",    "Afficher le menu"),
        BotCommand("ping",    "Alertes Ping / ICMP"),
        BotCommand("nmap",    "Scans NMAP detectes"),
        BotCommand("blocked", "IPs bloquees"),
        BotCommand("logs",    "Derniers logs Suricata"),
        BotCommand("about",   "A propos de l'outil"),
    ])


def main():
    global _telegram_app

    if os.geteuid() != 0:
        print("Lance en root (sudo).")
        sys.exit(1)

    signal.signal(signal.SIGINT,  graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    setup_chain()

    log.info("══════════════════════════════════════════")
    log.info("  suricata_guard.py  -  DEMARRE     ")
    log.info(f"  Seuil blocage : {ALERT_THRESHOLD} alertes")
    log.info(f"  Email activé  : {EMAIL_ENABLED} ({EMAIL_PROVIDER})")
    log.info(f"  Email vers    : {EMAIL_TO}")
    log.info(f"  Signé         : {TOOL_SIGNATURE} ({TOOL_AUTHOR_FULL})")
    log.info("══════════════════════════════════════════")

    app = ApplicationBuilder().token(TELEGRAM_TOKEN).post_init(post_init).build()
    _telegram_app = app

    app.add_handler(CommandHandler("start",   cmd_start))
    app.add_handler(CommandHandler("menu",    cmd_menu))
    app.add_handler(CommandHandler("ping",    cmd_ping))
    app.add_handler(CommandHandler("nmap",    cmd_nmap))
    app.add_handler(CommandHandler("blocked", cmd_blocked))
    app.add_handler(CommandHandler("logs",    cmd_logs))
    app.add_handler(CommandHandler("about",   cmd_about))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, button_handler))

    # Mail de démarrage
    if MAIL_ON_START:
        s, b = make_email_start()
        send_email(s, b)

    # Notification Telegram de démarrage
    threading.Thread(
        target=lambda: (time.sleep(3), tg_send(
            "🛡️ <b>Suricata Guard démarré</b>\n"
            f"📧 Notifications mail : {'✅ Activées' if EMAIL_ENABLED else '❌ Désactivées'}\n"
            f"🕐 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"
            f"🔰 by <b>{TOOL_SIGNATURE}</b>"
        )),
        daemon=True
    ).start()

    threading.Thread(target=monitor_loop, daemon=True).start()

    log.info("Bot Telegram démarré — tape /start dans Telegram")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
