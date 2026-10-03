#!/usr/bin/env python3
"""
vigie.py
━━━━━━━━━━━━━━━━━━━━━━━
✅ Surveille fast.log de Suricata en temps réel (polling 50 ms)
✅ NMAP / attaques / DDoS → blocage immédiat iptables + alerte Telegram + mail
✅ Seuil glissant pour les autres alertes
✅ PING / ICMP            → silencieux (visible via /ping)
✅ Bot Telegram réservé à UN chat (chat_id configuré)
✅ Notifications email (Gmail, Outlook ou SMTP custom)

Configuration : /etc/vigie/config.json (généré par l'installeur)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Outil développé et signé par : __KAT4NA_

   Cette signature fait partie intégrante de l'outil — ne pas retirer.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import smtplib
import ssl
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

try:
    from telegram import BotCommand, KeyboardButton, ReplyKeyboardMarkup, Update
    from telegram.ext import (
        ApplicationBuilder, CommandHandler, ContextTypes, MessageHandler, filters,
    )
    TELEGRAM_AVAILABLE = True
except ImportError:  # le blocage et les mails fonctionnent sans Telegram
    TELEGRAM_AVAILABLE = False


# ╔══════════════════════════════════════════════════════════════╗
# ║                        CONFIG                               ║
# ╚══════════════════════════════════════════════════════════════╝

VERSION          = "4.1"
CONFIG_FILE      = os.environ.get("VIGIE_CONFIG", "/etc/vigie/config.json")
LOG_FILE         = os.environ.get("VIGIE_LOG", "/var/log/vigie.log")
BLOCKED_LOG      = os.environ.get("VIGIE_BLOCKED_LOG", "/var/log/vigie_blocked.log")
IPTABLES         = shutil.which("iptables") or "/sbin/iptables"
CHAIN            = "VIGIE"
MAX_RULES_REMOVE = 50  # sécurité : nombre max de règles DROP retirées pour une même IP

# ── SIGNATURE OUTIL (NE PAS MODIFIER) ───────────────────────────
TOOL_SIGNATURE   = "__KAT4NA_"
TOOL_AUTHOR_FULL = "Aledji Ar-Rachad"


def load_config(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        sys.exit(f"Configuration introuvable : {path} (relance l'installeur)")
    except json.JSONDecodeError as e:
        sys.exit(f"Configuration invalide ({path}) : {e}")


CFG = load_config(CONFIG_FILE)

FAST_LOG        = CFG.get("fast_log", "/var/log/suricata/fast.log")
ALERT_THRESHOLD = int(CFG.get("alert_threshold", 5))
ALERT_WINDOW    = int(CFG.get("alert_window_seconds", 600))

# ── TELEGRAM ────────────────────────────────────────────────────
TELEGRAM_TOKEN   = CFG.get("telegram_token", "")
TELEGRAM_CHAT_ID = int(CFG.get("telegram_chat_id") or 0)
TELEGRAM_ENABLED = (
    bool(CFG.get("telegram_enabled")) and bool(TELEGRAM_TOKEN) and TELEGRAM_CHAT_ID != 0
)

# ── EMAIL ───────────────────────────────────────────────────────
EMAIL_ENABLED  = bool(CFG.get("email_enabled"))
EMAIL_PROVIDER = CFG.get("email_provider", "gmail")
EMAIL_FROM     = CFG.get("email_from", "")
EMAIL_PASSWORD = CFG.get("email_password", "")
EMAIL_TO       = list(CFG.get("email_to", []))
SMTP_HOST      = CFG.get("smtp_host", "")
SMTP_PORT      = int(CFG.get("smtp_port", 587))
SMTP_USE_TLS   = bool(CFG.get("smtp_use_tls", True))

MAIL_ON_BLOCK   = True
MAIL_ON_UNBLOCK = True
MAIL_ON_START   = True

# ── Mots-clés : blocage immédiat (testé AVANT le mode silencieux) ──
INSTANT_BLOCK_KEYWORDS = [
    "NMAP", "PORT SCAN", "SCAN FRAG", "SCAN SHELL",
    "HPING3", "HPING", "DDOS", "DOS", "FLOOD",
    "M-SPLOIT", "SHELL", "TROJAN", "RECON",
    "XMAS", "SYN FLOOD", "UDP FLOOD", "ICMP FLOOD",
    "SSH BRUTEFORCE", "SSH BRUTE-FORCE", "RDP BRUTEFORCE",
    "RDP BRUTE-FORCE", "SMB SCAN", "SMB BRUTEFORCE",
    "DNS AMPLIFICATION", "DNS AMP", "SLOWLORIS",
    "SSL SCAN", "TLS SCAN", "FTP BRUTEFORCE", "WEB BRUTEFORCE",
    "SQLI", "SQL INJECTION", "XSS", "WEBSHELL", "C2",
    "EXPLOIT", "BACKDOOR", "BOTNET",
]

# ── Silencieux : stocké (/ping) mais pas de notification ─────────
SILENT_KEYWORDS = [
    "PING ICMP", "ICMP DÉTECTÉ", "ICMP DETECTE",
    "PING DETECTED", "ICMP", "PING",
]


def _compile_keywords(words: list) -> re.Pattern:
    """Mots courts : mot entier (évite « DOS » dans « DOSSIER »).
    Mots longs : début de mot (« SHELL » trouve « SHELLCODE »)."""
    alts = []
    for w in words:
        esc = re.escape(w)
        alts.append(rf"\b{esc}\b" if len(w) <= 4 else rf"\b{esc}")
    return re.compile("|".join(alts), re.IGNORECASE)


INSTANT_RE = _compile_keywords(INSTANT_BLOCK_KEYWORDS)
SILENT_RE  = _compile_keywords(SILENT_KEYWORDS)
NMAP_RE    = re.compile(r"NMAP|PORT SCAN|SCAN FRAG|XMAS", re.IGNORECASE)
PING_NMAP_RE = re.compile(r"NMAP|PORT SCAN|SCAN|PING|ICMP|XMAS|RECON", re.IGNORECASE)

WHITELIST = {"127.0.0.1", "::1"} | set(CFG.get("whitelist", []))

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
# ║                      ÉTAT GLOBAL                            ║
# ╚══════════════════════════════════════════════════════════════╝

log = logging.getLogger("vigie")

STATE_LOCK    = threading.RLock()
blocked_ips   = set()
alert_hits    = defaultdict(deque)   # ip -> timestamps des alertes (fenêtre glissante)
recent_alerts = deque(maxlen=100)
ping_alerts   = deque(maxlen=50)

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
IPV4_RULE_RE = re.compile(r"-s\s+([0-9.]+)(?:/32)?\s+-j\s+DROP")


# ╔══════════════════════════════════════════════════════════════╗
# ║                        LOGGING                              ║
# ╚══════════════════════════════════════════════════════════════╝

def setup_logging():
    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(logging.FileHandler(LOG_FILE))
    except OSError as e:
        print(f"⚠ Impossible d'ouvrir {LOG_FILE} : {e}")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )


def is_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def local_ipv4_addresses() -> set:
    """Adresses IPv4 du serveur : on ne bloque jamais le serveur lui-même
    (une règle peut se déclencher sur son propre trafic sortant)."""
    res = _run(["ip", "-o", "-4", "addr", "show"])
    if res is None or res.returncode != 0:
        return set()
    return set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", res.stdout))


def _esc(value) -> str:
    """Échappe pour le mode HTML de Telegram (évite les messages rejetés)."""
    return html.escape(str(value), quote=False)


def _is_blocked(ip: str) -> bool:
    with STATE_LOCK:
        return ip in blocked_ips


# ╔══════════════════════════════════════════════════════════════╗
# ║                    ENVOI EMAIL                              ║
# ╚══════════════════════════════════════════════════════════════╝

SMTP_PRESETS = {
    "gmail":   ("smtp.gmail.com", 587, True),
    "outlook": ("smtp.outlook.com", 587, True),
}


def _smtp_params():
    if EMAIL_PROVIDER in SMTP_PRESETS:
        return SMTP_PRESETS[EMAIL_PROVIDER]
    return SMTP_HOST, SMTP_PORT, SMTP_USE_TLS


def send_email(subject: str, body_html: str):
    """Envoie un mail dans un thread séparé pour ne pas bloquer."""
    if not EMAIL_ENABLED or not EMAIL_TO:
        return
    threading.Thread(target=_send_email_sync, args=(subject, body_html), daemon=True).start()


def _send_email_sync(subject: str, body_html: str):
    try:
        host, port, use_tls = _smtp_params()
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        msg["To"] = ", ".join(EMAIL_TO)
        text_plain = re.sub(r"<[^>]+>", "", body_html).strip()
        msg.attach(MIMEText(text_plain, "plain", "utf-8"))
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        context = ssl.create_default_context()
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=15, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=15)
        with server:
            server.ehlo()
            if use_tls and port != 465:
                server.starttls(context=context)
                server.ehlo()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        log.info(f"📧 Mail envoyé : {subject}")
    except Exception as e:
        log.error(f"❌ Erreur envoi mail : {e}")


def _mail_html(color: str, title: str, rows: list, footer_html: str = "") -> str:
    rows_html = "".join(
        f'<tr style="{"background:#f9f9f9;" if i % 2 else ""}">'
        f'<td style="padding:8px;font-weight:bold;color:#555;">{_esc(k)}</td>'
        f'<td style="padding:8px;font-family:monospace;">{_esc(v)}</td></tr>'
        for i, (k, v) in enumerate(rows)
    )
    return f"""<html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;">
<div style="max-width:600px;margin:auto;background:#fff;border-radius:8px;border-left:5px solid {color};padding:20px;">
<h2 style="color:{color};">{_esc(title)}</h2>
<table style="width:100%;border-collapse:collapse;">{rows_html}</table>
<p style="color:#888;font-size:12px;">{footer_html}</p>
<p style="color:#aaa;font-size:11px;">Vigie v{VERSION} — by {TOOL_SIGNATURE}</p>
</div></body></html>"""


def make_email_block(ip: str, reason: str, ts: str) -> tuple:
    subject = f"🚨 [Suricata] IP BLOQUÉE : {ip}"
    body = _mail_html(
        "#e74c3c", "🚨 Alerte Vigie",
        [("Statut", "IP BLOQUÉE"), ("IP", ip), ("Raison", reason),
         ("Date/Heure", ts), ("Action", "DROP via iptables")],
        footer_html=(
            f"Pour débloquer : <code>sudo iptables -D {CHAIN} -s {_esc(ip)} -j DROP</code>"
            "<br>Ou via le bot Telegram → 🔓 Débloquer une IP."
        ),
    )
    return subject, body


def make_email_unblock(ip: str) -> tuple:
    subject = f"✅ [Suricata] IP DÉBLOQUÉE : {ip}"
    body = _mail_html(
        "#2ecc71", "✅ IP débloquée",
        [("IP", ip), ("Date/Heure", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))],
        footer_html="Débloquée via le bot Telegram ou le script de désinstallation.",
    )
    return subject, body


def make_email_start() -> tuple:
    subject = "🛡️ [Suricata] Service démarré"
    body = _mail_html(
        "#3498db", f"🛡️ Vigie v{VERSION} démarré",
        [("Date", datetime.now().strftime("%d/%m/%Y %H:%M:%S")),
         ("Seuil blocage", f"{ALERT_THRESHOLD} alertes / {ALERT_WINDOW} s"),
         ("Log surveillé", FAST_LOG),
         ("Chaîne iptables", CHAIN),
         ("Telegram", "activé" if TELEGRAM_ENABLED else "désactivé")],
    )
    return subject, body


# ╔══════════════════════════════════════════════════════════════╗
# ║                  TELEGRAM HELPERS                           ║
# ╚══════════════════════════════════════════════════════════════╝

def _log_tg_result(fut):
    try:
        exc = fut.exception()
    except Exception:
        return
    if exc is not None:
        log.error(f"❌ Envoi Telegram échoué : {exc}")


def tg_send(message: str):
    if not TELEGRAM_ENABLED or _bot_loop is None or _telegram_app is None:
        return
    fut = asyncio.run_coroutine_threadsafe(
        _telegram_app.bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message, parse_mode="HTML"),
        _bot_loop,
    )
    fut.add_done_callback(_log_tg_result)


def _join_limited(header: str, blocks: list, limit: int = 4000) -> str:
    """Assemble des blocs HTML complets sans jamais dépasser la limite Telegram
    (couper au milieu d'une balise <code> casserait le message)."""
    out, size = [header], len(header)
    for block in blocks:
        if size + len(block) + 2 > limit:
            out.append("<i>… (liste tronquée)</i>")
            break
        out.append(block)
        size += len(block) + 2
    return "\n\n".join(out)


# ╔══════════════════════════════════════════════════════════════╗
# ║                 COMMANDES IPTABLES                          ║
# ╚══════════════════════════════════════════════════════════════╝

def _run(cmd: list, timeout: int = 30):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        log.error(f"Commande impossible {' '.join(cmd)} : {e}")
        return None


def _rc(cmd: list) -> int:
    res = _run(cmd)
    return -1 if res is None else res.returncode


def run_cmd(cmd: list) -> bool:
    res = _run(cmd)
    if res is None:
        return False
    if res.returncode != 0:
        log.error(f"Échec : {' '.join(cmd)} → {res.stderr.strip()}")
        return False
    return True


def parse_blocked_ips(iptables_output: str) -> list:
    """Extrait les IPs de la sortie `iptables -S VIGIE` (sans doublon)."""
    seen, ips = set(), []
    for line in iptables_output.splitlines():
        m = IPV4_RULE_RE.search(line)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            ips.append(m.group(1))
    return ips


def get_blocked_ips_list() -> list:
    res = _run([IPTABLES, "-S", CHAIN])
    if res is None or res.returncode != 0:
        return []
    return parse_blocked_ips(res.stdout)


def persist_rules():
    """Sauvegarde les règles pour qu'elles survivent à un redémarrage."""
    if shutil.which("netfilter-persistent") is None:
        return
    threading.Thread(target=_run, args=(["netfilter-persistent", "save"], 60), daemon=True).start()


def setup_chain():
    _run([IPTABLES, "-N", CHAIN])  # erreur ignorée : la chaîne existe déjà
    for chain in ("INPUT", "FORWARD"):
        if _rc([IPTABLES, "-C", chain, "-j", CHAIN]) != 0:
            run_cmd([IPTABLES, "-I", chain, "1", "-j", CHAIN])
    with STATE_LOCK:
        blocked_ips.update(get_blocked_ips_list())
    log.info(f"Chaîne iptables '{CHAIN}' prête ({len(blocked_ips)} IP déjà bloquée(s)).")


def block_ip(ip: str, reason: str, alert_msg: str = ""):
    with STATE_LOCK:
        if ip in blocked_ips or ip in WHITELIST:
            return
        blocked_ips.add(ip)
        alert_hits.pop(ip, None)

    if not run_cmd([IPTABLES, "-A", CHAIN, "-s", ip, "-j", "DROP"]):
        with STATE_LOCK:
            blocked_ips.discard(ip)
        return
    persist_rules()

    log.warning(f"BLOQUÉ  {ip:<20} | {reason}")
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    try:
        with open(BLOCKED_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} | BLOCKED | {ip} | {reason}\n")
    except OSError as e:
        log.error(f"Impossible d'écrire {BLOCKED_LOG} : {e}")

    tg_send(
        "🚨 <b>ALERTE — IP BLOQUÉE</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 IP     : <code>{_esc(ip)}</code>\n"
        f"📌 Détect : {_esc(alert_msg or reason)}\n"
        "🔒 Action : DROP immédiat\n"
        f"🕐 {ts}"
    )
    if MAIL_ON_BLOCK:
        send_email(*make_email_block(ip, alert_msg or reason, ts))


def unblock_ip(ip: str) -> bool:
    """Retire TOUTES les règles DROP de cette IP (il peut y en avoir plusieurs)."""
    removed = 0
    for _ in range(MAX_RULES_REMOVE):
        if _rc([IPTABLES, "-D", CHAIN, "-s", ip, "-j", "DROP"]) != 0:
            break
        removed += 1
    with STATE_LOCK:
        blocked_ips.discard(ip)
        alert_hits.pop(ip, None)
    if removed:
        persist_rules()
        log.info(f"IP {ip} débloquée ({removed} règle(s) retirée(s)).")
        if MAIL_ON_UNBLOCK:
            send_email(*make_email_unblock(ip))
    return removed > 0


def unblock_all() -> int:
    count = len(get_blocked_ips_list())
    _run([IPTABLES, "-F", CHAIN])
    with STATE_LOCK:
        blocked_ips.clear()
        alert_hits.clear()
    persist_rules()
    log.info(f"Toutes les IPs débloquées ({count}).")
    if MAIL_ON_UNBLOCK and count:
        send_email(*make_email_unblock("TOUTES"))
    return count


# ╔══════════════════════════════════════════════════════════════╗
# ║              CONSTRUCTEURS DE TEXTE (partagés)               ║
# ╚══════════════════════════════════════════════════════════════╝
# Utilisés à la fois par les commandes (/ping, /nmap…) et par les
# boutons du clavier fixe : les deux affichent toujours la même chose.

def _group_by_src(alerts: list) -> dict:
    groups = {}
    for a in alerts:  # ordre chronologique : on garde la dernière occurrence
        g = groups.setdefault(a["src"], {"count": 0})
        g["count"] += 1
        g["msg"], g["time"] = a["msg"], a["time"]
    return groups


def _snapshot(dq: deque, n: int) -> list:
    with STATE_LOCK:
        return list(dq)[-n:]


def _alert_block(a: dict) -> str:
    status = "🚫 BLOQUÉ" if _is_blocked(a["src"]) else "⚠️ Alerte"
    return (
        f"🕐 <code>{_esc(a['time'])}</code>\n"
        f"📌 {_esc(a['msg'])}\n"
        f"🌐 <code>{_esc(a['src'])}</code> → <code>{_esc(a['dst'])}</code> "
        f"[{_esc(a['proto'])}] {status}"
    )


def _group_block(ip: str, info: dict) -> str:
    status = "🚫 BLOQUÉ" if _is_blocked(ip) else "⚠️ Libre"
    return (
        f"🌐 <code>{_esc(ip)}</code> [{status}]\n"
        f"   📌 {_esc(info['msg'])}\n"
        f"   🔁 {info['count']} fois | 🕐 {_esc(info['time'])}"
    )


def text_last_alerts() -> str:
    last = _snapshot(recent_alerts, 10)
    if not last:
        return "ℹ️  Aucune alerte pour l'instant."
    blocks = [_alert_block(a) for a in reversed(last)]
    return _join_limited("⚠️  <b>10 Dernières Alertes Suricata</b>", blocks)


def text_logs() -> str:
    last = _snapshot(recent_alerts, 10)
    if not last:
        return "ℹ️  Aucune alerte enregistrée."
    blocks = [_alert_block(a) for a in reversed(last)]
    return _join_limited("📋  <b>10 Derniers Logs Suricata</b>", blocks)


def text_ping() -> str:
    last = _snapshot(ping_alerts, 10)
    if not last:
        return "✅  Aucun ping/ICMP détecté pour l'instant."
    blocks = [
        f"🕐 <code>{_esc(a['time'])}</code>\n"
        f"🌐 <code>{_esc(a['src'])}</code> → <code>{_esc(a['dst'])}</code>\n"
        f"📌 {_esc(a['msg'])} | {'🚫 BLOQUÉ' if _is_blocked(a['src']) else '🟡 Libre'}"
        for a in reversed(last)
    ]
    return _join_limited("🏓  <b>Alertes Ping / ICMP (silencieuses)</b>", blocks)


def _scan_text(title: str, alerts: list, empty: str) -> str:
    if not alerts:
        return empty
    groups = _group_by_src(alerts)
    blocks = [_group_block(ip, info) for ip, info in groups.items()]
    return _join_limited(title, blocks)


def text_nmap() -> str:
    alerts = [a for a in list(recent_alerts) if NMAP_RE.search(a["msg"])]
    return _scan_text("🗺️  <b>Scans NMAP Détectés</b>", alerts,
                      "✅  Aucun scan NMAP détecté pour l'instant.")


def text_ping_nmap() -> str:
    alerts = [a for a in list(recent_alerts) if PING_NMAP_RE.search(a["msg"])]
    return _scan_text(
        "🔍  <b>IPs Ping / NMAP Détectées</b>", alerts,
        "✅  Aucun scan ou ping détecté pour l'instant.\n"
        "<i>Ce menu se remplit dès qu'un ping ou un scan est détecté par Suricata.</i>",
    )


def _read_tail(path: str, n: int):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return []
    return [line.rstrip("\n") for line in lines[-n:] if line.strip()]


def text_malicious() -> str:
    try:
        lines = _read_tail(BLOCKED_LOG, 10)
    except OSError as e:
        return f"❌ Erreur lecture log : {_esc(e)}"
    if not lines:
        return "✅  Aucun blocage enregistré pour l'instant."
    blocks = []
    for line in reversed(lines):
        parts = line.split("|", 3)  # ts | BLOCKED | ip | raison
        if len(parts) == 4:
            blocks.append(
                f"🕐 {_esc(parts[0].strip())}\n"
                f"🚫 <code>{_esc(parts[2].strip())}</code>\n"
                f"📌 {_esc(parts[3].strip())}"
            )
        else:
            blocks.append(f"<code>{_esc(line)}</code>")
    return _join_limited("🛑  <b>Log des IP malveillantes (dernières)</b>", blocks)


def text_blocked() -> str:
    ips = get_blocked_ips_list()
    if not ips:
        return "✅  Aucune IP bloquée actuellement."
    lines = [f"  #{i} → <code>{_esc(ip)}</code>" for i, ip in enumerate(ips, 1)]
    return _join_limited(f"🚫  <b>IPs Bloquées ({len(ips)})</b>", ["\n".join(lines)])


def text_about() -> str:
    return (
        f"🛡️  <b>Vigie v{VERSION}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🔰 Développé et signé par : <b>{TOOL_SIGNATURE}</b>\n"
        f"👤 {TOOL_AUTHOR_FULL}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🌐 IPs surveillées en temps réel via Suricata\n"
        "🚫 Blocage automatique iptables\n"
        f"📊 Seuil : {ALERT_THRESHOLD} alertes / {ALERT_WINDOW} s"
    )


# ╔══════════════════════════════════════════════════════════════╗
# ║                 CLAVIERS TELEGRAM                           ║
# ╚══════════════════════════════════════════════════════════════╝

def build_main_menu():
    keyboard = [
        [KeyboardButton(BTN_LAST_ALERTS), KeyboardButton(BTN_PING_NMAP)],
        [KeyboardButton(BTN_MALICIOUS), KeyboardButton(BTN_BLOCKED)],
        [KeyboardButton(BTN_UNBLOCK), KeyboardButton(BTN_REFRESH)],
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, is_persistent=True)


def build_unblock_menu():
    ips = get_blocked_ips_list()
    keyboard = [[KeyboardButton(f"{UNBLOCK_PREFIX}{ip}")] for ip in ips[:15]]
    if ips:
        keyboard.append([KeyboardButton(BTN_UNBLOCK_ALL)])
    keyboard.append([KeyboardButton(BTN_BACK)])
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, is_persistent=True)


# ╔══════════════════════════════════════════════════════════════╗
# ║                 COMMANDES SLASH BOT                         ║
# ╚══════════════════════════════════════════════════════════════╝
# Le filtre CHAT_FILTER ne laisse passer que le chat configuré :
# les messages des autres personnes ne reçoivent aucune réponse.

CHAT_FILTER = filters.Chat(chat_id=TELEGRAM_CHAT_ID) if TELEGRAM_AVAILABLE else None


async def _reply(update, text: str, markup=None):
    await update.message.reply_text(
        text, parse_mode="HTML", reply_markup=markup or build_main_menu()
    )


async def cmd_start(update, ctx):
    msg = await update.message.reply_text(
        f"🛡️  <b>Vigie v{VERSION}</b>\n"
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
        parse_mode="HTML",
    )
    try:
        await ctx.bot.pin_chat_message(
            chat_id=update.effective_chat.id, message_id=msg.message_id, disable_notification=True
        )
    except Exception:
        pass


async def cmd_menu(update, ctx):
    await _reply(update, "🛡️  <b>Vigie</b> — Menu")


async def cmd_ping(update, ctx):
    await _reply(update, await asyncio.to_thread(text_ping))


async def cmd_nmap(update, ctx):
    await _reply(update, await asyncio.to_thread(text_nmap))


async def cmd_blocked(update, ctx):
    await _reply(update, await asyncio.to_thread(text_blocked))


async def cmd_logs(update, ctx):
    await _reply(update, await asyncio.to_thread(text_logs))


async def cmd_about(update, ctx):
    await _reply(update, text_about())


# ╔══════════════════════════════════════════════════════════════╗
# ║         GESTIONNAIRE DES BOUTONS (clavier fixe en bas)       ║
# ╚══════════════════════════════════════════════════════════════╝
# Le clavier fixe envoie le libellé du bouton comme un message texte :
# on fait donc du routage sur le texte reçu.

TEXT_BUTTONS = {
    BTN_LAST_ALERTS: text_last_alerts,
    BTN_PING_NMAP: text_ping_nmap,
    BTN_MALICIOUS: text_malicious,
    BTN_BLOCKED: text_blocked,
}


async def button_handler(update, ctx):
    text = (update.message.text or "").strip()

    if text in TEXT_BUTTONS:
        await _reply(update, await asyncio.to_thread(TEXT_BUTTONS[text]))

    elif text == BTN_REFRESH:
        await _reply(update, "🔄  Menu actualisé.")

    elif text == BTN_UNBLOCK:
        markup = await asyncio.to_thread(build_unblock_menu)
        if markup.keyboard and len(markup.keyboard) > 1:
            await _reply(update, "🔓  <b>Choisis une IP à débloquer :</b>", markup)
        else:
            await _reply(update, "✅  Aucune IP bloquée pour le moment.")

    elif text == BTN_BACK:
        await _reply(update, "🛡️  Menu principal.")

    elif text == BTN_UNBLOCK_ALL:
        count = await asyncio.to_thread(unblock_all)
        await _reply(update, f"✅  {count} IP(s) débloquée(s) — toutes les règles ont été retirées.")

    elif text.startswith(UNBLOCK_PREFIX):
        ip = text[len(UNBLOCK_PREFIX):].strip()
        if not is_ipv4(ip):
            await _reply(update, "❓  Adresse IP invalide.")
            return
        ok = await asyncio.to_thread(unblock_ip, ip)
        remaining = await asyncio.to_thread(get_blocked_ips_list)
        head = (f"✅  IP <code>{_esc(ip)}</code> débloquée !" if ok
                else f"ℹ️  <code>{_esc(ip)}</code> n'était pas bloquée.")
        if remaining:
            await _reply(update, f"{head}\n🔓  Il reste {len(remaining)} IP(s) bloquée(s).",
                         await asyncio.to_thread(build_unblock_menu))
        else:
            await _reply(update, f"{head}\n🎉  Plus aucune IP bloquée.")

    else:
        await _reply(update, "❓  Utilise les boutons ci-dessous 👇 ou tape /menu.")


async def on_error(update, ctx):
    log.error("Erreur dans un gestionnaire Telegram", exc_info=ctx.error)


# ╔══════════════════════════════════════════════════════════════╗
# ║                    CLASSIFIERS                              ║
# ╚══════════════════════════════════════════════════════════════╝

def is_instant_block(msg: str) -> bool:
    return INSTANT_RE.search(msg) is not None


def is_silent(msg: str) -> bool:
    return SILENT_RE.search(msg) is not None


def classify(msg: str) -> str:
    """« instant » (blocage), « silent » (/ping) ou « normal » (seuil).
    Le blocage immédiat est testé AVANT le silencieux : sinon « ICMP FLOOD »
    serait classé comme simple ping et ne serait jamais bloqué."""
    if is_instant_block(msg):
        return "instant"
    if is_silent(msg):
        return "silent"
    return "normal"


# ╔══════════════════════════════════════════════════════════════╗
# ║                    PROCESS LINE                             ║
# ╚══════════════════════════════════════════════════════════════╝

def process_line(line: str):
    m = LINE_RE.search(line)
    if not m:
        return

    ts, msg, proto, src_ip, dst_ip = (
        m.group(1), m.group(2).strip(), m.group(3).strip(),
        m.group(4).strip(), m.group(5).strip(),
    )
    entry = {"time": ts, "msg": msg, "proto": proto, "src": src_ip, "dst": dst_ip}

    with STATE_LOCK:
        recent_alerts.append(entry)

    kind = classify(msg)
    if kind == "silent":
        with STATE_LOCK:
            ping_alerts.append(entry)
        log.info(f"PING silencieux {src_ip:<20} (/ping pour voir)")
        return

    with STATE_LOCK:
        skip = src_ip in WHITELIST or src_ip in blocked_ips
    if skip:
        return
    if not is_ipv4(src_ip):
        log.info(f"Alerte IPv6 ignorée pour le blocage : {src_ip} | {msg}")
        return

    if kind == "instant":
        log.warning(f"INSTANT BLOCK {src_ip:<20} | {msg}")
        block_ip(src_ip, f"INSTANT [{msg}]", msg)
        return

    now = time.time()
    with STATE_LOCK:
        hits = alert_hits[src_ip]
        hits.append(now)
        while hits and now - hits[0] > ALERT_WINDOW:
            hits.popleft()
        count = len(hits)
    log.info(f"Alerte {count:>3}/{ALERT_THRESHOLD}  {src_ip:<20} | {msg}")
    if count >= ALERT_THRESHOLD:
        block_ip(src_ip, f"SEUIL ({count} alertes en {ALERT_WINDOW}s) [{msg}]", msg)


# ╔══════════════════════════════════════════════════════════════╗
# ║                   MONITOR LOOP                              ║
# ╚══════════════════════════════════════════════════════════════╝

def monitor_loop():
    log.info(f"En attente de {FAST_LOG}...")
    while not os.path.exists(FAST_LOG):
        time.sleep(2)
    log.info(f"Surveillance active : {FAST_LOG}")

    f = open(FAST_LOG, "r", encoding="utf-8", errors="replace")
    f.seek(0, os.SEEK_END)
    inode = os.stat(FAST_LOG).st_ino
    while True:
        try:
            line = f.readline()
            if line:
                process_line(line)
                continue
            time.sleep(0.05)  # polling 50 ms

            # Rotation (logrotate) ou troncature : sans ça on ne lirait plus rien.
            st = os.stat(FAST_LOG)
            if st.st_ino != inode or st.st_size < f.tell():
                log.info("fast.log a tourné, réouverture du fichier.")
                f.close()
                f = open(FAST_LOG, "r", encoding="utf-8", errors="replace")
                inode = st.st_ino
        except FileNotFoundError:
            time.sleep(2)
        except Exception as e:  # ne jamais laisser mourir la surveillance
            log.error(f"Erreur surveillance : {e}")
            time.sleep(1)


# ╔══════════════════════════════════════════════════════════════╗
# ║                        MAIN                                 ║
# ╚══════════════════════════════════════════════════════════════╝

def graceful_exit(sig, frame):
    log.info("Arrêt propre. Les règles iptables restent en place (voir README).")
    sys.exit(0)


async def post_init(app):
    global _bot_loop
    _bot_loop = asyncio.get_running_loop()
    await app.bot.set_my_commands([
        BotCommand("start", "Démarrer et épingler le menu"),
        BotCommand("menu", "Afficher le menu"),
        BotCommand("ping", "Alertes Ping / ICMP"),
        BotCommand("nmap", "Scans NMAP détectés"),
        BotCommand("blocked", "IPs bloquées"),
        BotCommand("logs", "Derniers logs Suricata"),
        BotCommand("about", "À propos de l'outil"),
    ])
    try:
        await app.bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=(f"🛡️ <b>Vigie démarré</b>\n"
                  f"📧 Mails : {'✅ activés' if EMAIL_ENABLED else '❌ désactivés'}\n"
                  f"🕐 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"
                  f"🔰 by <b>{TOOL_SIGNATURE}</b>"),
            parse_mode="HTML",
        )
    except Exception as e:
        log.error(f"Notification de démarrage Telegram impossible : {e}")


def run_telegram():
    global _telegram_app
    app = ApplicationBuilder().token(TELEGRAM_TOKEN).post_init(post_init).build()
    _telegram_app = app

    for name, handler in (
        ("start", cmd_start), ("menu", cmd_menu), ("ping", cmd_ping), ("nmap", cmd_nmap),
        ("blocked", cmd_blocked), ("logs", cmd_logs), ("about", cmd_about),
    ):
        app.add_handler(CommandHandler(name, handler, filters=CHAT_FILTER))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND & CHAT_FILTER, button_handler))
    app.add_error_handler(on_error)

    log.info("Bot Telegram démarré — tape /start dans Telegram")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


def main():
    if os.geteuid() != 0:
        print("Lance en root (sudo).")
        sys.exit(1)

    setup_logging()
    log.info("══════════════════════════════════════════")
    log.info(f"  vigie.py v{VERSION} - DÉMARRE")
    log.info(f"  Seuil blocage : {ALERT_THRESHOLD} alertes / {ALERT_WINDOW} s")
    log.info(f"  Telegram      : {'activé' if TELEGRAM_ENABLED else 'désactivé'}")
    log.info(f"  Email         : {'activé' if EMAIL_ENABLED else 'désactivé'} ({EMAIL_PROVIDER})")
    log.info(f"  Signé         : {TOOL_SIGNATURE} ({TOOL_AUTHOR_FULL})")
    log.info("══════════════════════════════════════════")

    own = local_ipv4_addresses()
    WHITELIST.update(own)
    log.info(f"  IPs du serveur protégées : {', '.join(sorted(own)) or 'aucune détectée'}")

    setup_chain()
    if MAIL_ON_START:
        send_email(*make_email_start())

    threading.Thread(target=monitor_loop, daemon=True, name="monitor").start()

    if TELEGRAM_ENABLED and TELEGRAM_AVAILABLE:
        run_telegram()  # bloquant : gère Ctrl+C / SIGTERM proprement
    else:
        if TELEGRAM_ENABLED:
            log.error("python-telegram-bot est absent : Telegram désactivé.")
        else:
            log.info("Telegram désactivé : blocage et mails uniquement.")
        signal.signal(signal.SIGINT, graceful_exit)
        signal.signal(signal.SIGTERM, graceful_exit)
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    main()
