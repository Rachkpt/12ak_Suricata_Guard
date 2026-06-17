<div align="center">
  <img src="Logo/logo.png" alt="12ak_Suricata Guard logo" width="160">
</div>

# 🛡️ 12ak_Suricata Guard

**12ak_Suricata Guard** est un système de détection et de blocage automatique d'IPs malveillantes, conçu pour sécuriser un serveur Linux (Ubuntu/Debian) en temps réel.

Il combine **Suricata** (détection réseau) avec un **bot Telegram** et des **notifications email**, pour que tu puisses surveiller et réagir aux attaques directement depuis ton téléphone — sans rester collé à un terminal.

---

## 🎯 À quoi ça sert ?

L'outil surveille en permanence le trafic réseau de ton serveur et détecte automatiquement :

- 🗺️ **Scans NMAP** (toutes vitesses, `-sS`, `-sT`, `-sA`, `-sX`, `-sU`, scans fragmentés...)
- 💣 **Attaques DDoS** (SYN flood, UDP flood, ICMP flood, Slowloris)
- 🔑 **Brute-force** (SSH, RDP, FTP, formulaires web)
- 🕵️ **Reconnaissance réseau** (scan SMB, amplification DNS, scan SSL/TLS)
- 🐚 **Exploits & shells** (Metasploit, webshells, SQLi, XSS)

Dès qu'une activité suspecte dépasse le seuil défini (ou est jugée immédiatement dangereuse), l'IP source est **bloquée automatiquement via iptables**, et tu reçois une alerte instantanée sur **Telegram** et/ou par **email**.

Le bot Telegram te permet aussi de tout piloter à la main :

| Bouton | Action |
|---|---|
| ⚠️ 10 Dernières Alertes | Voir les dernières alertes Suricata |
| 🔍 IPs Ping & NMAP | Voir qui a scanné ou pingué ton serveur |
| 🛑 IPs Malveillantes / Logs | Consulter l'historique des blocages |
| 🚫 IPs Bloquées | Lister les IPs actuellement bloquées |
| 🔓 Débloquer une IP | Débloquer une IP en un clic |
| 🔄 Actualiser | Rafraîchir le menu |

---

## ⚙️ Installation

L'installation est **100% automatisée** : un seul script s'occupe d'installer Suricata, de configurer les règles de détection, d'installer le bot Telegram et de tout démarrer en service permanent.

### Prérequis

- Un serveur **Ubuntu / Debian** (testé sur Ubuntu 22.04+)
- Accès **root** (ou `sudo`)
- *(Optionnel)* Un bot Telegram créé via [@BotFather](https://t.me/BotFather), et ton `chat_id` via [@userinfobot](https://t.me/userinfobot)
- *(Optionnel)* Une adresse email pour les notifications (mot de passe d'application si Gmail)

### Étapes

```bash
# 1. Cloner le repo
git clone https://github.com/Rachkpt/12ak_Suricata_Guard.git
cd 12ak_Suricata_Guard/12ak_Suricata_Guard

# 2. Lancer l'installation (en root)
sudo bash install_suricata_guard.sh
```

Le script va te poser quelques questions (interface réseau, seuil de blocage, token Telegram, identifiants email...) et configure **tout automatiquement** à partir de tes réponses : aucune configuration manuelle à faire après.

Une fois terminé, va sur Telegram et envoie `/start` à ton bot pour voir apparaître le menu. 🚀

---

## 🔧 Commandes utiles après installation

```bash
# Suivre les logs du bot en direct
journalctl -u suricata-guard -f

# Voir les IPs actuellement bloquées
sudo iptables -L SURICATA_GUARD -n

# Redémarrer le bot
sudo systemctl restart suricata-guard

# Vérifier que Suricata tourne bien
sudo systemctl status suricata
```

---

## 📁 Contenu du repo

- `install_suricata_guard.sh` — script d'installation et de déploiement automatique
- `suricata_guard.py` — le bot Telegram + moteur de blocage automatique
- `local.rules` — les règles de détection Suricata (NMAP, DDoS, brute-force, web...)

---

<div align="center">

Développé et signé par **12ak_H4ck**

</div>
