<div align="center">
  <img src="Logo/logo.png" alt="12ak_Vigie logo" width="160">
</div>

# 🛡️ 12ak_Vigie

**12ak_Vigie** détecte et bloque automatiquement les IPs malveillantes sur un serveur Linux (Ubuntu/Debian), en temps réel.

Il combine **Suricata** (détection réseau), **iptables** (blocage), un **bot Telegram** (pilotage depuis ton téléphone) et des **notifications email**.

---

## 🎯 Ce qu'il détecte

- 🗺️ **Scans NMAP** (`-sS`, `-sT`, `-sA`, `-sX`, `-sU`, scans fragmentés…) → blocage immédiat
- 💣 **DDoS** (SYN / UDP / ICMP flood, Slowloris) → blocage immédiat
- 🔑 **Brute-force** (SSH, RDP, FTP, formulaires web)
- 🕵️ **Reconnaissance** (SMB, amplification DNS, scan SSL/TLS)
- 🐚 **Exploits & shells** (Metasploit, webshells, SQLi, XSS)
- 🏓 **Ping / ICMP** → silencieux (consultable avec `/ping`, jamais bloqué seul)

Les scans et attaques bloquent l'IP dès la première alerte. Les autres alertes bloquent l'IP après **N alertes en 10 minutes** (seuil configurable).

### Boutons du bot Telegram

| Bouton | Action |
|---|---|
| ⚠️ 10 Dernières Alertes | Les 10 dernières alertes Suricata |
| 🔍 IPs Ping & NMAP | Qui a scanné ou pingué le serveur |
| 🛑 IPs Malveillantes / Logs | Historique des blocages |
| 🚫 IPs Bloquées | IPs bloquées en ce moment |
| 🔓 Débloquer une IP | Liste des IPs bloquées, un bouton par IP |
| 🔓 TOUT Débloquer | Retire tous les blocages (demandé dans le sous-menu) |
| 🔄 Actualiser | Réaffiche le menu |

**Sécurité :** le bot ne répond qu'au **chat_id** configuré à l'installation. Toute autre personne qui trouve ton bot ne reçoit aucune réponse.

---

## ⚙️ Installation

### Prérequis

- Ubuntu / Debian (testé sur Ubuntu 22.04+), accès **root** (`sudo`)
- *(Optionnel)* Un bot Telegram : crée-le avec [@BotFather](https://t.me/BotFather), puis récupère ton `chat_id` avec [@userinfobot](https://t.me/userinfobot)
- *(Optionnel)* Une adresse email pour les alertes. Avec Gmail, utilise un [mot de passe d'application](https://myaccount.google.com/apppasswords), pas ton mot de passe habituel.

### Étapes

```bash
# 1. Cloner le repo
git clone https://github.com/Rachkpt/12ak_Suricata_Guard.git
cd 12ak_Suricata_Guard/12ak_Suricata_Guard

# 2. Lancer l'installation (en root)
sudo bash install_vigie.sh
```

L'installeur pose quelques questions (interface réseau, seuil, Telegram, email, whitelist), puis configure tout seul. Si tu es connecté en SSH, il te propose de **whitelister ton IP** pour que tu ne te bloques pas toi-même.

Ensuite, envoie `/start` à ton bot Telegram.

### Où sont les fichiers ?

| Chemin | Contenu |
|---|---|
| `/opt/vigie/vigie.py` | Le moteur (droits 700, root) |
| `/etc/vigie/config.json` | Ta configuration et tes secrets (droits 600, root) |
| `/etc/systemd/system/vigie.service` | Le service |
| `/var/log/vigie.log` | Journal du bot (roté chaque semaine) |
| `/var/log/vigie_blocked.log` | Historique des blocages |
| `/etc/suricata/rules/local.rules` | Les règles de détection |

Pour modifier la configuration : édite `/etc/vigie/config.json`, puis `sudo systemctl restart vigie`. Les champs les plus utiles sont `alert_threshold`, `alert_window_seconds` et `whitelist`.

---

## 🔧 Utilisation courante

```bash
# Voir les logs du bot en direct
journalctl -u vigie -f

# Voir les IPs actuellement bloquées
sudo iptables -S VIGIE

# Débloquer une IP à la main
sudo iptables -D VIGIE -s 203.0.113.7 -j DROP

# Redémarrer le bot
sudo systemctl restart vigie

# Vérifier Suricata
sudo systemctl status suricata
```

---

## ⏹️ Arrêter

Trois niveaux, du plus léger au plus complet :

```bash
# 1. Arrêter le bot seulement (les IPs restent bloquées)
sudo systemctl stop vigie

# 2. Arrêter le bot ET l'empêcher de redémarrer au reboot
sudo systemctl disable --now vigie

# 3. Débloquer toutes les IPs (sans toucher au reste)
sudo iptables -F VIGIE
```

Pour arrêter Suricata aussi : `sudo systemctl disable --now suricata`.

---

## 🗑️ Tout supprimer

Un script de désinstallation est copié sur le serveur à l'installation :

```bash
sudo bash /opt/vigie/uninstall_vigie.sh
```

Il demande confirmation (tape `OUI`), puis :

1. arrête et supprime le service ;
2. retire **toutes** les IPs bloquées et la chaîne `VIGIE` ;
3. supprime `/opt/vigie` et `/etc/vigie` (les secrets sont effacés) ;
4. retire `local.rules` de Suricata.

Il te demande ensuite si tu veux aussi supprimer les logs et désinstaller Suricata (réponse par défaut : non).

Pour une suppression sans question (garde Suricata et les logs) : `sudo bash /opt/vigie/uninstall_vigie.sh --yes`

---

## 🩺 Dépannage

| Problème | Solution |
|---|---|
| Le bot ne répond pas sur Telegram | Vérifie que tu écris depuis le **même compte** que celui du chat_id. `journalctl -u vigie -n 50` affiche les erreurs. |
| Un bouton ne réagit pas | Vérifie que le service tourne (`systemctl status vigie`), puis retape `/menu`. |
| Aucune alerte n'apparaît | Vérifie que `/var/log/suricata/fast.log` grossit (`sudo tail -f /var/log/suricata/fast.log`) et que `suricata` est actif. |
| Une IP légitime est bloquée | `sudo iptables -D VIGIE -s IP -j DROP`, puis ajoute-la à `whitelist` dans `config.json`. |
| Tu t'es bloqué toi-même en SSH | Depuis la console de ton hébergeur : `sudo iptables -F VIGIE`. |

---

## 🧪 Tests

```bash
cd 12ak_Suricata_Guard/12ak_Suricata_Guard
python3 -m unittest discover -s tests -v
```

Les tests n'appellent jamais iptables réel et ne nécessitent pas Telegram.

---

## 📁 Contenu du repo

- `install_vigie.sh` — installeur complet
- `uninstall_vigie.sh` — arrêt et suppression complets
- `vigie.py` — le moteur de blocage et le bot Telegram
- `local.rules` — les règles de détection Suricata
- `tests/` — tests unitaires

---

<div align="center">

Développé et signé par **__KAT4NA_**

</div>
