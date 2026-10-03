"""
Tests de vigie.py (bibliothèque standard uniquement).

Lancement depuis le dossier du script :
    python3 -m unittest discover -s tests -v
"""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="sg_test_")
CONFIG = Path(TMP) / "config.json"
CONFIG.write_text(json.dumps({
    "alert_threshold": 3,
    "alert_window_seconds": 600,
    "telegram_enabled": False,
    "telegram_token": "",
    "telegram_chat_id": 0,
    "email_enabled": False,
    "whitelist": ["192.168.1.50"],
}))
os.environ["VIGIE_CONFIG"] = str(CONFIG)
os.environ["VIGIE_LOG"] = str(Path(TMP) / "vigie.log")
os.environ["VIGIE_BLOCKED_LOG"] = str(Path(TMP) / "blocked.log")

spec = importlib.util.spec_from_file_location("vigie", ROOT / "vigie.py")
sg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sg)

# Sécurité : les tests ne doivent JAMAIS toucher au vrai pare-feu (lancés en root
# sur le serveur, un appel iptables réel bloquerait de vraies IPs).
IPTABLES_CALLS = []
sg._run = lambda cmd, timeout=30: IPTABLES_CALLS.append(cmd) or None
sg.run_cmd = lambda cmd: IPTABLES_CALLS.append(cmd) or True
sg.persist_rules = lambda: None
sg.log.setLevel("CRITICAL")  # sorties de test propres

SAMPLE_LINE = (
    "02/03/2026-10:11:12.123456  [**] [1:3400001:1] POSSBL PORT SCAN (NMAP -sS) [**] "
    "[Classification: Attempted Information Leak] [Priority: 2] "
    "{TCP} 10.0.0.5:4444 -> 192.168.1.10:80\n"
)


class ParseLineTests(unittest.TestCase):
    def test_parse_extracts_fields(self):
        before = len(sg.recent_alerts)
        sg.process_line(SAMPLE_LINE)
        entry = list(sg.recent_alerts)[-1]
        self.assertEqual(len(sg.recent_alerts), min(before + 1, sg.recent_alerts.maxlen))
        self.assertEqual(entry["src"], "10.0.0.5")
        self.assertEqual(entry["dst"], "192.168.1.10")
        self.assertEqual(entry["proto"], "TCP")
        self.assertIn("NMAP", entry["msg"])

    def test_garbage_line_is_ignored(self):
        before = len(sg.recent_alerts)
        sg.process_line("ceci n'est pas une alerte\n")
        self.assertEqual(len(sg.recent_alerts), before)


class ClassificationTests(unittest.TestCase):
    def test_icmp_flood_is_instant_not_silent(self):
        # « ICMP » est un mot silencieux, mais « ICMP FLOOD » doit bloquer
        self.assertEqual(sg.classify("POSSBL ICMP FLOOD"), "instant")

    def test_plain_ping_is_silent(self):
        self.assertEqual(sg.classify("ICMP Echo Request"), "silent")

    def test_short_keyword_matches_whole_word_only(self):
        self.assertTrue(sg.is_instant_block("ET DOS Inbound attack"))
        self.assertFalse(sg.is_instant_block("Mise à jour DOSSIER partagé"))

    def test_long_keyword_matches_prefix(self):
        self.assertTrue(sg.is_instant_block("M-SPLOIT SHELLCODE detected"))

    def test_normal_web_alert_is_not_instant(self):
        self.assertFalse(sg.is_instant_block("ET INFO HTTP GET request"))


class ParseBlockedTests(unittest.TestCase):
    def test_parses_iptables_s_output(self):
        out = (
            "-N VIGIE\n"
            "-A VIGIE -s 1.2.3.4/32 -j DROP\n"
            "-A VIGIE -s 5.6.7.8/32 -j DROP\n"
            "-A VIGIE -s 1.2.3.4/32 -j DROP\n"
        )
        self.assertEqual(sg.parse_blocked_ips(out), ["1.2.3.4", "5.6.7.8"])

    def test_empty_chain(self):
        self.assertEqual(sg.parse_blocked_ips("-N VIGIE\n"), [])


class TextTests(unittest.TestCase):
    def setUp(self):
        sg.recent_alerts.clear()
        sg.blocked_ips.clear()

    def test_html_is_escaped(self):
        sg.process_line(
            "02/03/2026-10:11:12.1  [**] [1:1:1] <script>x</script> ET TEST [**] "
            "[Classification: x] [Priority: 2] {TCP} 10.9.9.9:1 -> 192.168.1.10:80\n"
        )
        text = sg.text_last_alerts()
        self.assertIn("&lt;script&gt;", text)
        self.assertNotIn("<script>", text)

    def test_long_list_never_exceeds_telegram_limit(self):
        for i in range(10):
            sg.process_line(
                f"02/03/2026-10:11:{i:02d}.1  [**] [1:1:1] {'X' * 900} SHELL [**] "
                f"[Classification: x] [Priority: 2] {{TCP}} 10.1.1.{i}:1 -> 192.168.1.10:80\n"
            )
        text = sg.text_last_alerts()
        self.assertLessEqual(len(text), 4000)
        # aucune balise <code> ouverte sans fermeture (ce qui ferait rejeter le message)
        self.assertEqual(text.count("<code>"), text.count("</code>"))

    def test_empty_state_message(self):
        self.assertIn("Aucune alerte", sg.text_last_alerts())


class ValidationTests(unittest.TestCase):
    def test_ipv4_validation(self):
        self.assertTrue(sg.is_ipv4("203.0.113.7"))
        self.assertFalse(sg.is_ipv4("::1"))
        self.assertFalse(sg.is_ipv4("pas une ip"))
        self.assertFalse(sg.is_ipv4("1.2.3"))

    def test_whitelist_is_honoured(self):
        self.assertIn("192.168.1.50", sg.WHITELIST)
        self.assertIn("127.0.0.1", sg.WHITELIST)

    def test_block_skips_whitelisted_ip(self):
        IPTABLES_CALLS.clear()
        sg.block_ip("192.168.1.50", "test")
        self.assertEqual(IPTABLES_CALLS, [])

    def test_block_then_unblock_uses_drop_rule(self):
        IPTABLES_CALLS.clear()
        sg.blocked_ips.discard("203.0.113.9")
        sg.block_ip("203.0.113.9", "test")
        self.assertIn([sg.IPTABLES, "-A", sg.CHAIN, "-s", "203.0.113.9", "-j", "DROP"], IPTABLES_CALLS)
        self.assertIn("203.0.113.9", sg.blocked_ips)


class RulesFileTests(unittest.TestCase):
    """Contrôles structurels de local.rules (sans Suricata installé)."""

    @classmethod
    def setUpClass(cls):
        cls.rules = [
            line.strip() for line in (ROOT / "local.rules").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    def test_every_rule_is_well_formed(self):
        for rule in self.rules:
            with self.subTest(rule=rule[:60]):
                self.assertTrue(rule.startswith(("alert ", "drop ", "pass ", "reject ")), rule[:60])
                self.assertIn('(msg:"', rule)
                self.assertTrue(rule.endswith(";)"), "la règle doit finir par ;)")
                self.assertEqual(rule.count("("), rule.count(")"), "parenthèses déséquilibrées")

    def test_sids_are_unique(self):
        sids = [r.split("sid:")[1].split(";")[0] for r in self.rules if "sid:" in r]
        self.assertEqual(len(sids), len(set(sids)), "sid en double")

    def test_every_rule_has_classtype(self):
        for rule in self.rules:
            with self.subTest(rule=rule[:60]):
                self.assertIn("classtype:", rule)


class ModifiedRulesClassificationTests(unittest.TestCase):
    """Les messages des règles corrigées tombent dans la bonne catégorie."""

    def test_ping_of_death_now_blocks(self):
        self.assertEqual(sg.classify("ICMP DOS - Ping of Death potentiel"), "instant")

    def test_log4j_blocks_immediately(self):
        self.assertEqual(sg.classify("EXPLOIT Log4j JNDI injection (URI)"), "instant")

    def test_noisy_patterns_go_through_threshold(self):
        for msg in ("HTTP CONNEXIONS LENTES MULTIPLES - a surveiller",
                    "WEB POST REPETES - formulaires (a surveiller)",
                    "DNS REQUETES MULTIPLES - volume anormal",
                    "SMB CONNEXIONS MULTIPLES - sondage 445"):
            with self.subTest(msg=msg):
                self.assertEqual(sg.classify(msg), "normal")


if __name__ == "__main__":
    unittest.main()
