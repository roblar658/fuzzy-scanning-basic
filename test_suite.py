"""
Automatisert test-suite for Fuzz Security Test System.

Tester:
1. URL-validering og lovlighets-guardrails (avviser eksterne adresser, tillater localhost).
2. Live sårbarhetstesting mot app-serveren i både Sårbar Modus og Sikker Modus.
"""

import unittest
import threading
import time
import urllib.request
import json
import http.server

from fuzz_engine import validate_target_url, run_full_fuzz, PAYLOAD_CATEGORIES
from app_server import FuzzHTTPRequestHandler, init_database, STATE_LOCK
import app_server

TEST_PORT = 8089


class TestFuzzSecuritySuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Starter en lokal instans av app-serveren i en bakgrunnstråd for testing."""
        init_database()
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", TEST_PORT), FuzzHTTPRequestHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        """Avslutter test-serveren."""
        cls.server.shutdown()
        cls.server.server_close()

    def test_00_dashboard_and_target_rendering(self):
        """Verifiserer at både dashboardet og målapplikasjonen rendres uten feil."""
        with urllib.request.urlopen(f"http://127.0.0.1:{TEST_PORT}/") as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8")
            self.assertIn("Aegis Security Analyzer", body)

        with urllib.request.urlopen(f"http://127.0.0.1:{TEST_PORT}/target?q=") as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8")
            self.assertIn("NordicFlow ERP", body)

    def test_01_url_validation_guardrails(self):
        """Verifiserer at sikkerhetssjekken blokkerer uautoriserte eksterne mål."""
        # Eksterne adresser skal avvises av lovmessige hensyn
        valid, msg = validate_target_url("http://google.com/search")
        self.assertFalse(valid)
        self.assertIn("ekstern", msg)

        valid, msg = validate_target_url("https://unauthorized-target.org/api")
        self.assertFalse(valid)

        # Lokale adresser skal godkjennes
        valid, msg = validate_target_url("http://localhost:8080/target?q=")
        self.assertTrue(valid)

        valid, msg = validate_target_url("http://127.0.0.1:8089/target")
        self.assertTrue(valid)

    def test_02_vulnerable_mode_detection(self):
        """Verifiserer at fuzzeren oppdager SQL-feil og XSS i sårbar modus."""
        with STATE_LOCK:
            app_server.SECURE_MODE = False

        target_url = f"http://127.0.0.1:{TEST_PORT}/target"
        
        # Test SQL probes
        report = run_full_fuzz(target_url, "q", categories=["sql_probes", "xss_probes"])
        self.assertTrue(report["success"])
        
        summary = report["summary"]
        self.assertGreater(summary["critical"], 0, "Fuzzeren burde ha oppdaget kritiske sårbarheter i sårbar modus!")
        self.assertEqual(summary["overall_status"], "SÅRBAR")

        # Sjekk spesifikk SQL-feillekkasje for enkeltfnutt
        single_quote_result = next((r for r in report["results"] if r["payload"] == "'"), None)
        self.assertIsNotNone(single_quote_result)
        self.assertEqual(single_quote_result["severity"], "KRITISK")
        self.assertTrue(any("SQL" in f and "lekket" in f for f in single_quote_result["findings"]))

        # Sjekk XSS refleksjon for <script>
        script_result = next((r for r in report["results"] if "<script>" in r["payload"]), None)
        self.assertIsNotNone(script_result)
        self.assertEqual(script_result["severity"], "KRITISK")
        self.assertTrue(any("Uenkodet refleksjon" in f for f in script_result["findings"]))

    def test_03_secure_mode_verification(self):
        """Verifiserer at fuzzeren bekrefter at systemet er sikkert når Sikker Modus er på."""
        with STATE_LOCK:
            app_server.SECURE_MODE = True

        target_url = f"http://127.0.0.1:{TEST_PORT}/target"
        
        # Test alle kategorier
        report = run_full_fuzz(target_url, "q", categories=["sql_probes", "xss_probes", "boundary_tests"])
        self.assertTrue(report["success"])
        
        summary = report["summary"]
        self.assertEqual(summary["critical"], 0, "Det skal ikke være noen kritiske sårbarheter i sikker modus!")
        self.assertEqual(summary["high"], 0, "Det skal ikke være noen høye sårbarheter i sikker modus!")
        self.assertEqual(summary["overall_status"], "SIKKER")

        # Enkeltfnutt skal nå håndteres trygt som vanlig tekst
        single_quote_result = next((r for r in report["results"] if r["payload"] == "'"), None)
        self.assertIsNotNone(single_quote_result)
        self.assertEqual(single_quote_result["severity"], "TRYGG")


if __name__ == "__main__":
    unittest.main()

