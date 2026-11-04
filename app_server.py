#!/usr/bin/env python3
"""
App Server - Profesjonell Web-basert Fuzz Test Suite & Målapplikasjon.

Inneholder:
1. Target Web Page (/target): Realistisk bedriftsportal (NordicFlow ERP & Ordreregister)
   med søkefelt (q) som kan settes i enten Sårbar Modus (dynamisk SQL, rå HTML-refleksjon)
   eller Sikker Modus (Prepared statements, HTML-escaping, skjemavalidering).
2. Fuzz Testing Suite (/): Profesjonelt utvikler- og QA-dashboard i ren bedriftsstil for
   å lime inn URL, velge inputfelt, kjøre diagnostiske fuzz-tester og analysere funn mot CWE/OWASP.
"""

import http.server
import json
import sqlite3
import urllib.parse
import html
import threading
import sys
from typing import Any, Dict

from fuzz_engine import run_full_fuzz, stream_fuzz, PAYLOAD_CATEGORIES, validate_target_url

PORT = 8080

# Global tilstand for test-applikasjonen
STATE_LOCK = threading.Lock()
SECURE_MODE = False  # Standard: sårbar for å demonstrere sårbarhetsdeteksjon

# In-memory SQLite database
DB_CONN = sqlite3.connect(":memory:", check_same_thread=False)


def init_database():
    """Initialiserer realistisk bedriftsdata i minnedatabasen."""
    cursor = DB_CONN.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_no TEXT NOT NULL,
            customer TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL,
            order_date TEXT NOT NULL
        )
    """)
    cursor.execute("DELETE FROM orders")
    orders = [
        ("ORD-2026-8941", "Equinor ASA", "IT-Drift & Sikkerhet", "Fornyelse av Enterprise PKI-sertifikater og HSM-moduler", 145000.00, "Fullført", "28.10.2026"),
        ("ORD-2026-8942", "DNB Bank ASA", "Konsulentbistand", "Sikkerhetsgjennomgang av API-gateway og OAuth-integrasjoner", 89500.00, "Under behandling", "01.11.2026"),
        ("ORD-2026-8943", "Kongsberg Gruppen", "Maskinvare", "Leveranse av sikre nettverksrutere og brannmur-noder", 230000.00, "Fullført", "25.10.2026"),
        ("ORD-2026-8944", "Telenor Norge AS", "Skylagring", "Dedikert kryptert lagringsklynge Tier-3 datasenter", 54000.00, "Venter godkjenning", "03.11.2026"),
        ("ORD-2026-8945", "Aker Solutions ASA", "Programvare", "Arbeidsstasjonlisenser for teknisk analyse og CAD", 42000.00, "Fullført", "15.10.2026"),
        ("ORD-2026-8946", "Posten Bring AS", "Konsulentbistand", "Optimalisering av ruteplanlegging og logistikkdatabase", 67500.00, "Under behandling", "02.11.2026"),
        ("ORD-2026-8947", "Gjensidige Forsikring", "IT-Drift & Sikkerhet", "Sikkerhetskopiering og katastrofegjenoppretting (DRP)", 115000.00, "Fullført", "19.10.2026"),
        ("ORD-2026-8948", "Yara International", "Maskinvare", "Sensornoder og industrielt IoT-nettverksutstyr", 78000.00, "Venter godkjenning", "04.11.2026"),
    ]
    cursor.executemany(
        "INSERT INTO orders (order_no, customer, category, description, amount, status, order_date) VALUES (?, ?, ?, ?, ?, ?, ?)",
        orders
    )
    DB_CONN.commit()


# ==============================================================================
# HTML FOR SIKKERHETS- OG FUZZING-DASHBOARD (/)
# ==============================================================================
def get_dashboard_html() -> str:
    return f"""<!DOCTYPE html>
<html lang="no">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegis AppSec - Input Validering & Fuzzing Suite</title>
    <style>
        :root {{
            --bg-page: #f8fafc;
            --bg-card: #ffffff;
            --border-subtle: #e2e8f0;
            --border-strong: #cbd5e1;
            --text-main: #0f172a;
            --text-secondary: #475569;
            --text-muted: #64748b;
            --brand-primary: #1e40af;
            --brand-primary-hover: #1d4ed8;
            --brand-accent: #2563eb;
            --color-critical: #b91c1c;
            --bg-critical: #fef2f2;
            --border-critical: #fecaca;
            --color-high: #c2410c;
            --bg-high: #fff7ed;
            --border-high: #fed7aa;
            --color-medium: #854d0e;
            --bg-medium: #fefce8;
            --border-medium: #fef08a;
            --color-safe: #15803d;
            --bg-safe: #f0fdf4;
            --border-safe: #bbf7d0;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Monaco, Consolas, monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-page);
            color: var(--text-main);
            font-family: var(--font-sans);
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }}
        
        /* Toppmeny */
        .navbar {{
            background: #ffffff;
            border-bottom: 1px solid var(--border-subtle);
            height: 60px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 32px;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
            text-decoration: none;
            color: var(--text-main);
        }}
        .brand-badge {{
            background: var(--brand-primary);
            color: #ffffff;
            font-size: 0.75rem;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 4px;
            letter-spacing: 0.5px;
        }}
        .brand-title {{
            font-size: 1rem;
            font-weight: 600;
            letter-spacing: -0.2px;
        }}
        .brand-subtitle {{
            font-size: 0.8rem;
            color: var(--text-muted);
            border-left: 1px solid var(--border-strong);
            padding-left: 12px;
        }}
        .nav-actions {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 14px;
            font-size: 0.85rem;
            font-weight: 500;
            border-radius: 6px;
            border: 1px solid var(--border-strong);
            background: #ffffff;
            color: var(--text-main);
            cursor: pointer;
            text-decoration: none;
            transition: all 0.15s ease;
        }}
        .btn:hover {{
            background: #f1f5f9;
            border-color: #94a3b8;
        }}
        .btn-primary {{
            background: var(--brand-primary);
            color: #ffffff;
            border-color: var(--brand-primary);
        }}
        .btn-primary:hover {{
            background: var(--brand-primary-hover);
            border-color: var(--brand-primary-hover);
        }}

        /* Hovedlayout */
        .container {{
            max-width: 1240px;
            margin: 32px auto;
            padding: 0 24px;
        }}

        /* Statusindikator for målmiljø */
        .environment-status {{
            background: #ffffff;
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            padding: 12px 18px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .env-left {{
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 0.85rem;
        }}
        .status-dot {{
            width: 9px;
            height: 9px;
            border-radius: 50%;
        }}
        .status-dot.vulnerable {{ background: var(--color-critical); }}
        .status-dot.secure {{ background: var(--color-safe); }}

        /* 2-kolonne inndeling */
        .main-grid {{
            display: grid;
            grid-template-columns: 1.15fr 0.85fr;
            gap: 24px;
            margin-bottom: 28px;
        }}
        @media (max-width: 900px) {{
            .main-grid {{ grid-template-columns: 1fr; }}
        }}

        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 8px;
            padding: 24px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05);
        }}
        .card-header {{
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border-subtle);
            padding-bottom: 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .card-title {{
            font-size: 1rem;
            font-weight: 600;
            color: var(--text-main);
        }}
        .card-subtitle {{
            font-size: 0.8rem;
            color: var(--text-muted);
        }}

        /* Skjema */
        .form-group {{ margin-bottom: 18px; }}
        .form-label {{
            display: block;
            font-size: 0.825rem;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}
        .input-text, .select-box {{
            width: 100%;
            padding: 9px 12px;
            background: #ffffff;
            border: 1px solid var(--border-strong);
            border-radius: 6px;
            font-size: 0.875rem;
            color: var(--text-main);
            font-family: var(--font-mono);
            transition: border-color 0.15s;
        }}
        .input-text:focus, .select-box:focus {{
            outline: none;
            border-color: var(--brand-accent);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
        }}
        .url-row {{
            position: relative;
        }}
        .url-actions {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 6px;
            font-size: 0.75rem;
            color: var(--text-muted);
        }}
        .link-btn {{
            background: none;
            border: none;
            color: var(--brand-accent);
            font-size: 0.75rem;
            font-weight: 500;
            cursor: pointer;
            text-decoration: underline;
            padding: 0;
        }}

        .suite-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-top: 8px;
        }}
        .suite-item {{
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 10px 12px;
            background: #f8fafc;
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            cursor: pointer;
        }}
        .suite-item:hover {{
            background: #f1f5f9;
        }}
        .suite-item input {{
            margin-top: 3px;
            cursor: pointer;
        }}
        .suite-info .suite-title {{
            font-size: 0.825rem;
            font-weight: 600;
            color: var(--text-main);
        }}
        .suite-info .suite-desc {{
            font-size: 0.725rem;
            color: var(--text-muted);
        }}

        .btn-submit {{
            width: 100%;
            padding: 11px;
            background: var(--brand-primary);
            color: #ffffff;
            border: 1px solid var(--brand-primary);
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            margin-top: 10px;
            transition: background 0.15s ease;
        }}
        .btn-submit:hover {{
            background: var(--brand-primary-hover);
        }}
        .btn-submit:disabled {{
            opacity: 0.6;
            cursor: not-allowed;
        }}

        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .spinner {{
            display: inline-block;
            width: 15px;
            height: 15px;
            border: 2px solid rgba(255, 255, 255, 0.35);
            border-radius: 50%;
            border-top-color: #ffffff;
            animation: spin 0.75s linear infinite;
            vertical-align: middle;
            margin-right: 8px;
        }}
        .spinner-lg {{
            width: 36px;
            height: 36px;
            border: 3px solid rgba(37, 99, 235, 0.15);
            border-radius: 50%;
            border-top-color: var(--brand-accent);
            animation: spin 0.75s linear infinite;
        }}
        .loading-container {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 44px 20px;
            gap: 12px;
        }}
        .loading-title {{
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--text-main);
        }}
        .loading-subtitle {{
            font-size: 0.8rem;
            color: var(--text-muted);
        }}

        .progress-bar-container {{
            background: #e2e8f0;
            border-radius: 999px;
            height: 6px;
            overflow: hidden;
            margin-bottom: 20px;
            display: none;
        }}
        .progress-bar-fill {{
            background: var(--brand-accent);
            height: 100%;
            width: 0%;
            transition: width 0.15s ease;
        }}
        @keyframes fadeInRow {{
            from {{ opacity: 0; background-color: #f1f5f9; }}
            to {{ opacity: 1; background-color: transparent; }}
        }}
        .fade-in-row {{
            animation: fadeInRow 0.3s ease-out;
        }}

        /* Veilederboks i høyre kolonne */
        .guide-box {{
            font-size: 0.825rem;
            color: var(--text-secondary);
        }}
        .guide-item {{
            margin-bottom: 14px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-subtle);
        }}
        .guide-item:last-child {{ border-bottom: none; }}
        .guide-item strong {{ color: var(--text-main); }}

        .code-preview {{
            background: #0f172a;
            color: #f8fafc;
            padding: 12px;
            border-radius: 6px;
            font-family: var(--font-mono);
            font-size: 0.775rem;
            overflow-x: auto;
            margin-top: 6px;
            line-height: 1.4;
        }}

        /* Resultat-seksjon */
        .results-card {{
            display: none;
            background: #ffffff;
            border: 1px solid var(--border-subtle);
            border-radius: 8px;
            padding: 24px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05);
        }}
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-box {{
            background: #f8fafc;
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            padding: 14px 18px;
        }}
        .stat-value {{
            font-size: 1.6rem;
            font-weight: 700;
            color: var(--text-main);
            line-height: 1.1;
        }}
        .stat-label {{
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }}
        .stat-box.critical .stat-value {{ color: var(--color-critical); }}
        .stat-box.high .stat-value {{ color: var(--color-high); }}
        .stat-box.safe .stat-value {{ color: var(--color-safe); }}

        /* Tabell */
        .table-responsive {{
            overflow-x: auto;
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
        }}
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.825rem;
            text-align: left;
        }}
        .data-table th {{
            background: #f1f5f9;
            color: var(--text-secondary);
            font-weight: 600;
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-strong);
            white-space: nowrap;
        }}
        .data-table td {{
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-subtle);
            color: var(--text-main);
            vertical-align: middle;
        }}
        .data-table tr:hover td {{
            background: #f8fafc;
        }}

        .pill {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.725rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }}
        .pill.critical {{ background: var(--bg-critical); color: var(--color-critical); border: 1px solid var(--border-critical); }}
        .pill.high {{ background: var(--bg-high); color: var(--color-high); border: 1px solid var(--border-high); }}
        .pill.medium {{ background: var(--bg-medium); color: var(--color-medium); border: 1px solid var(--border-medium); }}
        .pill.safe {{ background: var(--bg-safe); color: var(--color-safe); border: 1px solid var(--border-safe); }}
        .pill.error {{ background: #f1f5f9; color: var(--text-muted); border: 1px solid var(--border-subtle); }}

        .code-badge {{
            font-family: var(--font-mono);
            background: #f1f5f9;
            border: 1px solid var(--border-strong);
            color: #0f172a;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.775rem;
            display: inline-block;
            max-width: 240px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            vertical-align: middle;
        }}
    </style>
</head>
<body>
    <header class="navbar">
        <a href="/" class="brand">
            <span class="brand-badge">APPSEC</span>
            <span class="brand-title">Aegis Security Analyzer</span>
            <span class="brand-subtitle">Automatisert Validerings- og Fuzzing-suite</span>
        </a>
        <div class="nav-actions">
            <a href="/target" target="_blank" class="btn">
                <span>Åpne Målapplikasjon</span>
                <span style="font-size: 0.75rem; color: var(--text-muted);">(Portal)</span>
            </a>
            <button id="toggleTargetModeBtn" class="btn">Endre Sikkerhetsmodus</button>
        </div>
    </header>

    <main class="container">
        <!-- Målstatus -->
        <div class="environment-status">
            <div class="env-left">
                <span id="statusDot" class="status-dot vulnerable"></span>
                <span id="envStatusText">Laster status for testmiljøet...</span>
            </div>
            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">Endepunkt: http://localhost:8080/target</span>
        </div>

        <div class="main-grid">
            <!-- Testkonfigurasjon -->
            <section class="card">
                <div class="card-header">
                    <div>
                        <h2 class="card-title">Testkonfigurasjon</h2>
                        <p class="card-subtitle">Konfigurer mål og testsuiter for det spesifikke inputfeltet</p>
                    </div>
                </div>

                <form id="fuzzForm">
                    <div class="form-group">
                        <label class="form-label" for="targetUrl">Mål-URL (Lim inn relevant URL):</label>
                        <div class="url-row">
                            <input type="text" id="targetUrl" class="input-text" value="http://localhost:8080/target?q=" placeholder="http://localhost:8080/target?q=" required>
                        </div>
                        <div class="url-actions">
                            <span></span>
                            <button type="button" class="link-btn" id="pasteLocalTarget">Sett inn lokal testportal-URL</button>
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 14px;" class="form-group">
                        <div>
                            <label class="form-label" for="paramName">Inputfelt / Parameter:</label>
                            <input type="text" id="paramName" class="input-text" value="q" placeholder="F.eks. q, search, order_id" required>
                        </div>
                        <div>
                            <label class="form-label" for="httpMethod">Metode:</label>
                            <select id="httpMethod" class="select-box">
                                <option value="GET" selected>GET</option>
                                <option value="POST">POST</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">Valideringssuiter (Diagnostiske mønstre):</label>
                        <div class="suite-grid">
                            <label class="suite-item">
                                <input type="checkbox" name="cat" value="sql_probes" checked>
                                <div class="suite-info">
                                    <div class="suite-title">SQL-integritet (CWE-89)</div>
                                    <div class="suite-desc">Syntaksbrudd, escape-svikt og kommentarer</div>
                                </div>
                            </label>
                            <label class="suite-item">
                                <input type="checkbox" name="cat" value="xss_probes" checked>
                                <div class="suite-info">
                                    <div class="suite-title">Tegnentiteter & XSS (CWE-79)</div>
                                    <div class="suite-desc">HTML-refleksjon og tag-filtrering</div>
                                </div>
                            </label>
                            <label class="suite-item">
                                <input type="checkbox" name="cat" value="boundary_tests" checked>
                                <div class="suite-info">
                                    <div class="suite-title">Grenseverdier (CWE-20)</div>
                                    <div class="suite-desc">Buffer-størrelser, tomme felt og numeriske ytterpunkter</div>
                                </div>
                            </label>
                            <label class="suite-item">
                                <input type="checkbox" name="cat" value="special_characters" checked>
                                <div class="suite-info">
                                    <div class="suite-title">Spesialtegn (CWE-176)</div>
                                    <div class="suite-desc">Null-bytes, CRLF og kodingsanomalier</div>
                                </div>
                            </label>
                        </div>
                    </div>

                    <button type="submit" id="submitBtn" class="btn-submit">
                        Kjør sikkerhetsanalyse
                    </button>
                </form>
            </section>

            <!-- Teknisk veiledning og standarder -->
            <section class="card">
                <div class="card-header">
                    <div>
                        <h2 class="card-title">Metodikk & Diagnose</h2>
                        <p class="card-subtitle">Hvordan testene analyseres og standarder for utbedring</p>
                    </div>
                </div>

                <div class="guide-box">
                    <div class="guide-item">
                        <strong>Kritisk (SQL-syntaksfeil / Lekkasje):</strong>
                        <p>Dersom serveren returnerer databasespesifikke feilmeldinger (f.eks. <code>sqlite3.OperationalError</code>) eller endrer spørringslogikk ved modifiserte anførselstegn, indikerer det direkte sårbarhet for SQL-injeksjon.</p>
                    </div>
                    <div class="guide-item">
                        <strong>Høy (Uenkodet HTML-refleksjon):</strong>
                        <p>Dersom spesialtegn som <code>&lt;script&gt;</code> eller tag-attributter reflekteres rått i responsen uten entitetskoding (<code>&amp;lt;script&amp;gt;</code>), åpner dette for Cross-Site Scripting.</p>
                    </div>
                    <div class="guide-item">
                        <strong>Trygg / Robust:</strong>
                        <p>Serveren benytter parametriserte spørringer, koder entiteter og håndterer store datamengder uten serverkrasj (HTTP 200 eller 400 Bad Request).</p>
                    </div>
                </div>

                <div style="margin-top: 16px;">
                    <span class="form-label">Anbefalt sikringsmønster:</span>
                    <pre class="code-preview">// Parametrisert spørring (Prepared statement)
cursor.execute("SELECT * FROM orders WHERE customer LIKE ?", (f"%{{query}}%",))</pre>
                </div>
            </section>
        </div>

        <!-- Resultater -->
        <section class="results-card" id="resultsSection">
            <div class="card-header">
                <div>
                    <h2 class="card-title">Testrapport & Observasjoner</h2>
                    <p class="card-subtitle" id="resultsSubtitle">Diagnostisk evaluering for angitt endepunkt</p>
                </div>
            </div>

            <div class="summary-stats">
                <div class="stat-box">
                    <div class="stat-value" id="metricTotal">0</div>
                    <div class="stat-label">Tester Kjørt</div>
                </div>
                <div class="stat-box critical">
                    <div class="stat-value" id="metricCritical">0</div>
                    <div class="stat-label">Kritiske Avvik</div>
                </div>
                <div class="stat-box high">
                    <div class="stat-value" id="metricHigh">0</div>
                    <div class="stat-label">Høye Avvik</div>
                </div>
                <div class="stat-box safe">
                    <div class="stat-value" id="metricSafe">0</div>
                    <div class="stat-label">Bestått / Trygg</div>
                </div>
            </div>

            <div class="table-responsive">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th style="width: 100px;">Klassifisering</th>
                            <th style="width: 70px;">HTTP</th>
                            <th style="width: 80px;">Tid</th>
                            <th style="width: 160px;">Kategori</th>
                            <th style="width: 220px;">Testverdi (Payload)</th>
                            <th>Diagnostisk Observasjon</th>
                        </tr>
                    </thead>
                    <tbody id="resultsBody">
                    </tbody>
                </table>
            </div>
        </section>
    </main>

    <script>
        const form = document.getElementById('fuzzForm');
        const submitBtn = document.getElementById('submitBtn');
        const targetUrlInput = document.getElementById('targetUrl');
        const pasteBtn = document.getElementById('pasteLocalTarget');
        const envStatusText = document.getElementById('envStatusText');
        const statusDot = document.getElementById('statusDot');
        const toggleTargetModeBtn = document.getElementById('toggleTargetModeBtn');
        const resultsSection = document.getElementById('resultsSection');
        const resultsBody = document.getElementById('resultsBody');

        async function fetchTargetStatus() {{
            try {{
                const res = await fetch('/api/target/status');
                const data = await res.json();
                if (data.secure_mode) {{
                    statusDot.className = 'status-dot secure';
                    envStatusText.innerHTML = '<strong>Miljøstatus:</strong> Sikret produksjonsmodus (Prepared statements & HTML-entitetskoding aktivert).';
                }} else {{
                    statusDot.className = 'status-dot vulnerable';
                    envStatusText.innerHTML = '<strong>Miljøstatus:</strong> Ubeskyttet modus (Dynamisk SQL & ufiltrert refleksjon). Fuzz-tester vil avdekke avvik.';
                }}
            }} catch (err) {{
                envStatusText.innerText = 'Kunne ikke innhente målmiljøets status.';
            }}
        }}

        toggleTargetModeBtn.addEventListener('click', async () => {{
            await fetch('/api/target/toggle-mode', {{ method: 'POST' }});
            await fetchTargetStatus();
        }});

        pasteBtn.addEventListener('click', () => {{
            targetUrlInput.value = window.location.origin + '/target?q=';
        }});

        fetchTargetStatus();

        form.addEventListener('submit', async (e) => {{
            e.preventDefault();
            const url = targetUrlInput.value.trim();
            const param = document.getElementById('paramName').value.trim();
            const method = document.getElementById('httpMethod').value;
            
            const cats = Array.from(document.querySelectorAll('input[name="cat"]:checked')).map(cb => cb.value);
            if (cats.length === 0) {{
                alert('Vennligst velg minst én valideringssuite.');
                return;
            }}

            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner"></span> Kjører diagnostiske tester...';
            resultsSection.style.display = 'block';
            resultsBody.innerHTML = `
                <tr>
                    <td colspan="6">
                        <div class="loading-container">
                            <div class="spinner-lg"></div>
                            <div class="loading-title">Kjører sikkerhetsanalyse mot inputfeltet</div>
                            <div class="loading-subtitle">Sender diagnostiske testverdier (SQL, XSS, grenseverdier, spesialtegn)...</div>
                        </div>
                    </td>
                </tr>
            `;

            try {{
                const response = await fetch('/api/fuzz/run', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        url: url,
                        param: param,
                        method: method,
                        categories: cats
                    }})
                }});

                const data = await response.json();
                if (!data.success) {{
                    alert('Valideringsfeil: ' + (data.error || 'Ukjent feil'));
                    resultsSection.style.display = 'none';
                    return;
                }}

                renderResults(data);
            }} catch (err) {{
                alert('Tilkoblingsfeil: ' + err.message);
            }} finally {{
                submitBtn.disabled = false;
                submitBtn.innerText = 'Kjør sikkerhetsanalyse';
            }}
        }});

        function renderResults(data) {{
            const summary = data.summary;
            document.getElementById('metricTotal').innerText = summary.total_probes;
            document.getElementById('metricCritical').innerText = summary.critical;
            document.getElementById('metricHigh').innerText = summary.high;
            document.getElementById('metricSafe').innerText = summary.safe;
            document.getElementById('resultsSubtitle').innerText = `Evaluering for felt '${{summary.param_name}}' mot ${{summary.target_url}} (${{summary.method}})`;

            resultsBody.innerHTML = '';
            
            data.results.forEach(item => {{
                const tr = document.createElement('tr');
                
                let pillClass = 'safe';
                if (item.severity === 'KRITISK') pillClass = 'critical';
                else if (item.severity === 'HØY') pillClass = 'high';
                else if (item.severity === 'MIDDELS') pillClass = 'medium';
                else if (item.severity === 'FEIL') pillClass = 'error';

                const httpCode = item.status_code !== null ? item.status_code : 'FEIL';
                const finding = item.findings.join(' | ');

                tr.innerHTML = `
                    <td><span class="pill ${{pillClass}}">${{item.severity}}</span></td>
                    <td style="font-family: var(--font-mono); font-weight: 600;">${{httpCode}}</td>
                    <td style="font-family: var(--font-mono); color: var(--text-muted);">${{item.elapsed_ms || 0}} ms</td>
                    <td style="color: var(--text-secondary);">${{item.category}}</td>
                    <td>
                        <span class="code-badge" title="${{escapeHtml(item.payload)}}">${{escapeHtml(item.payload)}}</span><br>
                        <small style="color: var(--text-muted); font-size: 0.72rem;">${{escapeHtml(item.label)}}</small>
                    </td>
                    <td>
                        <div style="font-weight: 500; font-size: 0.8rem;">${{escapeHtml(finding)}}</div>
                        ${{item.raw_snippet ? `<div style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono); margin-top: 3px; max-width: 460px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">Respons: ${{escapeHtml(item.raw_snippet)}}</div>` : ''}}
                    </td>
                `;
                resultsBody.appendChild(tr);
            }});
        }}

        function escapeHtml(text) {{
            if (!text) return '';
            return String(text)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }}
    </script>
</body>
</html>
"""


# ==============================================================================
# HTML FOR MÅL-APPLIKASJONEN (/target) - NORDICFLOW ERP & ORDREREGISTER
# ==============================================================================
def get_target_html(query: str, results: list, error_msg: str = "") -> str:
    """Genererer HTML for en profesjonell bedriftsportal som skal testes."""
    with STATE_LOCK:
        is_secure = SECURE_MODE

    # XSS-demonstrasjon:
    # I sårbar modus reflekteres strengen rått i HTML
    # I sikker modus benyttes html.escape
    if is_secure:
        safe_query_display = html.escape(query)
        security_indicator = """
            <span class="badge-status badge-success">Sikkerhetsprofil: Høy (WAF & Prepared Statements Aktiv)</span>
        """
    else:
        safe_query_display = query
        security_indicator = """
            <span class="badge-status badge-warning">Sikkerhetsprofil: Standard (Ubeskyttet dynamisk SQL)</span>
        """

    rows_html = ""
    if error_msg:
        # Sårbar modus returnerer en standard systemfeil som lekker feilen
        rows_html = f"""
        <tr>
            <td colspan="7">
                <div class="system-error-box">
                    <div style="font-weight: 600; margin-bottom: 4px;">Systemfeil under databasespørring:</div>
                    <pre>{html.escape(error_msg)}</pre>
                </div>
            </td>
        </tr>
        """
    elif not results:
        rows_html = """
        <tr>
            <td colspan="7" style="text-align: center; padding: 32px; color: #64748b;">
                Ingen ordrer eller poster samsvarer med søkekriteriet.
            </td>
        </tr>
        """
    else:
        for r in results:
            p_id, order_no, customer, cat, desc, amount, status, o_date = r
            if is_secure:
                order_no = html.escape(order_no)
                customer = html.escape(customer)
                cat = html.escape(cat)
                desc = html.escape(desc)
                status = html.escape(status)
                o_date = html.escape(o_date)

            status_class = "badge-neutral"
            if status == "Fullført":
                status_class = "badge-success"
            elif status == "Under behandling":
                status_class = "badge-info"
            elif status == "Venter godkjenning":
                status_class = "badge-warning"

            rows_html += f"""
            <tr>
                <td style="font-family: var(--font-mono); font-weight: 600; color: #1e40af;">{order_no}</td>
                <td style="font-weight: 600;">{customer}</td>
                <td>{cat}</td>
                <td style="color: #475569; max-width: 320px;">{desc}</td>
                <td style="font-family: var(--font-mono); font-weight: 600; text-align: right;">{amount:,.2f} kr</td>
                <td><span class="badge-status {status_class}">{status}</span></td>
                <td style="color: #64748b; font-size: 0.8rem;">{o_date}</td>
            </tr>
            """

    return f"""<!DOCTYPE html>
<html lang="no">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NordicFlow ERP - Kunde- og Ordreregister</title>
    <style>
        :root {{
            --bg-page: #f1f5f9;
            --bg-card: #ffffff;
            --border: #e2e8f0;
            --border-dark: #cbd5e1;
            --text-main: #0f172a;
            --text-secondary: #475569;
            --text-muted: #64748b;
            --primary: #1e3a8a;
            --primary-hover: #1e40af;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-page);
            color: var(--text-main);
            font-family: var(--font-sans);
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }}

        /* Corporate Navbar */
        .portal-header {{
            background: #ffffff;
            border-bottom: 1px solid var(--border);
            padding: 0 32px;
            height: 64px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .brand-section {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .logo-text {{
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--primary);
            letter-spacing: -0.3px;
        }}
        .app-nav {{
            display: flex;
            gap: 20px;
            margin-left: 24px;
            border-left: 1px solid var(--border);
            padding-left: 24px;
        }}
        .nav-item {{
            text-decoration: none;
            color: var(--text-secondary);
            font-size: 0.85rem;
            font-weight: 500;
            padding: 6px 0;
        }}
        .nav-item.active {{
            color: var(--primary);
            font-weight: 600;
            border-bottom: 2px solid var(--primary);
        }}
        .user-chip {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
        .avatar {{
            width: 32px;
            height: 32px;
            background: #e2e8f0;
            color: #334155;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 0.75rem;
        }}

        /* Hovedinnhold */
        .portal-container {{
            max-width: 1200px;
            margin: 28px auto;
            padding: 0 24px;
        }}

        /* Drifts- og miljølinje */
        .env-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #ffffff;
            border: 1px solid var(--border);
            padding: 10px 16px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}

        /* Søkekort */
        .search-container {{
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
        }}
        .search-title {{
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--text-main);
            margin-bottom: 12px;
        }}
        .search-bar {{
            display: flex;
            gap: 10px;
        }}
        .search-field {{
            flex: 1;
            padding: 10px 14px;
            border: 1px solid var(--border-dark);
            border-radius: 6px;
            font-size: 0.9rem;
            color: var(--text-main);
        }}
        .search-field:focus {{
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(30, 58, 138, 0.1);
        }}
        .btn-search {{
            padding: 10px 22px;
            background: var(--primary);
            color: #ffffff;
            border: none;
            border-radius: 6px;
            font-size: 0.875rem;
            font-weight: 600;
            cursor: pointer;
        }}
        .btn-search:hover {{
            background: var(--primary-hover);
        }}

        .target-url-info {{
            margin-top: 12px;
            font-size: 0.775rem;
            color: var(--text-muted);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f8fafc;
            padding: 8px 12px;
            border-radius: 4px;
            border: 1px solid var(--border);
        }}
        .target-url-info code {{
            color: #0369a1;
            font-family: var(--font-mono);
            font-weight: 600;
        }}

        .results-summary {{
            margin-bottom: 16px;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}

        /* Datatabell */
        .table-card {{
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
        }}
        .order-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            text-align: left;
        }}
        .order-table th {{
            background: #f8fafc;
            color: var(--text-secondary);
            font-weight: 600;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
        }}
        .order-table td {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
        }}
        .order-table tr:last-child td {{
            border-bottom: none;
        }}
        .order-table tr:hover td {{
            background: #f8fafc;
        }}

        /* Badges */
        .badge-status {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.725rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-success {{ background: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; }}
        .badge-info {{ background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }}
        .badge-warning {{ background: #fffbeb; color: #b45309; border: 1px solid #fde68a; }}
        .badge-neutral {{ background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }}

        .system-error-box {{
            background: #fef2f2;
            border: 1px solid #fecaca;
            border-radius: 6px;
            padding: 16px;
            color: #991b1b;
            font-size: 0.85rem;
        }}
        .system-error-box pre {{
            margin-top: 8px;
            background: #ffffff;
            border: 1px solid #fca5a5;
            padding: 10px;
            border-radius: 4px;
            font-family: var(--font-mono);
            font-size: 0.775rem;
            color: #7f1d1d;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <header class="portal-header">
        <div class="brand-section">
            <span class="logo-text">NordicFlow ERP</span>
            <nav class="app-nav">
                <a href="/target" class="nav-item active">Ordrer</a>
                <a href="#" class="nav-item">Kunder</a>
                <a href="#" class="nav-item">Fakturaer</a>
                <a href="#" class="nav-item">Logistikk</a>
                <a href="#" class="nav-item">Innstillinger</a>
            </nav>
        </div>
        <div class="user-chip">
            <div class="avatar">RN</div>
            <div>
                <div style="font-weight: 600; font-size: 0.8rem; color: var(--text-main);">Robert Nilsen</div>
                <div style="font-size: 0.725rem; color: var(--text-muted);">QA & Systemdrift</div>
            </div>
        </div>
    </header>

    <main class="portal-container">
        <!-- Miljøstatus -->
        <div class="env-bar">
            <div>
                <strong>Miljø:</strong> Staging-01 &bull; 
                <strong>Modul:</strong> Ordreregister v3.2 &bull; 
                <strong>Database:</strong> SQLite Engine
            </div>
            <div>
                {security_indicator}
            </div>
        </div>

        <!-- Søkefelt -->
        <section class="search-container">
            <div class="search-title">Søk i kunde- og ordredata</div>
            <form action="/target" method="GET" class="search-bar">
                <input type="text" id="q" name="q" class="search-field" value="{safe_query_display}" placeholder="Søk etter kundenavn, ordrenummer eller varebeskrivelse...">
                <button type="submit" class="btn-search">Søk</button>
            </form>
            <div class="target-url-info">
                <span>Test-URL for dette feltet: <code>http://localhost:8080/target?q=</code></span>
                <span>Feltparameter: <code>q</code></span>
            </div>
        </section>

        {f'<div class="results-summary">Søkeresultater for: <strong>{safe_query_display}</strong></div>' if query else ''}

        <!-- Datatabell -->
        <div class="table-card">
            <table class="order-table">
                <thead>
                    <tr>
                        <th style="width: 140px;">Ordrenr</th>
                        <th style="width: 200px;">Kunde</th>
                        <th style="width: 170px;">Kategori</th>
                        <th>Beskrivelse / Leveranse</th>
                        <th style="width: 130px; text-align: right;">Beløp</th>
                        <th style="width: 140px;">Status</th>
                        <th style="width: 100px;">Dato</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
    </main>
</body>
</html>
"""


# ==============================================================================
# HTTP REQUEST HANDLER
# ==============================================================================
class FuzzHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Hoved-request handler for test-appen og fuzzer-kontrollpanelet."""

    def log_message(self, format, *args):
        # Stille logging for å holde terminalen ryddig under massiv testing
        pass

    def send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html_content: str, status: int = 200):
        body = html_content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        # 1. Fuzzing Dashboard (Rot)
        if path == "/" or path == "/dashboard":
            self.send_html(get_dashboard_html())
            return

        # 2. Target Web-side (/target)
        if path == "/target":
            query_val = qs.get("q", [""])[0]
            self.handle_target_search(query_val)
            return

        # 3. API: Status
        if path == "/api/target/status":
            with STATE_LOCK:
                is_secure = SECURE_MODE
            self.send_json({"secure_mode": is_secure})
            return

        # 4. API: Ordrer JSON
        if path == "/api/target/orders":
            query_val = qs.get("q", [""])[0]
            items, error, status_code = self.execute_search_query(query_val)
            if error:
                self.send_json({"error": error}, status=status_code)
            else:
                self.send_json({"orders": items, "count": len(items)})
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. API: Toggle Sikker vs Sårbar Modus
        if path == "/api/target/toggle-mode":
            global SECURE_MODE
            with STATE_LOCK:
                SECURE_MODE = not SECURE_MODE
                current_mode = SECURE_MODE
            self.send_json({"success": True, "secure_mode": current_mode})
            return

        # 2. API: Kjør Fuzz-tester
        if path == "/api/fuzz/run":
            length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(raw_body)
            except Exception:
                self.send_json({"success": False, "error": "Ugyldig JSON i forespørsel."}, status=400)
                return

            target_url = data.get("url", "")
            param_name = data.get("param", "q")
            method = data.get("method", "GET")
            categories = data.get("categories", None)

            result = run_full_fuzz(target_url, param_name, categories=categories, method=method)
            self.send_json(result)
            return

        # 3. POST mot /target
        if path == "/target":
            length = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(length).decode("utf-8")
            post_params = urllib.parse.parse_qs(post_body)
            query_val = post_params.get("q", [""])[0]
            self.handle_target_search(query_val)
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def execute_search_query(self, query: str):
        """
        Kjører søk i databasen enten sikkert eller sårbart avhengig av SECURE_MODE.
        Returnerer (rows, error_message, http_status_code).
        """
        with STATE_LOCK:
            is_secure = SECURE_MODE

        cursor = DB_CONN.cursor()
        
        if is_secure:
            # SIKKER MODUS:
            # 1. Valider input-lengde (Rejekt ved > 100 tegn med HTTP 400 Bad Request)
            if len(query) > 100:
                return None, "Valideringsfeil: Input overskrider maksimal tillatt lengde (100 tegn).", 400
            
            # 2. Benytt parametrisert spørring (Prepared statement med ?)
            sql = "SELECT id, order_no, customer, category, description, amount, status, order_date FROM orders WHERE customer LIKE ? OR description LIKE ? OR order_no LIKE ?"
            param = f"%{query}%"
            try:
                cursor.execute(sql, (param, param, param))
                rows = cursor.fetchall()
                return rows, None, 200
            except Exception as e:
                return None, "En intern feil oppstod under databasesøket.", 500
        else:
            # SÅRBAR MODUS:
            # Dynamisk SQL-strengsammensetting (f-string) mot customer for å demonstrere sårbarhet
            sql = f"SELECT id, order_no, customer, category, description, amount, status, order_date FROM orders WHERE customer LIKE '%{query}%'"
            try:
                cursor.execute(sql)
                rows = cursor.fetchall()
                return rows, None, 200
            except sqlite3.OperationalError as e:
                # Sårbarhet: Lekker den rå databasestacktracen / feilmeldingen direkte med HTTP 500
                return None, f"sqlite3.OperationalError: {str(e)}", 500
            except Exception as e:
                return None, f"Databasefeil: {str(e)}", 500

    def handle_target_search(self, query: str):
        """Håndterer rendering av målsiden med søkeresultater eller feilmeldinger."""
        items, error, status_code = self.execute_search_query(query)
        if error:
            html_page = get_target_html(query, [], error_msg=error)
            self.send_html(html_page, status=status_code)
        else:
            html_page = get_target_html(query, items or [])
            self.send_html(html_page, status=200)


def start_server():
    init_database()
    server_address = ("127.0.0.1", PORT)
    httpd = http.server.ThreadingHTTPServer(server_address, FuzzHTTPRequestHandler)
    print("=" * 70)
    print(f"Aegis AppSec Suite Server aktiv på http://localhost:{PORT}")
    print(f"  - Kontrollpanel & Fuzzing Dashboard: http://localhost:{PORT}/")
    print(f"  - Målportal (NordicFlow ERP):         http://localhost:{PORT}/target?q=")
    print("=" * 70)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nAvslutter server...")
        httpd.server_close()


if __name__ == "__main__":
    start_server()
