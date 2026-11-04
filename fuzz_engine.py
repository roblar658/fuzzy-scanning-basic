"""
Fuzz Engine - Profesjonell og defensiv input-validering og fuzz-testing.

Inneholder diagnostiske payloads og analysemotor for å oppdage
sårbarheter og mangler i input-validering (CWE-89 SQLi, CWE-79 XSS,
grenseverdier, spesialtegn og uventede feilkoder) på en kontrollert og lovlig måte.
"""

import time
import urllib.request
import urllib.parse
import urllib.error
import re
from typing import List, Dict, Any, Optional

# Kategori-definisjoner og payloads med profesjonell terminologi
PAYLOAD_CATEGORIES = {
    "sql_probes": {
        "name": "SQL-spørringsintegritet (CWE-89)",
        "description": "Tester syntakssekvenser som avslører manglende prepared statements og databasefeil.",
        "payloads": [
            {"payload": "'", "label": "Apostrof / Enkelt anførselstegn", "intent": "Avsløre unescaped streng-literaler i SQL"},
            {"payload": "\"", "label": "Dobbelt anførselstegn", "intent": "Avsløre syntaksbrudd i identifikatorer eller strenger"},
            {"payload": "''", "label": "Sekvens av enkle anførselstegn ('')", "intent": "Undersøke tegnpars-håndtering"},
            {"payload": "' OR '1'='1", "label": "Klassisk tautologi (' OR '1'='1)", "intent": "Undersøke logisk predikat-injeksjon"},
            {"payload": "' OR '1'='2", "label": "Falsk predikatbetingelse (' OR '1'='2)", "intent": "Undersøke differensiell respons"},
            {"payload": "1' ORDER BY 1--", "label": "Sorteringsklausul med linjekommentar (--)", "intent": "Sjekke kommentarhåndtering"},
            {"payload": "' /*kommentar*/", "label": "C-stil SQL-blokk-kommentar (/* */)", "intent": "Sjekke blokk-kommentarhåndtering"},
            {"payload": "'; --", "label": "Setningsterminator og kommentar (; --)", "intent": "Avsløre støtte for stacked queries"},
            {"payload": "') OR ('1'='1", "label": "Parentesbalansering med logisk OR", "intent": "Avsløre sammensatte WHERE-klausuler"},
            {"payload": "1' AND (SELECT 1 FROM non_existing_fuzz_tbl_xyz)--", "label": "Syntaksfeilprovoserende delspørring", "intent": "Fremprovosere tabellfeil"}
        ]
    },
    "xss_probes": {
        "name": "Kontekstuell entitetskoding & XSS (CWE-79)",
        "description": "Undersøker om skript- og HTML-koder reflekteres rått i responsen uten entitetskoding.",
        "payloads": [
            {"payload": "<fuzztest>", "label": "Ufarlig HTML-tag (<fuzztest>)", "intent": "Sjekke om vinkelklammer enkodes som &lt; og &gt;"},
            {"payload": "<script>/*fuzz*/</script>", "label": "Standard skript-tag", "intent": "Sjekke filter mot <script>"},
            {"payload": "\"><script>alert(1)</script>", "label": "Attributt-utbryter med skriptelement", "intent": "Sjekke om attributtkontekst brytes"},
            {"payload": "<img src=x onerror=alert(1)>", "label": "Event handler i bildeelement (onerror)", "intent": "Avsløre manglende sanitering av tag-attributter"},
            {"payload": "' onfocus='alert(1)' autofocus='", "label": "Fokus-basert hendelseshåndterer", "intent": "Test av attributt-injeksjon"},
            {"payload": "<svg/onload=alert(1)>", "label": "SVG-element med onload-hendelse", "intent": "Bypass av naive HTML-filtre"}
        ]
    },
    "boundary_tests": {
        "name": "Grenseverdier og buffervalidering (CWE-20)",
        "description": "Tester ekstrem lengde, tomme data og uventede datatyper.",
        "payloads": [
            {"payload": "", "label": "Nullengde-streng (Empty string)", "intent": "Håndtering av tom input"},
            {"payload": "   ", "label": "Mellomromstegn (Whitespace only)", "intent": "Trim- og normaliseringshåndtering"},
            {"payload": "A" * 256, "label": "256 tegn (Kort buffer)", "intent": "Validering av feltstørrelse"},
            {"payload": "A" * 2048, "label": "2048 tegn (Middels buffer)", "intent": "Buffer og minneovervåking"},
            {"payload": "A" * 10000, "label": "10 000 tegn (Ekstrem lengde)", "intent": "Sjekke for ressursuttømming, DoS eller unntak"},
            {"payload": "-1", "label": "Negativ numerisk verdi (-1)", "intent": "Uventet fortegn for ID/antall"},
            {"payload": "99999999999999999999999999999999", "label": "Stort heltall (BigInt overflow)", "intent": "Sjekke heltallsoverflyt"}
        ]
    },
    "special_characters": {
        "name": "Tegnsett & kodingsanomalier (CWE-176)",
        "description": "Tester null-bytes, formateringsstrenger, linjeskift og unicode-varianter.",
        "payloads": [
            {"payload": "%00", "label": "URL-enkodet Null-byte (%00)", "intent": "Strengterminerings-sårbarheter"},
            {"payload": "test\x00fuzz", "label": "Binær Null-byte i streng", "intent": "C-interoperabilitet og nullterminering"},
            {"payload": "../../../etc/passwd", "label": "Katalogkryssing (Unix Path Traversal)", "intent": "Filbane-validering"},
            {"payload": "..\\..\\..\\windows\\win.ini", "label": "Katalogkryssing (Windows Path Traversal)", "intent": "Windows-filbanevalidering"},
            {"payload": "\r\nInjected-Header: true", "label": "CRLF-sekvens (Header-injeksjon)", "intent": "Responssplitting"},
            {"payload": "%s%s%s%s%n", "label": "C-stil formatstrenger (%s%n)", "intent": "Format string sårbarheter"},
            {"payload": "{{7*7}}", "label": "Maluttrykk (Server-Side Template Injection)", "intent": "Template evaluering"},
            {"payload": "${7*7}", "label": "Expression Language uttrykk (${...})", "intent": "Evaluerings-sjekk"},
            {"payload": "’ OR ‘1’=‘1", "label": "Typografiske hermetegn (Smart quotes)", "intent": "Normaliserings-sårbarhet"}
        ]
    }
}

# Signaturer for kjente database- og serverfeil
SQL_ERROR_PATTERNS = [
    r"sqlite3\.(OperationalError|DatabaseError)",
    r"syntax error near",
    r"unrecognized token:",
    r"incomplete input",
    r"no such column:",
    r"no such table:",
    r"You have an error in your SQL syntax",
    r"mysql_fetch",
    r"pg_query\(\): Query failed",
    r"syntax error at or near",
    r"Unclosed quotation mark before the character string",
    r"Microsoft OLE DB Provider for ODBC Drivers",
    r"ORA-00933: SQL command not properly ended",
    r"ORA-00936: missing expression"
]


def validate_target_url(url: str) -> tuple[bool, str]:
    """
    Sikkerhetsmekanisme: Verifiserer at målet er innenfor lovlige rammer.
    Tillater som standard kun lokale adresser (localhost / 127.0.0.1 / loopback)
    for å forhindre utilsiktet eller uautorisert testing mot tredjeparter.
    """
    if not url or not isinstance(url, str):
        return False, "URL-feltet er tomt. Vennligst angi en gyldig mål-URL."

    parsed = urllib.parse.urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        return False, "Ugyldig URL-format. URL må inneholde protokoll (http:// eller https://)."

    hostname = (parsed.hostname or "").lower()
    
    # Tillatte sikre lokale testdomener
    allowed_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "testserver.local"}
    
    if hostname in allowed_hosts or hostname.endswith(".localhost"):
        return True, "Gyldig autorisert lokalt testmål."
    
    return False, (
        f"Vertsadressen '{hostname}' er ekstern. "
        "Systemet støtter kun lokale testmiljøer (f.eks. http://localhost:...)."
    )


def test_single_payload(
    base_url: str,
    param_name: str,
    payload_item: Dict[str, str],
    category_id: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 4.0
) -> Dict[str, Any]:
    """
    Sender én diagnostisk testverdi mot målet og analyserer responsen.
    """
    payload = payload_item["payload"]
    label = payload_item.get("label", payload)
    intent = payload_item.get("intent", "")
    
    req_headers = {
        "User-Agent": "AegisAppSec-Validator/2.4 (Defensive-Audit-Safe-Probe)",
        "Accept": "*/*"
    }
    if headers:
        req_headers.update(headers)

    parsed_url = urllib.parse.urlparse(base_url.strip())
    
    # Bygg forespørsel
    data_to_send = None
    if method.upper() == "GET":
        query_dict = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
        query_dict[param_name] = [payload]
        new_query = urllib.parse.urlencode(query_dict, doseq=True)
        target_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
    else:
        target_url = base_url
        form_data = {param_name: payload}
        data_to_send = urllib.parse.urlencode(form_data).encode("utf-8")
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"

    start_time = time.time()
    status_code = None
    response_body = ""
    error_msg = None
    
    try:
        req = urllib.request.Request(target_url, data=data_to_send, headers=req_headers, method=method.upper())
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            raw_bytes = resp.read(65536)
            response_body = raw_bytes.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status_code = e.code
        try:
            response_body = e.read(65536).decode("utf-8", errors="replace")
        except Exception:
            response_body = ""
    except urllib.error.URLError as e:
        error_msg = f"Tilkoblingsfeil: {e.reason}"
    except Exception as e:
        error_msg = f"Forespørselsfeil: {str(e)}"

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    findings = []
    severity = "TRYGG"

    if error_msg:
        return {
            "payload": payload,
            "label": label,
            "category": category_id,
            "intent": intent,
            "status_code": None,
            "elapsed_ms": elapsed_ms,
            "severity": "FEIL",
            "findings": [error_msg],
            "raw_snippet": ""
        }

    # 1. Uhåndtert unntak (HTTP 500)
    if status_code == 500:
        findings.append("HTTP 500 Internal Server Error: Uhåndtert unntak eller krasj i applikasjonens databasesjikt.")
        severity = "HØY"

    # 2. Databasefeil lekkasje
    sql_leaks = []
    for pattern in SQL_ERROR_PATTERNS:
        match = re.search(pattern, response_body, re.IGNORECASE)
        if match:
            sql_leaks.append(match.group(0))

    if sql_leaks:
        findings.append(f"SQL-syntaksfeil lekket i responsteksten: '{sql_leaks[0]}'. Avslører ubeskyttet dynamisk SQL (CWE-89).")
        severity = "KRITISK"

    # 3. Uenkodet refleksjon (XSS CWE-79)
    if category_id == "xss_probes" and payload:
        if payload in response_body:
            findings.append(f"Uenkodet refleksjon påvist: Koden '{payload}' gjengis direkte i HTML uten entitetskoding (CWE-79).")
            if "<script" in payload.lower() or "onerror" in payload.lower():
                severity = "KRITISK" if severity != "KRITISK" else "KRITISK"
            else:
                severity = "HØY" if severity != "KRITISK" else "KRITISK"
        elif any(part in response_body for part in ["&lt;script&gt;", "&lt;fuzztest&gt;", "&quot;"]):
            findings.append("Korrekt håndtert: Data er kodet med HTML-entiteter før rendering.")

    # 4. Latensavvik
    if elapsed_ms > 3000:
        findings.append(f"Responstid overstiger terskelverdi ({elapsed_ms} ms). Mulig ytelsesdegradering.")
        if severity == "TRYGG":
            severity = "MIDDELS"

    # 5. Normal status
    if not findings:
        if status_code == 200:
            findings.append("Normal respons (HTTP 200 OK). Forespørselen ble håndtert stabilt.")
            severity = "TRYGG"
        elif status_code == 400:
            findings.append("Avvist etter validering (HTTP 400 Bad Request). Korrekt defensiv håndtering.")
            severity = "TRYGG"
        elif status_code == 404:
            findings.append("HTTP 404 Not Found.")
            severity = "INFO"
        else:
            findings.append(f"HTTP Status {status_code}.")
            severity = "INFO"

    snippet = response_body[:300].strip().replace("\n", " ") if response_body else ""

    return {
        "payload": payload,
        "label": label,
        "category": category_id,
        "intent": intent,
        "status_code": status_code,
        "elapsed_ms": elapsed_ms,
        "severity": severity,
        "findings": findings,
        "raw_snippet": snippet
    }


def stream_fuzz(
    target_url: str,
    param_name: str,
    categories: Optional[List[str]] = None,
    method: str = "GET"
):
    """
    Generator som sender probes og yielder hvert enkelt resultat i sanntid.
    """
    valid, msg = validate_target_url(target_url)
    if not valid:
        yield {"type": "error", "message": msg}
        return

    selected_cats = categories if categories else list(PAYLOAD_CATEGORIES.keys())
    
    total_planned = sum(len(PAYLOAD_CATEGORIES[c]["payloads"]) for c in selected_cats if c in PAYLOAD_CATEGORIES)
    yield {"type": "start", "total_planned": total_planned}

    total_count = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    safe_count = 0

    for cat_id in selected_cats:
        if cat_id not in PAYLOAD_CATEGORIES:
            continue
        cat_info = PAYLOAD_CATEGORIES[cat_id]
        for p_item in cat_info["payloads"]:
            res = test_single_payload(target_url, param_name, p_item, cat_id, method=method)
            total_count += 1
            
            sev = res["severity"]
            if sev == "KRITISK":
                critical_count += 1
            elif sev == "HØY":
                high_count += 1
            elif sev == "MIDDELS":
                medium_count += 1
            elif sev == "TRYGG":
                safe_count += 1

            # Yield hvert enkelt probe-resultat umiddelbart
            yield {
                "type": "item",
                "index": total_count,
                "total_planned": total_planned,
                "data": res,
                "current_counts": {
                    "total": total_count,
                    "critical": critical_count,
                    "high": high_count,
                    "medium": medium_count,
                    "safe": safe_count
                }
            }

            time.sleep(0.02)

    summary = {
        "target_url": target_url,
        "param_name": param_name,
        "method": method,
        "total_probes": total_count,
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "safe": safe_count,
        "overall_status": "SÅRBAR" if (critical_count > 0 or high_count > 0) else ("ADVARSEL" if medium_count > 0 else "SIKKER")
    }

    yield {"type": "done", "summary": summary}


def run_full_fuzz(
    target_url: str,
    param_name: str,
    categories: Optional[List[str]] = None,
    method: str = "GET"
) -> Dict[str, Any]:
    """
    Kjører en komplett valideringsrekke og returnerer samlet resultat.
    """
    valid, msg = validate_target_url(target_url)
    if not valid:
        return {
            "success": False,
            "error": msg,
            "results": [],
            "summary": {}
        }

    results = []
    summary = {}
    for event in stream_fuzz(target_url, param_name, categories=categories, method=method):
        if event["type"] == "item":
            results.append(event["data"])
        elif event["type"] == "done":
            summary = event["summary"]
        elif event["type"] == "error":
            return {
                "success": False,
                "error": event["message"],
                "results": [],
                "summary": {}
            }

    return {
        "success": True,
        "summary": summary,
        "results": results
    }
