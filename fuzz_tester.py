#!/usr/bin/env python3
"""
Aegis AppSec CLI - Kommandolinjeverktøy for input-validering og fuzzy-testing.

Bruk:
  python fuzz_tester.py --url "http://localhost:8080/target?q=" --param q
"""

import sys
import argparse
import json
from fuzz_engine import run_full_fuzz, PAYLOAD_CATEGORIES, validate_target_url

# ANSI Terminalfarger
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    banner = f"""{CYAN}======================================================================
  AEGIS APPSEC CLI - INPUT VALIDATION & FUZZING SUITE
======================================================================{RESET}"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description="Aegis AppSec - Inputvalidering og sårbarhetsanalyse for webfelter."
    )
    parser.add_argument(
        "--url",
        type=str,
        required=True,
        help="Mål-URL som skal evalueres (av sikkerhetshensyn kun localhost/127.0.0.1)."
    )
    parser.add_argument(
        "--param",
        type=str,
        default="q",
        help="Navn på parameteren eller feltet som skal testes (standard: 'q')."
    )
    parser.add_argument(
        "--method",
        type=str,
        choices=["GET", "POST"],
        default="GET",
        help="HTTP-forespørselsmetode (standard: GET)."
    )
    parser.add_argument(
        "--category",
        type=str,
        default="all",
        help=f"Valideringssuiter (kommaseparert, eller 'all'). Tilgjengelige: {', '.join(PAYLOAD_CATEGORIES.keys())}"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Skriv ut rapporten som maskinlesbar JSON til stdout."
    )

    args = parser.parse_args()

    # Verifiser URL mot sikkerhetsreglene
    is_valid, validation_msg = validate_target_url(args.url)
    if not is_valid:
        print(f"\n{RED}[FEIL]{RESET} {validation_msg}\n", file=sys.stderr)
        sys.exit(1)

    cats = None
    if args.category != "all":
        cats = [c.strip() for c in args.category.split(",") if c.strip() in PAYLOAD_CATEGORIES]
        if not cats:
            print(f"{RED}Feil: Ingen gyldige testkategorier oppgitt.{RESET}", file=sys.stderr)
            sys.exit(1)

    if not args.json:
        print_banner()
        print(f"{BOLD}Mål-URL:{RESET}       {args.url}")
        print(f"{BOLD}Parameter:{RESET}     {args.param}")
        print(f"{BOLD}HTTP-metode:{RESET}   {args.method}")
        print(f"{BOLD}Testsuiter:{RESET}    {', '.join(cats or PAYLOAD_CATEGORIES.keys())}")
        print("\nUtfører strukturerte tester...\n")

    report = run_full_fuzz(args.url, args.param, categories=cats, method=args.method)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    summary = report["summary"]
    results = report["results"]

    # Vis strukturert tabell
    print(f"{'STATUS':<9} | {'TID':<8} | {'KATEGORI':<18} | {'TESTVERDI (PAYLOAD)':<25} | {'OBSERVASJON'}")
    print("-" * 92)

    for r in results:
        sev = r["severity"]
        if sev == "KRITISK":
            color = RED + BOLD
        elif sev == "HØY":
            color = RED
        elif sev == "MIDDELS":
            color = YELLOW
        elif sev == "TRYGG":
            color = GREEN
        else:
            color = RESET

        payload_repr = repr(r["payload"])[1:-1]
        if len(payload_repr) > 23:
            payload_repr = payload_repr[:20] + "..."

        finding_text = r["findings"][0] if r["findings"] else "OK"
        if len(finding_text) > 42:
            finding_text = finding_text[:39] + "..."

        time_str = f"{r['elapsed_ms']}ms" if r["elapsed_ms"] is not None else "N/A"
        http_code = str(r["status_code"]) if r["status_code"] else "ERR"

        print(f"{color}{sev:<9}{RESET} | {time_str:<8} | {r['category']:<18} | {payload_repr:<25} | [{http_code}] {finding_text}")

    print("-" * 92)
    print(f"\n{BOLD}OPPSUMMERING FOR FELT '{args.param}':{RESET}")
    print(f"Totalt antall tester kjørt: {summary['total_probes']}")
    print(f" - {RED}Kritiske avvik (CWE-89):{RESET} {summary['critical']}")
    print(f" - {RED}Høye avvik (CWE-79):{RESET}     {summary['high']}")
    print(f" - {YELLOW}Advarsler:{RESET}               {summary['medium']}")
    print(f" - {GREEN}Bestått / Robuste:{RESET}       {summary['safe']}")

    if summary["overall_status"] == "SÅRBAR":
        print(f"\n{RED}{BOLD}KONKLUSJON: Parameteren '{args.param}' krever tiltak før produksjonssetting.{RESET}")
        print("Anbefalte utbedringstiltak:")
        print("  1. Benytt prepared statements / parametriserte spørringer i databasesjiktet.")
        print("  2. Sørg for at utdata HTML-kodes (f.eks. html.escape() eller rammeverkets malmotor).")
        print("  3. Legg til eksplisitte type- og lengdebegrensninger på klientsiden og i API-laget.")
    else:
        print(f"\n{GREEN}{BOLD}KONKLUSJON: Parameteren fremstår robust mot testede mønstre.{RESET}")


if __name__ == "__main__":
    main()
