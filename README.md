# Aegis AppSec - Inputvalidering & Fuzzing Suite

Et strukturert og defensivt testrammeverk utviklet for automatisk verifisering av inputfelter i webapplikasjoner mot **SQL-injeksjon (CWE-89)**, **Cross-Site Scripting (CWE-79)**, **grenseverdier/bufferoverflyt (CWE-20)** og **tegnkoding/kontrolltegn (CWE-176)**.

Rammeverket er designet med et rent, profesjonelt bedriftsgrensesnitt og inkluderer en realistisk bedriftsportal (**NordicFlow ERP & Ordreregister**) for demonstrasjon og testing.

<img width="959" height="548" alt="image" src="https://github.com/user-attachments/assets/82d6697e-212b-4dbf-bb7a-567ec5c34038" />
<img width="954" height="515" alt="image" src="https://github.com/user-attachments/assets/b708dffe-92fa-4ecd-a190-b265bbd9b52c" />
<img width="950" height="497" alt="image" src="https://github.com/user-attachments/assets/77832739-ac4b-4dfa-9e78-1b5f5b426fa8" />


---

## 1. Målvalidering og virkemåte

- **Inliming av mål-URL:** Operatøren limer inn URL-en til endepunktet og parameteren som skal evalueres.
- **Målvalidering (`validate_target_url`):** Verktøyet validerer vertsadressen og kjører mot lokale testmiljøer (`localhost`, `127.0.0.1`, `::1`).
- **Diagnostisk evaluering:** Testene benytter strukturelle sonderinger for å avdekke databasefeil, manglende prepared statements og uenkodet refleksjon.

---

## 2. Prosjektstruktur

```text
fuzzy-security-test/
├── app_server.py      # Webserver (ThreadingHTTPServer): Serverer både målportalen (/target) og QA-dashboardet (/)
├── fuzz_engine.py     # Testmotor, valideringssuiter (CWE-89/79/20/176) og heuristisk responssjekk
├── fuzz_tester.py     # CLI-verktøy for terminal og CI/CD-pipelines med fargekodet tabell og JSON-eksport
├── test_suite.py      # Automatiserte enhets- og integrasjonstester
└── README.md          # Dokumentasjon, metodebeskrivelse og utbedringsveiledning
```

---

## 3. Kom i gang

### Steg 1: Start webserveren
Serveren benytter kun Pythons standardbibliotek:

```bash
python app_server.py
```

Serveren lytter på:
* **QA & Fuzzing Dashboard:** `http://localhost:8080/`
* **Målportal (NordicFlow ERP):** `http://localhost:8080/target?q=`

---

### Steg 2: Bruk Web-grensesnittet

1. Åpne **`http://localhost:8080/`** i nettleseren.
2. I feltet **«Mål-URL (Lim inn relevant URL)»** angis endepunktet:
   ```text
   http://localhost:8080/target?q=
   ```
3. Angi parameteren som skal testes (f.eks. `q`).
4. Velg ønskede valideringssuiter.
5. Klikk **«Kjør sikkerhetsanalyse»**.

#### Veksling mellom ubeskyttet og sikret modus:
- Klikk **«Endre Sikkerhetsmodus»** i toppmenyen:
  - **Ubeskyttet modus:** Benytter dynamisk SQL-strengsammensetting og rå HTML-refleksjon. Fuzzeren vil umiddelbart identifisere kritiske avvik (CWE-89 SQL-feillekkasje og CWE-79 uenkodet refleksjon).
  - **Sikret produksjonsmodus:** Aktiverer parametriserte spørringer (Prepared statements), lengdevalidering og `html.escape`. Alle tester passerer med grønn status.

---

### Steg 3: Kjøring via CLI

```bash
# Evaluer søkefeltet 'q' i terminalen:
python fuzz_tester.py --url "http://localhost:8080/target?q=" --param q

# Evaluer kun SQL-integritet:
python fuzz_tester.py --url "http://localhost:8080/target?q=" --param q --category "sql_probes"

# Eksporter rapport som maskinlesbar JSON:
python fuzz_tester.py --url "http://localhost:8080/target?q=" --param q --json
```

---

## 4. Testsuiter og evaluering

| Suite | Identifikator | Formål & Metode |
| :--- | :--- | :--- |
| **SQL-spørringsintegritet** | CWE-89 | Tester syntakssekvenser (`'`, `"`, `--`, `/* */`, tautologier) for å avdekke databasespesifikke feilmeldinger og strukturelle brudd. |
| **Tegnentiteter & XSS** | CWE-79 | Evaluerer om HTML-elementer, tagger (`<fuzztest>`) og event handlers reflekteres uenkodet i HTTP-responsen. |
| **Grenseverdier & Buffer** | CWE-20 | Tester tomme strenger, mellomrom og store datamengder (opptil 10 000 tegn) for å verifisere stabil minne- og prosesseringshåndtering. |
| **Tegnsett & Kodingsanomalier** | CWE-176 | Undersøker håndtering av null-bytes (`%00`, binære null-tegn), katalogkryssing (`../`), template tags (`{{7*7}}`) og linjeskift. |

---

## 5. Anbefalte sikringstiltak (Remediation)

### 1. Parametriserte spørringer (Prepared Statements)
Unngå strengformatering i databasekall:

```python
# SIKRET (Python / SQLite):
cursor.execute("SELECT * FROM orders WHERE customer LIKE ?", (f"%{query}%",))
```

### 2. Kontekstuell entitetskoding
Sørg for at utdata kodes før det settes inn i HTML:

```python
import html
safe_output = html.escape(query)
```

### 3. API-validering og typebegrensning
Avvis uventet input tidlig med HTTP 400 Bad Request fremfor uhåndterte 500-unntak:

```python
if len(query) > 100:
    return "Ugyldig input: overskrider maksimal feltlengde", 400
```
