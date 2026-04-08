# hit-sbom-import

iTop 3.2 extension for importing [CycloneDX](https://cyclonedx.org/) Software Bills of Materials (SBOM) and visualising the impact chain from individual components all the way to Business Processes.

---

## Data model

| Class | Parent | Description |
|---|---|---|
| `SBOMComponent` | `FunctionalCI` | A single package/library from a CycloneDX BOM |
| `SBOMArtifact` | `FunctionalCI` | The primary artifact a BOM describes |
| `lnkSBOMArtifactToSBOMComponent` | link | Many-to-many: artifact ↔ component |
| `lnkSBOMComponentToSBOMComponent` | link | Component dependency edge (dependent → dependency) |

Both `SBOMComponent` and `SBOMArtifact` extend `FunctionalCI`, so they inherit org, contacts, documents, change tickets, and the full iTop impact graph.

Impact chain: **SBOMComponent → SBOMArtifact → FunctionalCI → ApplicationSolution → BusinessProcess**

---

## SBOM Import — REST API

### Endpoint

```
POST /extensions/hit-sbom-import/webservices/import_sbom.php
```

Authentication: HTTP Basic Auth.  
Supported formats: CycloneDX JSON (`.json`) and CycloneDX XML (`.xml`).

### Parameters

| Field | Type | Required | Description |
|---|---|---|---|
| `org_id` | integer | yes | iTop Organisation ID |
| `functionalci_id` | integer | no | ID of the FunctionalCI (App/Server) this SBOM describes. Pass `0` to leave unlinked. |
| `sbom_file` | file upload | yes | CycloneDX `.json` or `.xml` file |

### curl examples

```bash
# Python environment SBOM
curl -u sbom:password \
  -F 'org_id=1' \
  -F 'functionalci_id=0' \
  -F 'sbom_file=@python-sbom.cdx.json' \
  'http://<itop>/extensions/hit-sbom-import/webservices/import_sbom.php'

# npm project SBOM (837 components — requires memory_limit >= 512M, see below)
curl -u sbom:password \
  -F 'org_id=1' \
  -F 'functionalci_id=0' \
  -F 'sbom_file=@npm-sbom.cdx.json' \
  'http://<itop>/extensions/hit-sbom-import/webservices/import_sbom.php'
```

### Successful response

```json
{
  "status": "ok",
  "artifact_id": 12,
  "artifact_name": "myapp 1.0.0",
  "component_count": 142,
  "skipped_count": 58,
  "dep_edge_count": 310,
  "errors": []
}
```

### Browser UI

Navigate to the same URL without curl — it renders an HTML upload form.

---

## PHP configuration for large SBOMs

Large SBOMs (> 500 components or > 2 MB) require higher PHP limits. Add or edit `/etc/php.d/99-itop.ini` (or the equivalent for your distro):

```ini
upload_max_filesize = 64M
post_max_size       = 64M
memory_limit        = 512M
max_execution_time  = 120
```

Then restart Apache/php-fpm:

```bash
systemctl restart apache2   # or httpd / php-fpm
```

---

## Impact Analysis page

A dedicated page that renders the iTop impact graph starting from any `SBOMComponent` or `SBOMArtifact` — without touching any iTop core file.

### URL

```
/extensions/hit-sbom-import/webservices/sbom_impact.php?class=SBOMComponent&id=<id>
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `class` | `SBOMComponent` | `SBOMComponent` or `SBOMArtifact` |
| `id` | — | Object ID. Omit to see a simple object picker. |
| `relation` | `impacts` | Relation to traverse (only `impacts` is defined) |
| `direction` | `down` | `down` = what this component impacts; `up` = what it depends on |
| `g` | `5` | Grouping threshold for the graph |

The "Impacts" tab on every `SBOMComponent` object in the normal iTop UI also works automatically once the datamodel is compiled.

---

## OSV.dev Vulnerability Scanner — `osv-scan.py`

Fetches all `SBOMComponent` records from iTop, queries [OSV.dev](https://osv.dev/) in parallel, and writes results back into the `vuln_*` fields.

### Requirements

```bash
pip install requests cvss
```

### Configuration

The script reads connection details from `.live-env` in the same directory (or accepts CLI flags):

```
ITOP_URL=http://<itop>
ITOP_REST_USER=sbom
ITOP_REST_PASS=password
```

### Usage

```bash
# Full scan — reads from iTop, queries OSV, writes results back
python3 osv-scan.py

# Override connection settings
python3 osv-scan.py --url http://51.20.136.47/itop --user sbom --pass 'Passw0rd!'

# Dry run — scan only, don't write to iTop
python3 osv-scan.py --dry-run

# Skip components whose cached data is already current
python3 osv-scan.py --only-changed

# Increase parallelism (default: 10 threads)
python3 osv-scan.py --workers 20

# Skip reading/writing vuln_* fields (useful before the datamodel is applied)
python3 osv-scan.py --no-cache --dry-run
```

### Fields updated in iTop

| Field | Type | Description |
|---|---|---|
| `vuln_severity` | enum | Highest severity: `none` / `low` / `medium` / `high` / `critical` |
| `vuln_ids` | text | Space-separated CVE/GHSA IDs (e.g. `CVE-2021-44228 GHSA-jfh8-c2jp-hdp8`) |
| `vuln_cvss_score` | decimal | Highest CVSS v3 base score |
| `vuln_attack_vector` | enum | `network` / `adjacent` / `local` / `physical` |
| `vuln_last_scanned` | datetime | UTC timestamp of the last scan |

---

## Installation

1. Copy the extension folder into `<itop-root>/extensions/hit-sbom-import/`
2. Run iTop setup (browser: `https://<itop>/setup/`) and apply the updated datamodel
3. Verify both `SBOMComponent` and `SBOMArtifact` appear under Configuration Management

---

## Files

```
hit-sbom-import/
├── module.hit-sbom-import.php          Module registration
├── datamodel.hit-sbom-import.xml       Class and relation definitions
├── model.hit-sbom-import.php           Compiler-generated PHP (do not edit)
├── en.dict.hit-sbom-import.php         English dictionary strings
├── images/
│   ├── artifact.png
│   └── component.png
├── lib/
│   └── SBOMImporter.php                CycloneDX JSON/XML import logic
├── webservices/
│   ├── import_sbom.php                 SBOM upload endpoint (browser + curl)
│   └── sbom_impact.php                 Impact analysis page
└── osv-scan.py                         OSV.dev vulnerability scanner
```
