# M365 Security & IAM Intelligence Engine

**Read-only, full-spectrum Microsoft 365 security posture assessment tool.**

> ⚠️ **This tool NEVER modifies the tenant.** No remediation. No auto-fix. No write operations. Strictly read-only analysis.

## Features

- **7 Security Domains**: Identity, Conditional Access, Privileged Access, Device Compliance, Application Security, Defender, Monitoring
- **40+ Security Controls**: Deep inspection with CIS Benchmark, NIST 800-53, and Zero Trust alignment
- **Scoring Model**: 0-100 composite score with per-domain breakdowns and maturity levels
- **Attack Path Simulation**: Identifies chained weaknesses across domains
- **5 Output Formats**: JSON, CSV (3 files), Markdown technical report, Executive summary, Interactive HTML
- **Multi-Tenant Support**: Named profile system — manage multiple tenants from one install
- **250K+ User Support**: Streaming collectors, async concurrency, SQLite caching
- **Safety Enforced**: HTTP-level guard blocks all write operations before they reach the wire

---

## Prerequisites

- **Python 3.11+**
- **Microsoft Entra App Registration** with Application (not delegated) permissions — see [Azure Setup](#azure-app-registration-setup) below
- **Certificate** (PFX/PKCS12) exported as a base64-encoded text file — see [Certificate Setup](#certificate-setup) below

---

## Azure App Registration Setup

You must create an app registration in **each tenant** you want to scan. These steps require a **Global Administrator** or **Application Administrator** role.

### Step 1 — Create the App Registration

1. Sign into the [Azure Portal](https://portal.azure.com) for the target tenant
2. Go to **Entra ID → App registrations → New registration**
3. Name it something like `M365 Security Engine` and click **Register**
4. Copy the **Directory (tenant) ID** and **Application (client) ID** — you will need these

### Step 2 — Grant API Permissions

In the app registration, go to **API permissions → Add a permission → Microsoft Graph → Application permissions**.

Add the following permissions, then click **Grant admin consent**:

| Permission | Purpose |
|---|---|
| `User.Read.All` | Read all user accounts |
| `Group.Read.All` | Read groups and memberships |
| `Directory.Read.All` | Read directory objects and roles |
| `Policy.Read.All` | Read Conditional Access policies |
| `RoleManagement.Read.All` | Read role assignments (PIM, RBAC) |
| `Application.Read.All` | Read app registrations and service principals |
| `AuditLog.Read.All` | Read audit and sign-in logs |
| `SecurityEvents.Read.All` | Read Defender/security alerts |
| `IdentityRiskyUser.Read.All` | Read Identity Protection risky users |
| `DeviceManagementConfiguration.Read.All` | Read Intune device configurations |
| `DeviceManagementManagedDevices.Read.All` | Read Intune managed devices |
| `PrivilegedAccess.Read.AzureAD` | Read PIM role activations |
| `UserAuthenticationMethod.Read.All` | Read MFA/auth method registrations |

> All permissions are **read-only**. No write permissions are required or used.

### Step 3 — Create a Certificate

The engine authenticates with a certificate (not a client secret). This is more secure and does not expire as quickly.

#### Generate a self-signed certificate (PowerShell)

```powershell
$cert = New-SelfSignedCertificate `
    -Subject "CN=M365SecurityEngine" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2)

# Export as PFX
$password = ConvertTo-SecureString -String "YourCertPassword" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "m365engine.pfx" -Password $password

# Export public key (.cer) to upload to Azure
Export-Certificate -Cert $cert -FilePath "m365engine.cer"
```

#### Upload the public key to your app registration

1. In the app registration, go to **Certificates & secrets → Certificates → Upload certificate**
2. Upload the `m365engine.cer` file (public key only — never upload the private key/PFX)

---

## Certificate Setup

The engine reads the certificate from a **base64-encoded PFX file** (the `base64.txt` convention used throughout this toolkit).

### Convert your PFX to base64

**PowerShell:**
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes(".\m365engine.pfx")) | Out-File -Encoding ascii base64.txt
```

**Bash/macOS:**
```bash
base64 -i m365engine.pfx -o base64.txt
```

Place `base64.txt` in the same directory where you run the engine, or specify the path with `--cert-path`.

> **Security note:** `base64.txt` contains your private key. Add it to `.gitignore` and never commit it.

---

## Installation

```bash
cd m365_security_engine
pip install -r requirements.txt
```

---

## Quick Start

### Option A — Profile-based (recommended for regular use)

Profiles store tenant credentials so you don't repeat flags every scan.

**1. Register the tenant profile (once per tenant):**

```bash
python -m m365_security_engine profile add contoso-prod \
  --tenant-id  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-id  "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" \
  --cert-path  "./base64.txt" \
  --display-name "Contoso Corp" \
  --set-default
```

**2. Run a scan:**

```bash
# Uses the default profile automatically
python -m m365_security_engine

# Or name a specific profile
python -m m365_security_engine --profile contoso-prod
```

**3. Enter the certificate password when prompted:**

```
Enter the certificate password: ••••••••
```

Or set the env var to skip the prompt:

```bash
# PowerShell
$env:M365_CERT_PASSWORD = "YourCertPassword"
python -m m365_security_engine

# Bash
M365_CERT_PASSWORD="YourCertPassword" python -m m365_security_engine
```

---

### Option B — Ad-hoc (no profile needed)

```bash
python -m m365_security_engine \
  --tenant-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-id "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" \
  --cert-path "./base64.txt" \
  --tenant-name "Contoso Corp"
```

---

### Option C — Delegated auth (device-code flow)

```bash
python -m m365_security_engine --delegated
# Opens a browser login — uses your own account permissions
```

---

## Multi-Tenant Profile Management

Profiles are stored in `~/.m365_security_engine/profiles.json` — outside the project directory so they are never accidentally committed.

```bash
# Add / update a profile
python -m m365_security_engine profile add <name> \
  --tenant-id  <GUID> \
  --client-id  <GUID> \
  --cert-path  <path-to-base64.txt> \
  --display-name "Friendly Name" \
  --set-default          # optional: make this the default

# List all profiles
python -m m365_security_engine profile list

# Switch the default
python -m m365_security_engine profile set-default <name>

# Remove a profile
python -m m365_security_engine profile remove <name>
```

**Example with two tenants:**

```bash
python -m m365_security_engine profile add contoso \
  --tenant-id "aaa..." --client-id "bbb..." --cert-path ./contoso_base64.txt --set-default

python -m m365_security_engine profile add fabrikam \
  --tenant-id "ccc..." --client-id "ddd..." --cert-path ./fabrikam_base64.txt

# Scan contoso (default)
python -m m365_security_engine

# Scan fabrikam explicitly
python -m m365_security_engine --profile fabrikam
```

---

## Output Files

Reports are written to `./m365_scan_output/` (override with `--output-dir`):

| File | Description |
|---|---|
| `m365_security_scan_<id>.json` | Full raw JSON — all findings, scores, evidence |
| `findings_<id>.csv` | One row per finding — importable into Excel or a SIEM |
| `domain_scores_<id>.csv` | Per-domain scores and maturity levels |
| `scan_summary_<id>.csv` | Single-row overall scan metrics |
| `technical_report_<id>.md` | Deep-dive Markdown with all findings and evidence |
| `executive_summary_<id>.md` | One-page leadership summary |
| `security_report_<id>.html` | Interactive HTML report with expandable evidence detail |

---

## Additional CLI Options

```bash
python -m m365_security_engine [options]

  --profile/-p <name>        Named profile to use
  --tenant-id  <GUID>        Tenant ID (ad-hoc, no profile needed)
  --client-id  <GUID>        Client ID (ad-hoc, use with --tenant-id)
  --cert-path  <path>        Path to base64-encoded PFX file
  --tenant-name <name>       Display name in reports (overrides profile)
  --output-dir/-o <path>     Output directory (default: ./m365_scan_output)
  --skip-intune              Skip Intune/device compliance collection
  --skip-defender            Skip Defender collection
  --no-cache                 Disable caching; force fresh collection
  --formats json csv ...     Select output formats (default: all)
  --delegated                Use device-code auth instead of certificate
  --config/-c <file>         Load settings from a JSON config file
```

---

## JSON Configuration File

Alternatively, create a `config.json` to store settings:

```json
{
  "auth": {
    "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
    "cert_base64_path": "./base64.txt",
    "auth_mode": "certificate"
  },
  "collection": {
    "enable_intune": true,
    "enable_defender": true,
    "batch_size": 999,
    "max_concurrent_requests": 4
  },
  "output": {
    "output_dir": "./m365_scan_output",
    "formats": ["json", "csv", "markdown", "executive", "html"]
  }
}
```

Then run:

```bash
python -m m365_security_engine --config config.json
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    __main__.py (Orchestrator)                        │
├──────────────┬──────────────┬──────────────┬────────────────────────┤
│   Auth       │  Collectors  │  Analyzers   │       Reporting        │
│  (MSAL)      │  (7 modules) │  (7 modules) │ JSON/CSV/MD/HTML/Exec  │
├──────────────┴──────────────┴──────────────┴────────────────────────┤
│                    Graph Client (httpx async)                        │
├─────────────────────────────────────────────────────────────────────┤
│                 Safety Guardian (read-only enforcer)                 │
├─────────────────────────────────────────────────────────────────────┤
│         Cache (SQLite)  │  Scoring Engine  │  Framework Mappings    │
├─────────────────────────────────────────────────────────────────────┤
│              Profiles (~/.m365_security_engine/profiles.json)       │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Authentication** → MSAL acquires token (certificate or device-code)
2. **Collection** → 7 collectors query Graph API concurrently (async, paginated, streamed)
3. **Analysis** → 7 analyzers inspect collected data, emit typed `Finding` objects
4. **Scoring** → Findings aggregated into 0-100 domain and overall scores
5. **Reporting** → Multi-format output with framework mappings and attack paths

### Safety Model

Every HTTP request passes through `SafetyGuardian` before reaching the wire:

- **Blocked methods**: POST, PUT, PATCH, DELETE (except safe-listed POSTs like `$batch`)
- **Blocked URL patterns**: `/invite`, `/assign`, `/remove`, `/update`, `/enable`, `/disable`, `/wipe`, etc.
- **Violation logging**: All blocked attempts are logged to an audit trail
- **Banner**: Printed at startup confirming read-only mode

## Scoring Model

| Severity | Base Deduction | Maturity 0 Multiplier | Maturity 5 Multiplier |
|----------|---------------|----------------------|----------------------|
| Critical | 18 pts | ×1.5 (27 pts) | ×0.6 (10.8 pts) |
| High | 10 pts | ×1.5 (15 pts) | ×0.6 (6 pts) |
| Medium | 5 pts | ×1.5 (7.5 pts) | ×0.6 (3 pts) |
| Low | 2 pts | ×1.5 (3 pts) | ×0.6 (1.2 pts) |

Domain weights: Identity 25%, Conditional Access 20%, Privileged Access 20%, Device 15%, App 10%, Monitoring 10%

## Framework Alignment

- **CIS Microsoft 365 Benchmark v3.x**: Controls mapped via `cis_benchmark` field
- **NIST 800-53 Rev 5**: Access Control (AC), Identification & Auth (IA), Audit (AU), etc.
- **Zero Trust**: Findings mapped to Identity, Devices, Applications, Data, Infrastructure, Networks pillars

## Extending

### Add a new collector

1. Create `collectors/my_collector.py` extending `BaseCollector`
2. Implement `async def collect()` → return data dict
3. Add to `collectors/__init__.py` `ALL_COLLECTORS` list

### Add a new analyzer

1. Create `analyzers/my_analyzer.py` extending `BaseAnalyzer`
2. Implement `def _analyze()` → call `self.add_finding()`
3. Add to `analyzers/__init__.py` `ALL_ANALYZERS` list

## Files

```
m365_security_engine/
├── __init__.py              # Package root
├── __main__.py              # CLI entry point & orchestrator
├── config.py                # Configuration & constants
├── profiles.py              # Multi-tenant profile management
├── requirements.txt         # Python dependencies
├── README.md                # This file
├── auth/
│   └── authenticator.py     # MSAL certificate + delegated auth
├── safety/
│   └── guardian.py          # Read-only HTTP enforcer
├── graph/
│   └── client.py            # Async Graph API client
├── cache/
│   └── store.py             # SQLite scan cache
├── collectors/
│   ├── base.py              # Abstract collector + result model
│   ├── identity.py          # Users, groups, roles, PIM, risky users
│   ├── apps.py              # App registrations, service principals, OAuth
│   ├── conditional_access.py# CA policies, named locations, auth methods
│   ├── intune.py            # Devices, compliance, MAM, baselines
│   ├── defender.py          # Licensing, alerts, secure score, MDE
│   ├── privilege.py         # Role definitions, assignments, consent policies
│   └── monitoring.py        # Audit logs, diagnostics, sign-in analysis
├── analyzers/
│   ├── base.py              # Abstract analyzer + Finding data model
│   ├── identity_analyzer.py
│   ├── ca_analyzer.py
│   ├── intune_analyzer.py
│   ├── privilege_analyzer.py
│   ├── app_analyzer.py
│   ├── defender_analyzer.py
│   └── monitoring_analyzer.py
├── scoring/
│   ├── engine.py            # Score computation + attack paths
│   ├── models.py            # Score data models
│   └── frameworks.py        # CIS / NIST / Zero Trust mapping
├── reporting/
│   ├── json_export.py       # Full JSON output
│   ├── csv_export.py        # CSV summaries
│   ├── markdown_report.py   # Technical deep-dive report
│   ├── executive_summary.py # One-page executive brief
│   ├── html_report.py       # Interactive HTML report with evidence detail
│   └── templates/
│       ├── technical_report.md.j2
│       └── executive_summary.md.j2
└── schemas/
    ├── finding.json         # JSON schema for findings
    └── scan_result.json     # JSON schema for full output
```

**Profile storage (outside the project):**

```
~/.m365_security_engine/
└── profiles.json            # Named tenant profiles (never commit this)
```

---

## Security Notes

- `base64.txt` (and any equivalent cert files) must be in `.gitignore` — they contain private keys
- `profiles.json` is stored in your home directory (`~/.m365_security_engine/`) and never inside the repo
- The tool will never prompt for or store passwords to disk — use the `M365_CERT_PASSWORD` env var for automation
- All Graph API calls are read-only; the Safety Guardian blocks any write attempt at the HTTP layer

---

## License

MIT License — see individual file headers for details.
