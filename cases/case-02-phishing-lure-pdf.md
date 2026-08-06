

Case 02 phishing lure pdf · MD
# Case 02 — Phishing Lure PDF (Malicious in Campaign Context)
 
**Verdict:** Malicious in campaign context — Medium-High confidence
**Sample SHA-256:** `5a2c5ecfaa6a582055f07fc292f602c39c59d5ae6bacf711acacc60f7ed3d8a6`
**File type:** PDF 1.7, 2 pages
**Source:** MalwareBazaar
**Analyzed:** Isolated REMnux VM, static analysis only (never executed)
 
---
 
## Summary
 
A PDF whose file contents are inert — no code, no links — but which MalwareBazaar
associates with a phishing domain that threat intelligence sources confirm as malicious.
Assessed as the lure/delivery component of a phishing campaign whose payload was hosted
externally on infrastructure that is now decommissioned.
 
## Evidence
 
**1. Active-content scan — `pdfid.py`**
 
All dangerous object types zero (`/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`,
`/EmbeddedFile`, `/AcroForm`, `/XFA`, `/RichMedia`, `/JBIG2Decode`).
 
**One difference from a routine clean PDF:** `/ObjStm` = **1**. An object stream can
*conceal other objects from a surface scan* — `pdfid` cannot see inside it. A zero-count
result is therefore not sufficient to clear this file.
 
**2. Object-stream decompression — `pdf-parser.py -f`**
 
Because of the object stream, the file was decompressed and researched rather than
cleared on the surface scan alone:
 
- `pdf-parser.py --search URI` → empty
- `pdf-parser.py | grep -i http` → empty
- `pdf-parser.py -f | grep -i javascript` → empty
- `pdf-parser.py -f | grep -i http` → empty
Nothing hidden in the object stream. The file itself is genuinely inert.
 
**3. Threat intelligence — the actual finding**
 
MalwareBazaar tags this sample **`pdf` and `alfredcore-com`** — a domain-based campaign
tag. Reporter: **JAMESWT_WT**, an established malware researcher (raising confidence that
the association is deliberate and accurate, not bulk-upload noise).
 
**4. Domain reputation — VirusTotal URL report for `http://alfredcore.com/`**
 
| Finding | Detail |
|---|---|
| Detection | **2 / 92** vendors |
| alphaMountain.ai | **Malicious** |
| Fortinet | **Phishing** |
| DNS resolution | **127.0.0.1** (localhost — sinkholed / parked) |
| urlscan.io | Unable to scan — nothing live to load |
 
A 2/92 score is *not* dismissible here. Phishing infrastructure is deliberately
short lived and underreported; a specific "Phishing" categorization from a major vendor
carries more weight than the raw ratio suggests. The 127.0.0.1 resolution and urlscan's
failure independently confirm the domain is no longer live — consistent with a campaign
that has run its course.
 
## Impact
 
The file alone carries no executable payload. Its role is trust building: a legitimate
looking document delivered alongside phishing infrastructure that hosted the actual
malicious content. Victims would have been directed to `alfredcore[.]com` through the
campaign rather than through the PDF itself.
 
## IOCs
 
| Type | Value | Note |
|---|---|---|
| SHA-256 | `5a2c5ecfaa6a582055f07fc292f602c39c59d5ae6bacf711acacc60f7ed3d8a6` | The PDF |
| Domain | `alfredcore[.]com` | Phishing infra; VT 2/92; now resolves 127.0.0.1 |
 
## Actions
 
- **Block** `alfredcore[.]com` at proxy and DNS (defensive value is low now that it is
  sinkholed, but block for completeness and historical hunting).
- **Hunt** SIEM/proxy logs for historic connections to `alfredcore[.]com` — the campaign
  window is the relevant search period, not the present.
- **Block** the file hash at the mail gateway as a known campaign artifact.
- No endpoint remediation indicated from this file alone.
## Analyst note
 
This case demonstrates that **file-based analysis and threat-intelligence correlation are
separate layers**, and a verdict can depend entirely on the second. Static analysis of the
artifact returned nothing; the malicious indicator came only from correlating the sample
with campaign infrastructure and then checking that infrastructure's reputation.
 
Two judgment points worth stating explicitly:
1. The `/ObjStm` was decompressed rather than trusting the surface scan — the file was
   cleared *thoroughly*, not lazily.
2. A low detection ratio (2/92) was not treated as "clean." The *specificity* of the
   labels (Phishing, Malicious) and the DNS evidence outweighed the raw count.
## Screenshots
 
| File | Shows |
|---|---|
| `5a2-pdfid-results.png` | `pdfid.py` — `/ObjStm` = 1, all active content zero |
| `suspicious-55.png` | Full pdfid keyword list |
| `5a2-no-urls-hidden-objects.png` | Empty searches including decompressed (`-f`) object stream |
| `5a2-bazaar-results.png` | MalwareBazaar: `alfredcore-com` tag, reporter JAMESWT_WT |
| `5a2-virustotal-result.png` | Domain 2/92 — Fortinet Phishing, alphaMountain Malicious, 127.0.0.1 |
 
