

Readme · MD
# Phishing & Malware Analysis Lab
 
Static analysis of four real phishing and malware samples, using the workflow of identify, analyze, correlate with threat intelligence, extract
indicators, and writing a defensible verdict.
 
All samples were sourced from [MalwareBazaar](https://bazaar.abuse.ch) and handled in an
isolated REMnux VM with no network access. **No sample was ever executed, and no live
payloads are stored in this repository.**
 
Companion to my [Active Directory Security Lab](https://github.com/suepercrab) and [Wazuh SOC
Detection Lab](https://github.com/suepercrab), — together
covering identity, endpoint, and phishing threats.
 
---
 
## The four cases
 
| # | Sample | Verdict | What it demonstrates |
|---|---|---|---|
| [01](cases/case-01-benign-pdf.md) | PDF | **Benign** | Correctly clearing a clean file — tested for both embedded code and link-based lures |
| [02](cases/case-02-phishing-lure-pdf.md) | PDF | **Malicious (context)** | Threat-intel correlation — inert file tied to confirmed phishing infrastructure |
| [03](cases/case-03-macro-dropper-maldoc.md) | Word doc | **Malicious** | Macro analysis — `AutoOpen` → PowerShell → stealer hosted on abused AWS S3 |
| [04](cases/case-04-html-smuggling-convagent.md) | HTML | **Malicious** | HTML smuggling → full deobfuscation → confirmed Convagent trojan-dropper DLL |
 
Each case file contains the verdict with confidence, the evidence chain, impact,
defanged IOCs, recommended actions, and the screenshots supporting each finding.
 
## Skills demonstrated
 
- **PDF analysis** — `pdfid.py` object-type triage; `pdf-parser.py` content inspection and
  object-stream decompression (`-f`)
- **Macro analysis** — `olevba` VBA extraction, auto execution triggers, execution
  keywords, and automatically extracted IOCs
- **HTML smuggling analysis** — recognising `document.write(atob())`, decoding layered
  base64, and recovering an embedded PE payload
- **Payload identification** — `file`, magic-byte inspection, hashing, and VirusTotal
  family attribution
- **Threat-intel correlation** — MalwareBazaar tags, VirusTotal file and URL reputation,
  DNS resolution as a campaign status signal
- **IOC extraction and defanging** for safe handoff to blocking controls
- **Safe malware handling** — network isolation, snapshot rollback, static analysis
## Key findings at a glance
 
- **Case 03** — Word macro auto-downloads `flag_stealer.ps1` from an attacker-controlled
  **AWS S3 bucket** and runs it via `powershell.exe`. Legitimate cloud storage abused for
  payload hosting.
- **Case 04** — HTML smuggling delivers a **3.7 MB PE32 DLL** disguised as
  `WindowsUpdate.log`, identified as the **Convagent** trojan-dropper family (VirusTotal
  22/70). The kit carries three separate evasion mechanisms: a time-based self destruct,
  a Windows-only OS gate, and a click gate to defeat automated sandboxes.
- **Case 02** — A file with no malicious content whatsoever, correctly assessed as
  malicious *in context* through its association with a phishing domain that VirusTotal
  flags and that now resolves to `127.0.0.1` (decommissioned infrastructure).
- **Case 01** — Cleared as benign after testing for both attack models. Not every file in
  a malware corpus is malicious.
## Method
 
See **[methodology.md](methodology.md)** for the isolated VM configuration, safe handling
rules, the batch analysis workflow, tooling by file type, the environment issues
encountered (and their fixes), and the verification principles applied.
 
One of those principles is worth surfacing here: in Case 04 an initial extraction silently
truncated the payload to 12 bytes, which, because it happened to begin with `MZ`, looked
like a valid but undetected executable. The discrepancy was caught on a plausibility check
(12 bytes cannot be a working executable), the payload was re extracted correctly at
3.7 MB, and VirusTotal then identified it as Convagent. Validating an artifact's size and
structure before trusting a file type or reputation result is now part of the method.
 
## Repository structure
 
```
cases/          One markdown verdict per sample
screenshots/    Evidence images, numbered per case
methodology.md  Environment, safe handling, workflow, tooling, lessons
```
 
## Safety note
 
Every sample analyzed here is real, working malware. All analysis was performed statically
in an isolated VM with snapshot rollback; nothing was executed. Live samples and extracted
payloads are excluded from version control by design 
 
## Tools
 
REMnux · oletools (`olevba`) · Didier Stevens' `pdfid` / `pdf-parser` · `7z` · `exiftool` ·
CyberChef · VirusTotal · MalwareBazaar · urlscan.io · VirtualBox
 
