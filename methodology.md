

Methodology · MD
# Methodology
 
How these samples were handled and analyzed. Every sample in this lab is **real, working
malware**; the entire method is built around analyzing it without executing it and without
exposing anything outside the analysis VM.
 
---
 
## 1. Analysis environment
 
| Component | Configuration |
|---|---|
| Host | Windows desktop, VirtualBox |
| Analysis VM | REMnux (Ubuntu-based malware-analysis distribution) |
| VM resources | 4096 MB RAM, 2 CPU cores |
| Network | VirtualBox **Internal Network** (`malnet`) — isolated |
| Shared folders | **Disabled** |
| Shared clipboard | **Disabled** |
| Snapshot | Single `BASELINE`, taken before any sample was extracted |
 
### Why Internal Network and not Host-Only or the existing lab network
 
The analysis VM is deliberately placed on its own **Internal Network** with no other hosts
on it. It cannot reach the internet, the host, or any other VM.
 
Placing a malware VM on a shared lab network (e.g. alongside domain joined Windows hosts)
would give a sample that *did* execute a set of reachable targets — local subnet scanning,
credential spraying, and lateral movement are standard malware behaviours. Isolation is
scoped so that the blast radius of a mistake is a single disposable VM.
 
Host-Only was rejected because it still exposes the host. Bridged was rejected outright.
 
---
 
## 2. Safe-handling rules
 
1. Samples are only ever opened inside the isolated VM — never on the host.
2. **Nothing is executed.** No double clicking, no "enable content", no running macros or
   binaries. Files are *read* with parsing tools only.
3. Samples remain **zipped and password protected** (`infected`) until the moment of
   analysis.
4. Samples are downloaded **on the analysis VM itself** over a brief NAT window, then the
   VM is returned to Internal Network. Samples are never transferred from another machine
   via shared folders or removable media — every transfer channel is an additional seam.
5. NAT is only ever attached to a VM in a known-clean state.
6. Findings leave the VM as **text only** (hashes, URLs, notes) — read off screen or
   captured as host-side screenshots. No files are exported.
7. The VM is rolled back to `BASELINE` when the batch is complete.
### Why static analysis is safe
 
A malicious file that never runs is inert — malware is a program, and a program that does
not execute does nothing. Parsing tools (`pdfid`, `olevba`, `sha256sum`) *read bytes*; they
do not execute them.
 
The real risk is **accidental** execution: a file manager generating a thumbnail, a mail
client rendering a preview, a desktop indexer parsing content, or opening a file in its
intended application (Word, a PDF reader) rather than in a parser. The working rule is:
tools that read a file's *structure* are safe; anything that *renders or opens* the file in
its native application constitutes execution.
 
---
 
## 3. Workflow (batch method)
 
1. Adapter → **NAT**; confirm connectivity (`ping -c 3 8.8.8.8`)
2. Download the full sample set from MalwareBazaar; leave every sample zipped
3. Stage them: `mv ~/Downloads/*.zip ~/samples`
4. Adapter → **Internal Network**; confirm isolation (`ping` must now **fail**)
5. Take the `BASELINE` snapshot — samples present, all still zipped
6. Analyze each sample in its own `caseNN/` directory, extracting only when ready
7. Export each case's findings to the host **as that case is completed**
8. When the batch is finished, roll back to `BASELINE`
Findings are exported per case rather than at the end because the single rollback erases
everything at once.
 
**Note on this method:** because there is no rollback between cases, extracted samples
coexist during the session. This is acceptable for **static** analysis, where nothing
executes and samples cannot affect one another. Dynamic analysis would require a rollback
between every execution.
 
---
 
## 4. Tooling by file type
 
| File type | Primary tool | Purpose |
|---|---|---|
| Any | `sha256sum`, `file` | Fingerprint and identify |
| PDF | `pdfid.py` | Count risky object types (`/JS`, `/OpenAction`, `/Launch`, …) |
| PDF | `pdf-parser.py` | Read object contents; `-f` decompresses object streams |
| Office document | `olevba` | Extract and classify VBA macros without execution |
| Office document | `oledump.py` | Alternative OLE stream inspection |
| HTML | `grep`, `less`, `base64 -di` | Read source; extract and decode embedded payloads |
| Metadata | `exiftool` | Authorship, creation tool, timestamps |
 
**Reputation lookups** (VirusTotal, MalwareBazaar, urlscan.io) are performed **from the
host browser using extracted indicator strings** — never from the analysis VM, and never by
visiting a suspicious URL directly.
 
---
 
## 6. Verification principles applied
 
- **Plausibility-check every artifact.** A 12-byte file cannot be a working executable,
  regardless of what magic bytes it starts with. Size and structure are checked before a
  file type identification or a reputation result is trusted. (See Case 04.)
- **A clean surface scan is not a clearance.** Where a PDF contained an object stream
  (`/ObjStm`), it was decompressed and researched rather than cleared on `pdfid` counts
  alone. (See Case 02.)
- **Test for the current threat model, not the historical one.** Modern malicious PDFs are
  more often link-based lures than JavaScript exploits, so URL presence is tested
  explicitly rather than inferred from a zero `/JS` count.
- **A low detection ratio is not "clean."** Phishing infrastructure is short-lived and
  under reported; label *specificity* and corroborating evidence (e.g. DNS resolution)
  outweigh the raw vendor count. (See Case 02.)
- **Benign is a valid verdict.** Not every file in a malware corpus is malicious.
  Over-flagging wastes response capacity and erodes trust in the analysis (See Case 01.)
---
 
## 7. Repository safety
 
Live samples and extracted payloads are **excluded from version control by design** — see
`.gitignore`. This repository documents the *analysis*: tool output, indicators, verdicts,
and screenshots. No malware is distributed here.
 
