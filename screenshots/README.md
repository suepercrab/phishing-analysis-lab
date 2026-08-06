# Screenshots
 
Evidence images supporting each case verdict. Named `NN-what-it-shows.png` so the
investigation reads in order.
 
| File | Case | Shows |
|---|---|---|
| 19d-pdfid-results.png | 01 | pdfid keyword counts |
| suspicious-19d.png | 01 | Object dump — FlateDecode streams + image XObject |
| 19d-no-urls-results.png | 01 | Empty URI / http searches |
| 19d-bazaar-results.png | 01 | MalwareBazaar — `pdf` tag only, no family, Anonymous |
| 5a2-pdfid-results.png | 02 | pdfid — /ObjStm = 1, active content zero |
| suspicious-55.png | 02 | Full pdfid keyword list |
| 5a2-no-urls-hidden-objects.png | 02 | Empty searches incl. decompressed object stream |
| 5a2-bazaar-results.png | 02 | MalwareBazaar — `alfredcore-com` tag, JAMESWT_WT |
| 5a2-virustotal-result.png | 02 | Domain 2/92 — Fortinet Phishing, resolves 127.0.0.1 |
| 79e-olevba-1.png | 03 | Macro source — AutoOpen + payload URL |
| 79e-olevba-2.png | 03 | olevba analysis table — AutoExec / Suspicious / IOC |
| 55a-html.png | 04 | Raw HTML — document.write(atob( |
| 55a-script.png | 04 | Decoded layer — Date.now() self-destruct + blob |
| 55a-dropper.png | 04 | Dropper JS — Blob → WindowsUpdate.log → a.click() |
| 55a-exe.png | 04 | Error step — truncated 12-byte extraction |
| 55a-payload-hash.png | 04 | Correct extraction — 3.7 MB PE32 DLL + hash |
| 55a-virustotal.png | 04 | VirusTotal 22/70 — Convagent trojan-dropper |
 
**Note:** SHA-256 hashes are public (they appear on MalwareBazaar/VirusTotal) and are not
redacted. No personal or victim data appears in any screenshot.
 
