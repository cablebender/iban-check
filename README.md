# IBAN-Check als Proof-of-Concept

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

https://www.iban-check.org und https://iban-check.netzsicher.net

Powered by https://www.netzsicher.net

## Problemstellung
IBANs werden durch Angreifer in Mails immer wieder gefälscht. Dadurch kommen Kontoüberweisungen (z.Bsp. XRechnung, ZUGFeRD oder PDF-Anhänge) nicht beim regulären Rechnungsersteller an.

## Lösungansatz
Ein Rechnungsersteller setzt im DNS verschlüsselte Einträge seiner Bankverbindungen. Der Empfänger prüft diese und kann dadurch Manipulationen leichter erkennen.

## technischer Ansatz
### SHA-256 einer IBAN erstellen
#### Linux / macOS:
```
printf '%s' "DE12 3456 7890 1234 5678 90" | tr -d '[:space:]' | sha256sum | cut -d' ' -f1
```

#### Windows (Powershell):
```
([BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create()).ComputeHash([System.Text.Encoding]::UTF8.GetBytes(("DE12 3456 7890 1234 5678 90" -replace '\s','')))) -replace '-','').ToLower()
```
### im DNS veröffentlichen
#### bei einer IBAN:
```
_iban.example.com 3600 IN TXT "v=1; k=sha256; hash=<64-stelliger Hex-Hash>"
```
#### bei mehreren IBANs:
```
_iban.example.com 3600 IN TXT "v=1; k=sha256; hash=<64-stelliger Hex-Hash>"
_iban2.example.com 3600 IN TXT "v=1; k=sha256; hash=<64-stelliger Hex-Hash>"
..
_iban10.example.com 3600 IN TXT "v=1; k=sha256; hash=<64-stelliger Hex-Hash>"
```
