# IBAN-Check als Proof-of-Concept

https://www.iban-check.org

## Problemstellung
IBANs werden durch Angreifer in Mails immer wieder gefälscht. Dadurch kommen Kontoüberweisungen (z.Bsp. XRechnung, ZUGFeRD oder PDF-Anhänge) nicht beim regulären Rechnungsersteller an.

## Lösungansatz
Ein Rechnungsersteller setzt im DNS verschlüsselte Einträge seiner Bankverbindungen. Der Empfänger prüft diese und kann dadurch Manipulationen leichter erkennen.

## technischer Ansatz
### SHA-256 einer IBAN erstellen
#### Linux / macOS:
```
printf '%s' "DE44500105175407324931" \| tr -d '[:space:]' \| sha256sum \| cut -d' ' -f1
```

#### Windows:
```
powershell -NoProfile -Command "$iban='DE44500105175407324931';[BitConverter]::ToString((([Security.Cryptography.SHA256]::Create()).ComputeHash([Text.Encoding]::UTF8.GetBytes($iban)))) -replace '-',''"
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
