<#
.SYNOPSIS
    IBAN ⇄ DNS-SHA256 Checker mit DNSSEC-Validierung per DNS-over-HTTPS.

.DESCRIPTION
    Entfernt Whitespace aus der IBAN, berechnet den SHA-256-Hash, fragt bis zu zehn
    TXT-Records (_iban … _iban10) über dns.google/resolve ab (mit DNSSEC-Flag),
    vergleicht den Hash und gibt Status sowie Exit-Code zurück:
      0 = Übertragung sicher & Hash gefunden
      1 = Hash gefunden, aber ohne DNSSEC
      2 = Kein passender Hash gefunden
      3 = Fehler bei DNS-Abfrage

.PARAMETER Iban
    Die zu prüfende IBAN (z.B. DE44500105175407324931).

.PARAMETER Domain
    Die Domain, unter der die TXT-Records liegen (z.B. example.com).

.PARAMETER Resolver
    (Optional) URL des DoH-Resolvers. Standard: https://dns.google/resolve

.EXAMPLE
    .\IbanCheck.ps1 -Iban "DE44500105175407324931" -Domain "example.com"

.NOTES
    Erfordert PowerShell 5+ (Windows) oder PowerShell Core (Linux/macOS).
#>

param(
    [Parameter(Mandatory)][string] $Iban,
    [Parameter(Mandatory)][string] $Domain,
    [string] $Resolver = 'https://dns.google/resolve'
)

# 1) Berechne SHA-256-Hash (hex, lowercase)
$clean = $Iban -replace '\s',''
$bytes = [System.Text.Encoding]::UTF8.GetBytes($clean)
$sha   = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha.ComputeHash($bytes)
$ibanHash  = ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''

$dnssecOK = $false
$found    = $false
$matchedRecord = $null

# 2) Schleife über _iban … _iban10
for ($i = 1; $i -le 10 -and -not $found; $i++) {
    $label = if ($i -eq 1) { '_iban' } else { "_iban$i" }
    $name  = "$label.$Domain"

    # Baue DoH-URL mit DNSSEC-Flag (do=1)
    $url = "$Resolver?name=$name&type=TXT&do=1"

    try {
        $resp = Invoke-RestMethod -Uri $url -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Write-Error "DNS-Fehler bei $name: $_"
        exit 3
    }

    # DNSSEC-AD-Flag auswerten
    if ($resp.AD -eq $true) { $dnssecOK = $true }

    # TXT-Einträge parsen
    foreach ($ans in $resp.Answer) {
        # Daten ohne führende/abgeschlossene Anführungszeichen
        $txt = $ans.data.Trim('"') 
        # v=1; k=sha256; hash=…
        $map = @{}
        $txt.Split(';') | ForEach-Object {
            $kv = $_.Trim().Split('=',2)
            if ($kv.Length -eq 2) {
                $map[$kv[0].ToLower()] = $kv[1].ToLower()
            }
        }
        if (($map.v -eq '1') -and ($map.k -eq 'sha256') -and ($map.hash -eq $ibanHash)) {
            $found = $true
            $matchedRecord = $txt
            break
        }
    }
}

# 3) Ergebnis ausgeben & Exit-Code setzen
if ($found) {
    if ($dnssecOK) {
        Write-Host "✅ Übertragung sicher und Hash vorhanden"
        Write-Host "Gefundener Record: $matchedRecord"
        exit 0
    } else {
        Write-Host "⚠️ Hash stimmt, aber Übertragung unsicher (keine DNSSEC-Signatur)"
        Write-Host "Gefundener Record: $matchedRecord"
        exit 1
    }
} else {
    Write-Host "❌ Kein passender Hash gefunden."
    exit 2
}
