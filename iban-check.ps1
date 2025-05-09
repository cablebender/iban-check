<#
.SYNOPSIS
    IBAN ⇄ DNS-SHA256 Checker mit optionalen Debug-/Verbose-Ausgaben.

.DESCRIPTION
    Entfernt Whitespace aus der IBAN, berechnet den SHA-256-Hash, fragt bis zu zehn
    TXT-Records (_iban … _iban10) über DNS-over-HTTPS ab (mit DNSSEC-Flag),
    vergleicht den Hash und gibt Status sowie Exit-Code zurück.
    Mit `-Debug` oder `-Verbose` erhältst Du zusätzliche Debug-Informationen,
    inklusive eines nslookup-Fallbacks, wenn Resolve-DnsName fehlt.

.PARAMETER Iban
    Die zu prüfende IBAN (z.B. DE44500105175407324931).

.PARAMETER Domain
    Die Domain, unter der die TXT-Records liegen (z.B. example.com).

.PARAMETER Resolver
    (Optional) URL des DoH-Resolvers. Standard: https://dns.google/resolve

.EXAMPLE
    .\iban-check.ps1 -Iban "DE44500105175407324931" -Domain "example.com" -Debug
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Iban,
    [Parameter(Mandatory)][string] $Domain,
    [string] $Resolver = 'https://dns.google/resolve'
)

function Write-DebugLog { param($m); Write-Debug $m; Write-Verbose $m }

# 1) Resolver-URL validieren
if ($Resolver -notmatch '^https?://') {
    $Resolver = "https://$Resolver"
    Write-DebugLog "Resolver korrigiert auf: $Resolver"
}

# 2) SHA-256-Hash der IBAN
$clean     = $Iban -replace '\s',''
$bytes     = [Text.Encoding]::UTF8.GetBytes($clean)
$hashBytes = [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
$ibanHash  = ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''

Write-DebugLog "Saubere IBAN: $clean"
Write-DebugLog "Hash: $ibanHash"

$dnssecOK      = $false
$found         = $false
$matchedRecord = $null

# 3) Schleife über _iban … _iban10
for ($i = 1; $i -le 10 -and -not $found; $i++) {
    $label = if ($i -eq 1) { '_iban' } else { "_iban$i" }
    $name  = "$label.$Domain"

    # UriBuilder für DoH-Anfrage
    $u       = [UriBuilder]::new($Resolver)
    $u.Query = "name=$name&type=TXT&do=1"
    $dohUrl  = $u.Uri.AbsoluteUri

    Write-DebugLog "DoH-Resolver: $Resolver"
    Write-DebugLog "DoH-URL:      $dohUrl"

    if ($PSBoundParameters.Debug -or $PSBoundParameters.Verbose) {
        # Versuche Resolve-DnsName
        if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
            Write-DebugLog ">> Resolve-DnsName:"
            try {
                Resolve-DnsName -Name $name -Type TXT -Server 8.8.8.8 -ErrorAction Stop |
                  ForEach-Object { Write-DebugLog "   TXT: $($_.Strings -join '') (DNSSEC: $($_.Secured))" }
            } catch {
                Write-DebugLog "   Resolve-DnsName-Fehler: $($_.Exception.Message)"
            }
        }
        else {
            Write-DebugLog ">> Resolve-DnsName nicht verfügbar, nutze nslookup-Fallback"
            $ns = nslookup -type=TXT $name 8.8.8.8 2>&1
            $ns | ForEach-Object { Write-DebugLog "   nslookup: $_" }
        }
    }

    try {
        $resp = Invoke-RestMethod -Uri $u.Uri -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Write-Error "DNS-Fehler bei ${name}: $_"
        exit 3
    }

    if ($resp.AD) {
        $dnssecOK = $true
        Write-DebugLog "DNSSEC validiert (AD=1)"
    }

    foreach ($ans in $resp.Answer) {
        $txt = $ans.data.Trim('"')
        Write-DebugLog "Gefundener TXT: $txt"

        $map = @{}
        $txt.Split(';') | ForEach-Object {
            $kv = $_.Trim().Split('=',2)
            if ($kv.Length -eq 2) { $map[$kv[0].ToLower()] = $kv[1].ToLower() }
        }
        if ($map.v -eq '1' -and $map.k -eq 'sha256' -and $map.hash -eq $ibanHash) {
            $found         = $true
            $matchedRecord = $txt
            Write-DebugLog "Record passt!"
            break
        }
    }
}

# 4) Ausgabe & Exit-Code
if ($found) {
    if ($dnssecOK) {
        Write-Host "✅ Übertragung sicher und Hash vorhanden"
        Write-Host "Gefundener Record: $matchedRecord"
        exit 0
    }
    Write-Host "⚠️ Hash stimmt, aber ohne DNSSEC"
    Write-Host "Gefundener Record: $matchedRecord"
    exit 1
}

Write-Host "❌ Kein passender Hash gefunden."
exit 2
