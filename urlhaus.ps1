$apiKey = "AbuseIPDB api key" #AbuseIPDB API key
$days = 30

$Header = @{
    "Key" = $apiKey
    "Accept" = "application/json"
}

#Download urlhaus IOC list
$response = Invoke-WebRequest -Uri "https://urlhaus.abuse.ch/downloads/text_recent/" -UseBasicParsing

# Array for ips and domains
$ips = @()
$domains = @()


$response.Content -split "`n" | ForEach-Object {
    $line = $_.Trim()

    # remove prefix
    $cleanUrl = $line -replace "^https?://", ""
    # Additional cleaning
    $finalUrl = $cleanUrl -replace ":[0-9]+.*", "" -replace "/.*", ""

    # Check for URL or domain
    if ($finalUrl -match "^\d{1,3}(\.\d{1,3}){3}$") {
        if (-not $ips.Contains($finalUrl)) {
            $ips += $finalUrl
        }
    } elseif ($finalUrl -ne "") {
        $domain = $finalUrl -replace "^www\.", ""
        if (-not $domains.Contains($domain)) {
            $domains += $domain
        }
    }
}

# Limit amount of IP's (default = 100)
$ips = $ips | Select-Object -First 900

$maliciousIps = @()

# Check abuseIPDB 
foreach ($ip in $ips) {
    $URICheck = "https://api.abuseipdb.com/api/v2/check"
    $BodyCheck = @{
        'ipAddress' = $ip
        'maxAgeInDays' = '90'
        'verbose' = ''
    }

    Try {
        $AbuseIPDB = Invoke-RestMethod -Method GET -Uri $URICheck -Header $Header -Body $BodyCheck -ContentType 'application/json; charset=utf-8' 

        Write-Host "Checking IP: $ip, Abuse Confidence Score: $($AbuseIPDB.data.abuseConfidenceScore)"

        # Check the abuse confidence score --> by default, only IP's and domains with a confidence greater than 50% will be included in the list
        if ($AbuseIPDB.data.abuseConfidenceScore -gt 50) {
            $maliciousIps += $ip
            Write-Host "IP: $ip added to malicious list (Score: $($AbuseIPDB.data.abuseConfidenceScore))" -ForegroundColor Red
        } else {
            Write-Host "IP: $ip is safe (Score: $($AbuseIPDB.data.abuseConfidenceScore))" -ForegroundColor Green
        }
    } Catch {
        Write-Host "Error checking IP: $ip. Error: $_" -ForegroundColor Yellow
    }
}

# Malicious IP out
$maliciousIps | Out-File -FilePath "malicious_ips.txt" -Encoding ASCII

# Malicious domain out
$domains | Out-File -FilePath "domains.txt" -Encoding ASCII
