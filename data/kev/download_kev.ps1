# Download CISA KEV Catalog
# Run: .\data\kev\download_kev.ps1

Write-Host "📥 Downloading CISA KEV Catalog..." -ForegroundColor Cyan

$url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
$output = "data\kev\known_exploited_vulnerabilities.json"

try {
    Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing
    Write-Host "✅ KEV catalog downloaded successfully!" -ForegroundColor Green
    
    $fileSize = (Get-Item $output).Length
    $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
    Write-Host "📊 File size: $fileSizeMB MB" -ForegroundColor White
    
    # Show catalog info
    $json = Get-Content $output | ConvertFrom-Json
    Write-Host "📋 Catalog Version: $($json.catalogVersion)" -ForegroundColor White
    Write-Host "📋 KEV Count: $($json.count)" -ForegroundColor White
    Write-Host "📋 Released: $($json.dateReleased)" -ForegroundColor White
}
catch {
    Write-Host "❌ Download failed: $_" -ForegroundColor Red
    exit 1
}

