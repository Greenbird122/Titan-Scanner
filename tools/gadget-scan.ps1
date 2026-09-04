# Titan Gadget Scanner - Find prototype pollution gadgets in JavaScript files
# Usage: .\gadget-scan.ps1 -Target "https://example.com" -JavaScript "script1.js,script2.js"

param(
    [Parameter(Mandatory=$true)]
    [string]$Target,
    
    [Parameter(Mandatory=$true)]
    [string]$JavaScript,
    
    [switch]$Verbose
)

Write-Host "=== Titan Gadget Scanner ===" -ForegroundColor Cyan
Write-Host "Target: $Target" -ForegroundColor Yellow

# Known gadget patterns
$gadgetPatterns = @(
    # innerHTML gadgets
    @{Pattern="innerHTML\s*=\s*\w+\.(\w+)"; Sink="innerHTML"; Type="DOM"},
    @{Pattern="\.html\s*\(\s*\w+\.(\w+)\s*\)"; Sink="jQuery.html"; Type="DOM"},
    
    # script src gadgets
    @{Pattern="createElement\s*\(\s*['"]script['"]\s*\).*?\.src\s*=\s*\w+\.(\w+)"; Sink="script.src"; Type="Script"},
    @{Pattern="\.src\s*=\s*\w+\.(\w+)"; Sink="element.src"; Type="Script"},
    
    # eval gadgets
    @{Pattern="eval\s*\(\s*\w+\.(\w+)\s*\)"; Sink="eval"; Type="Code"},
    @{Pattern="new\s+Function\s*\(\s*\w+\.(\w+)\s*\)"; Sink="Function"; Type="Code"},
    
    # document.write gadgets
    @{Pattern="document\.write\s*\(\s*\w+\.(\w+)\s*\)"; Sink="document.write"; Type="DOM"},
    
    # setAttribute gadgets
    @{Pattern="setAttribute\s*\(\s*\w+\.(\w+)"; Sink="setAttribute"; Type="DOM"},
    
    # Template engine gadgets
    @{Pattern="config\.(\w+)"; Sink="config"; Type="Template"},
    @{Pattern="options\.(\w+)"; Sink="options"; Type="Template"},
    @{Pattern="settings\.(\w+)"; Sink="settings"; Type="Template"},
    
    # URL/Redirect gadgets
    @{Pattern="location\s*=\s*\w+\.(\w+)"; Sink="location"; Type="Redirect"},
    @{Pattern="window\.open\s*\(\s*\w+\.(\w+)\s*\)"; Sink="window.open"; Type="Redirect"},
    
    # Cookie gadgets
    @{Pattern="document\.cookie\s*=\s*\w+\.(\w+)"; Sink="document.cookie"; Type="Cookie"}
)

# Parse JavaScript files
$jsFiles = $JavaScript -split ","

foreach ($jsFile in $jsFiles) {
    Write-Host "`nScanning: $jsFile" -ForegroundColor Green
    
    try {
        $jsUrl = if ($jsFile -match "^http") { $jsFile } else { "$Target/$jsFile" }
        $jsContent = Invoke-WebRequest -Uri $jsUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        
        foreach ($gadget in $gadgetPatterns) {
            $matches = [regex]::Matches($jsContent.Content, $gadget.Pattern)
            
            if ($matches.Count -gt 0) {
                Write-Host "  [!] Found $($matches.Count) potential $($gadget.Type) gadget(s) for sink: $($gadget.Sink)" -ForegroundColor Red
                
                foreach ($match in $matches) {
                    $propertyName = $match.Groups[1].Value
                    Write-Host "    - Property: $propertyName (Line: $($match.Index))" -ForegroundColor Yellow
                    
                    if ($Verbose) {
                        $context = $jsContent.Content.Substring([Math]::Max(0, $match.Index - 50), [Math]::Min(150, $jsContent.Content.Length - [Math]::Max(0, $match.Index - 50)))
                        Write-Host "    Context: $context" -ForegroundColor DarkGray
                    }
                }
            }
        }
    } catch {
        Write-Host "  Error scanning $jsFile`: $_" -ForegroundColor Red
    }
}

# Known vulnerable library versions
$vulnerableLibs = @(
    @{Name="jQuery"; Versions="< 3.4.0"; CVE="CVE-2019-11358"; Gadget="$.extend"},
    @{Name="Lodash"; Versions="< 4.17.21"; CVE="CVE-2019-10744"; Gadget="_.merge"},
    @{Name="DOMPurify"; Versions="3.0.1 - 3.3.3"; CVE="CVE-2026-41238"; Gadget="CUSTOM_ELEMENT_HANDLING"},
    @{Name="Hoek"; Versions="< 5.0.3"; CVE="CVE-2018-3728"; Gadget="merge"},
    @{Name="Minimist"; Versions="< 1.2.6"; CVE="CVE-2020-7598"; Gadget="parse args"},
    @{Name="qs"; Versions="< 6.9.7"; CVE="CVE-2022-24999"; Gadget="parse"},
    @{Name="Object-path"; Versions="< 0.11.5"; CVE="CVE-2020-15256"; Gadget="set/get"}
)

Write-Host "`n=== Known Vulnerable Libraries ===" -ForegroundColor Cyan
foreach ($lib in $vulnerableLibs) {
    Write-Host "$($lib.Name) $($lib.Versions) - $($lib.CVE) - Gadget: $($lib.Gadget)" -ForegroundColor Yellow
}

Write-Host "`n=== Scan Complete ===" -ForegroundColor Cyan
