# Comprehensive DOM and Integration Test Runner for Sentinel AI v2.5 Enterprise
$edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$htmlPath = "file:///C:/Users/ADMIN/.gemini/antigravity/scratch/sentinel-ai/index.html"
$dumpFile = "C:\Users\ADMIN\.gemini\antigravity\scratch\sentinel-ai\dom_dump.txt"

Write-Host "Executing Headless Edge DOM rendering check..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $edgePath -ArgumentList "--headless", "--dump-dom", $htmlPath -NoNewWindow -PassThru -RedirectStandardOutput $dumpFile
$proc.WaitForExit(8000)

if (Test-Path $dumpFile) {
    $content = Get-Content $dumpFile -Raw
    Write-Host "Rendered DOM size: $($content.Length) bytes"

    $checks = @(
        @{ Name = "Page Title & Brand"; Pattern = 'SENTINEL <span class="gold">AI</span>' },
        @{ Name = "Status Pill Active"; Pattern = 'ENGINE v2.5 ACTIVE' },
        @{ Name = "Trust DNA Radar Canvas"; Pattern = '<canvas id="radarChartCanvas"' },
        @{ Name = "Interactive Simulator Headings"; Pattern = 'Deconstruct Real-World Attack Tradecraft' },
        @{ Name = "Spot the Phish Quiz (Q1)"; Pattern = 'Question 1 of 5' },
        @{ Name = "Rules Accordion Category"; Pattern = 'Urgency &amp; Psychological Coercion' },
        @{ Name = "Rule 1 (Artificial Time Constraint)"; Pattern = 'Artificial Time Constraint' },
        @{ Name = "Rule 2 (One-Time Password)"; Pattern = 'One-Time Password (OTP)' },
        @{ Name = "Rule 3 (Untraceable Payment Demand)"; Pattern = 'Non-Standard / Untraceable Payment Demand' },
        @{ Name = "Client-Side Privacy Assurance"; Pattern = 'Client-Side Execution:' }
    )

    $allPassed = $true
    foreach ($check in $checks) {
        if ($content -match [regex]::Escape($check.Pattern)) {
            Write-Host "[PASS] $($check.Name)" -ForegroundColor Green
        } else {
            Write-Host "[FAIL] $($check.Name) (Pattern: $($check.Pattern))" -ForegroundColor Red
            $allPassed = $false
        }
    }

    if ($allPassed) {
        Write-Host "`n>>> ALL 10 DOM INTEGRATION CHECKS PASSED SUCCESSFULLY! <<<`n" -ForegroundColor Green
    } else {
        Write-Host "`n>>> SOME CHECKS FAILED! <<<`n" -ForegroundColor Red
    }
} else {
    Write-Host "DOM dump file not found." -ForegroundColor Red
}
