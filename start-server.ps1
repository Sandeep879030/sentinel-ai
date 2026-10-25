# ==============================================================================
# Sentinel AI — Local Web Server Launcher
# Uses native .NET / PowerShell HttpListener (No Node.js or Python required!)
# ==============================================================================

$port = 8080
$prefix = "http://localhost:$port/"
$folder = $PSScriptRoot

if (-not (Test-Path $folder)) {
    $folder = Get-Location
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)

try {
    $listener.Start()
} catch {
    Write-Host "Failed to bind to port $port. Trying port 8081..." -ForegroundColor Yellow
    $port = 8081
    $prefix = "http://localhost:$port/"
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($prefix)
    $listener.Start()
}

Write-Host "=================================================================" -ForegroundColor DarkYellow
Write-Host "   SENTINEL AI — DIGITAL TRUST INSPECTOR LOCAL SERVER ONLINE" -ForegroundColor Gold
Write-Host "=================================================================" -ForegroundColor DarkYellow
Write-Host "   Serving directory : $folder" -ForegroundColor Gray
Write-Host "   Local URL         : $prefix" -ForegroundColor Green
Write-Host "   Press Ctrl+C in this console to stop the server." -ForegroundColor Gray
Write-Host "=================================================================" -ForegroundColor DarkYellow

# Launch in default browser
Start-Process $prefix

while ($listener.IsListening) {
    try {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response

        $urlPath = $request.Url.LocalPath.TrimStart('/')
        if ([string]::IsNullOrWhiteSpace($urlPath)) {
            $urlPath = "index.html"
        }

        $filePath = Join-Path $folder $urlPath

        if (Test-Path $filePath -PathType Leaf) {
            $bytes = [System.IO.File]::ReadAllBytes($filePath)
            
            # Content-type mapping
            $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
            switch ($ext) {
                ".html" { $response.ContentType = "text/html; charset=utf-8" }
                ".css"  { $response.ContentType = "text/css; charset=utf-8" }
                ".js"   { $response.ContentType = "application/javascript; charset=utf-8" }
                ".json" { $response.ContentType = "application/json; charset=utf-8" }
                ".svg"  { $response.ContentType = "image/svg+xml" }
                ".png"  { $response.ContentType = "image/png" }
                ".jpg"  { $response.ContentType = "image/jpeg" }
                default { $response.ContentType = "application/octet-stream" }
            }

            $response.ContentLength64 = $bytes.Length
            $response.OutputStream.Write($bytes, 0, $bytes.Length)
        } else {
            $response.StatusCode = 404
            $errBytes = [System.Text.Encoding]::UTF8.GetBytes("404 - File Not Found")
            $response.OutputStream.Write($errBytes, 0, $errBytes.Length)
        }
        $response.Close()
    } catch {
        # Catch cancellation or socket abort on exit
        break
    }
}

$listener.Stop()
