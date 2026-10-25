# ============================================================
#  Sentinel AI — GitHub Push Script
#  Repository: https://github.com/Sandeep879030/sentinel-ai
# ============================================================

$GIT   = "C:\Users\ADMIN\AppData\Local\Programs\Git\cmd\git.exe"
$REPO  = "C:\Users\ADMIN\.gemini\antigravity\scratch\sentinel-ai"
$REMOTE = "https://github.com/Sandeep879030/sentinel-ai.git"

Set-Location $REPO

Write-Host "`n[1/9] Initialising Git repository..." -ForegroundColor Cyan
& $GIT init
if ($LASTEXITCODE -ne 0) { Write-Error "git init failed"; exit 1 }

Write-Host "`n[2/9] Setting commit author..." -ForegroundColor Cyan
& $GIT config user.name  "Sandeep879030"
& $GIT config user.email "sandeep879030@users.noreply.github.com"

Write-Host "`n[3/9] Adding remote origin..." -ForegroundColor Cyan
$existing = & $GIT remote 2>&1
if ($existing -match "origin") {
    Write-Host "  Remote 'origin' already exists — updating URL." -ForegroundColor Yellow
    & $GIT remote set-url origin $REMOTE
} else {
    & $GIT remote add origin $REMOTE
}

Write-Host "`n[4/9] Fetching remote history (README commit)..." -ForegroundColor Cyan
& $GIT fetch origin
if ($LASTEXITCODE -ne 0) {
    Write-Warning "  Fetch failed. This may be a network issue or the branch does not exist yet."
    Write-Warning "  Continuing — will push as first commit if remote is empty."
}

Write-Host "`n[5/9] Checking out / creating 'main' branch..." -ForegroundColor Cyan
$branches = & $GIT branch -a 2>&1
if ($branches -match "remotes/origin/main") {
    Write-Host "  Remote 'main' branch found — creating local tracking branch." -ForegroundColor Green
    & $GIT checkout -b main --track origin/main 2>&1
    if ($LASTEXITCODE -ne 0) {
        # branch might already exist locally
        & $GIT checkout main
    }
    Write-Host "`n[5b] Merging remote README (--allow-unrelated-histories)..." -ForegroundColor Cyan
    & $GIT merge origin/main --allow-unrelated-histories -m "Merge remote README before adding project files"
    if ($LASTEXITCODE -ne 0) { Write-Error "Merge failed. Resolve conflicts manually."; exit 1 }
} elseif ($branches -match "remotes/origin/master") {
    Write-Host "  Remote 'master' branch found — creating local 'main' branch from it." -ForegroundColor Yellow
    & $GIT checkout -b main --track origin/master 2>&1
    if ($LASTEXITCODE -ne 0) { & $GIT checkout main }
    & $GIT merge origin/master --allow-unrelated-histories -m "Merge remote README before adding project files"
    if ($LASTEXITCODE -ne 0) { Write-Error "Merge failed."; exit 1 }
} else {
    Write-Host "  No remote branch found — initialising fresh 'main' branch." -ForegroundColor Yellow
    & $GIT checkout -b main
}

Write-Host "`n[6/9] Staging all project files..." -ForegroundColor Cyan
& $GIT add .
& $GIT status --short

Write-Host "`n[7/9] Committing..." -ForegroundColor Cyan
& $GIT commit -m "Upgrade Sentinel AI cybersecurity website" --allow-empty
if ($LASTEXITCODE -ne 0) { Write-Warning "Nothing to commit or commit failed."; }

Write-Host "`n[8/9] Pushing to GitHub..." -ForegroundColor Cyan
Write-Host "  >> GitHub will prompt for your username and Personal Access Token." -ForegroundColor Yellow
Write-Host "  >> Enter your GitHub username: Sandeep879030" -ForegroundColor Yellow
Write-Host "  >> Enter your PAT (token) as the password. It will NOT display as you type." -ForegroundColor Yellow
& $GIT push -u origin main
if ($LASTEXITCODE -ne 0) {
    Write-Error "Push failed. See message above. Do NOT use --force without understanding the error."
    exit 1
}

Write-Host "`n[9/9] SUCCESS! Your code is now on GitHub." -ForegroundColor Green
Write-Host "  Repository : https://github.com/Sandeep879030/sentinel-ai" -ForegroundColor Green
Write-Host "  Live site  : https://sandeep879030.github.io/sentinel-ai/ (after enabling GitHub Pages)" -ForegroundColor Green
