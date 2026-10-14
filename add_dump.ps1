# Add one memory image to the dashboard: download, unpack, analyse, check, export, LLM report.
# Every step can be re-run safely: downloads resume, unpacked files and Volatility output are
# reused, and a failed step says why without throwing away the steps that worked.
#
# Run from the Triageguard folder (with or without the .venv activated):
#   .\add_dump.ps1 -Name linux -Title "Ubuntu 22.04 (13Cubed Linux)" -Os "Ubuntu 22.04, kernel 6.5.0-41" `
#       -Source "13Cubed Linux memory forensics challenge" -Order 6 `
#       -Url https://cdn.13cubed.com/downloads/linux_challenge.zip `
#       -SymbolsUrl https://files.iblue.team/279b6e00-851e/Ubuntu22.04.6.5.0-41-generic.json.zip
#   .\add_dump.ps1 -Name mydump -Title "My dump" -Image D:\dumps\mem.raw     (file already on disk)
#
# Files go to ..\data\<Name>\ ; results to results\dumps\<Name>\ (commit that folder).
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Title = "",
    [string]$Os = "",
    [string]$Source = "",
    [int]$Order = 99,
    [string]$Url = "",          # archive or image to download
    [string]$Image = "",        # image already on disk (skips download)
    [string]$SymbolsUrl = "",   # Linux only: zip with the kernel's ISF .json
    [string]$Pcap = "",
    [switch]$NoLlm,
    [switch]$Fresh              # ignore cached Volatility output (after a Volatility upgrade)
)
# native commands are checked through $LASTEXITCODE; "Stop" would turn their stderr output
# into errors in Windows PowerShell 5.1
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$steps = [ordered]@{}
function Step($n, $msg) { Write-Host "`n[$n] $msg" -ForegroundColor Cyan }
function Done($key, $status) { $steps[$key] = $status }
function Fail($msg) {
    Write-Host "STOPPED: $msg" -ForegroundColor Red
    Summary
    exit 1
}
function Summary {
    Write-Host "`nSummary" -ForegroundColor Cyan
    foreach ($k in $steps.Keys) { "  {0,-10} {1}" -f $k, $steps[$k] }
}
function FreeGB($path) {
    $root = [System.IO.Path]::GetPathRoot((Resolve-Path $path).Path)
    $d = [System.IO.DriveInfo]::new($root)
    [math]::Round($d.AvailableFreeSpace / 1GB, 1)
}

if ($Name -notmatch '^[a-z0-9_-]+$') { Fail "Name must be lower case letters, digits, - or _ (it becomes a folder name)" }
if (-not (Test-Path "pyproject.toml")) { Fail "run this from the Triageguard folder" }
$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
$dir = Join-Path ".." (Join-Path "data" $Name)
New-Item -ItemType Directory -Force $dir | Out-Null
if ($Fresh) { $env:TRIAGEGUARD_NO_CACHE = "1" }

Step 1 "Checks"
& $py -m triageguard update
& $py -c "import volatility3"
if ($LASTEXITCODE) { Fail "volatility3 is not installed in $py (double-click TriageGuard.bat once to set up the .venv)" }
$free = FreeGB $dir
Write-Host "free space: $free GB"
if ($free -lt 10 -and -not $Image) { Fail "less than 10 GB free; run ..\cleanup.ps1 or free some space first" }
if (-not $NoLlm -and -not (Test-Path ".env") -and -not $env:GROQ_API_KEY) { Write-Host "no .env with GROQ_API_KEY: the LLM report will be skipped" -ForegroundColor Yellow }
Done "checks" "ok"

Step 2 "Image"
if (-not $Image) {
    if (-not $Url) { Fail "give -Url (to download) or -Image (a file on disk)" }
    $file = Join-Path $dir ([System.IO.Path]::GetFileName(([uri]$Url).AbsolutePath))
    # curl.exe ships with Windows 10+; -C - resumes a broken download instead of starting over
    for ($i = 1; $i -le 3; $i++) {
        curl.exe -L --fail --retry 5 -C - -o $file $Url
        if (-not $LASTEXITCODE) { break }
        Write-Host "download attempt $i failed (curl exit $LASTEXITCODE)" -ForegroundColor Yellow
        Start-Sleep -Seconds (5 * $i)
    }
    if ($LASTEXITCODE) { Fail "could not download $Url (the site may be down or blocked on this network)" }
    if ($file -match '\.(zip|7z|tar|tgz|gz)$') {
        $unpacked = Join-Path $dir "unpacked"
        if (Get-ChildItem $unpacked -Recurse -File -ErrorAction SilentlyContinue) {
            Write-Host "already unpacked: $unpacked"
        } else {
            New-Item -ItemType Directory -Force $unpacked | Out-Null
            tar -xf $file -C $unpacked
            if ($LASTEXITCODE) { Remove-Item $unpacked -Recurse -Force; Fail "could not unpack $file (corrupt download? delete it and run again)" }
        }
        # the image is the largest file in the archive
        $Image = (Get-ChildItem $unpacked -Recurse -File | Sort-Object Length -Descending | Select-Object -First 1).FullName
    } else {
        $Image = $file
    }
}
if (-not (Test-Path $Image)) { Fail "image not found: $Image" }
$size = "{0:N1} GB" -f ((Get-Item $Image).Length / 1GB)
Write-Host "image: $Image ($size)"
Done "image" "ok ($size)"

if ($SymbolsUrl) {
    Step 3 "Linux symbols"
    $zip = Join-Path $dir "symbols.zip"
    curl.exe -L --fail --retry 5 -C - -o $zip $SymbolsUrl
    if ($LASTEXITCODE) { Fail "could not download the symbol file $SymbolsUrl" }
    New-Item -ItemType Directory -Force "symbols\linux" | Out-Null
    tar -xf $zip -C "symbols\linux"
    if ($LASTEXITCODE) { Fail "could not unpack $zip" }
    Done "symbols" "ok"
}

Step 4 "Analysis (Volatility output is cached, so a second run is much faster)"
$db = Join-Path $dir "$Name.db"
Remove-Item $db -ErrorAction SilentlyContinue
$analyseArgs = @("-m", "triageguard", "analyze", $Image, "--db", $db, "--out", (Join-Path $dir "out"), "--no-llm")
if ($Pcap) { $analyseArgs += @("--pcap", $Pcap) }
& $py @analyseArgs
if ($LASTEXITCODE) { Fail "analysis crashed (see the error above); nothing was exported" }
Done "analysis" "ok"

Step 5 "Sanity check"
& $py -m triageguard check $db
if ($LASTEXITCODE) {
    Done "check" "FAILED"
    Fail "the result is unusable (see ERROR above), so it was not exported. For Linux, pass -SymbolsUrl with the kernel's ISF"
}
Done "check" "ok (read any WARN lines above)"

Step 6 "Export to the dashboard"
# Windows PowerShell drops empty arguments, so only pass the options that have a value
$exportArgs = @("-m", "triageguard", "export", $db, $Name, "--size", $size, "--order", $Order, "--clean")
foreach ($o in @(@("--title", $Title), @("--os", $Os), @("--source", $Source), @("--pcap", $Pcap))) {
    if ($o[1]) { $exportArgs += $o }
}
& $py @exportArgs
if ($LASTEXITCODE) { Fail "export failed" }
Done "export" "ok -> results\dumps\$Name"

if (-not $NoLlm) {
    Step 7 "LLM report"
    & $py -m triageguard report $db --out "results\dumps\$Name\report_llm.md"
    if ($LASTEXITCODE) { Done "llm" "skipped (no key, or the API refused; the rule report is on the dashboard). Retry later: $py -m triageguard report $db --out results\dumps\$Name\report_llm.md" }
    else { Done "llm" "ok" }
}

Summary
Write-Host "`nCommit with: git add results\dumps\$Name; git commit -m 'Add $Name dump'; git push" -ForegroundColor Green
