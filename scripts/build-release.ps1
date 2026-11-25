[CmdletBinding()]
param([switch]$SkipUiSmoke)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root
$version = ([xml](Get-Content -Raw -LiteralPath 'Guardian.App/Steam Mod Guardian.csproj')).Project.PropertyGroup.Version
$dist = Join-Path $root 'dist'
$name = "SteamModGuardian-$version-win-x64-portable"
$publish = Join-Path $dist $name
$zip = Join-Path $dist "$name.zip"
function Invoke-Dotnet { & dotnet @args; if ($LASTEXITCODE -ne 0) { throw "dotnet failed: $LASTEXITCODE" } }
function Smoke([string]$arg) {
    $p = Start-Process -FilePath (Join-Path $publish 'Steam Mod Guardian.exe') -ArgumentList $arg -PassThru
    if (-not $p.WaitForExit(60000)) { try { $p.Kill() } catch {}; throw "Smoke test timed out: $arg" }
    if ($p.ExitCode -ne 0) { throw "Smoke test failed: $arg ($($p.ExitCode))" }
}
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw 'Install .NET 8 SDK to build.' }
if ($env:OS -ne 'Windows_NT') { throw 'Run the release build on Windows.' }
New-Item -ItemType Directory -Force -Path $dist | Out-Null
if (Test-Path -LiteralPath $publish) { Remove-Item -LiteralPath $publish -Recurse -Force }
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
if (Test-Path -LiteralPath "$zip.sha256") { Remove-Item -LiteralPath "$zip.sha256" -Force }
Invoke-Dotnet run --project 'Guardian.Tests/Guardian.Tests.csproj' -c Release
Invoke-Dotnet publish 'Guardian.App/Steam Mod Guardian.csproj' -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:PublishTrimmed=false -p:DebugType=none -p:DebugSymbols=false -o $publish
foreach ($file in @('README.md','README.zh-CN.md','LICENSE','THIRD-PARTY-NOTICES.txt','diagnose.bat','SECURITY.md')) { Copy-Item -LiteralPath (Join-Path $root $file) -Destination $publish }
Copy-Item -LiteralPath (Join-Path $root 'rules') -Destination $publish -Recurse
$assetsDir = Join-Path $publish 'Guardian.App/Assets'; New-Item -ItemType Directory -Force -Path $assetsDir | Out-Null
Copy-Item -LiteralPath (Join-Path $root 'Guardian.App/Assets/AppIcon.png') -Destination $assetsDir
foreach ($file in @('CHANGELOG.md','CONTRIBUTING.md')) { Copy-Item -LiteralPath (Join-Path $root $file) -Destination $publish }
# Preserve SDK runtime notices and collect available NuGet package license files.
$licenseDir = Join-Path $publish 'licenses'; New-Item -ItemType Directory -Force -Path $licenseDir | Out-Null
$assets = Get-Content -LiteralPath 'Guardian.App/obj/project.assets.json' -Raw | ConvertFrom-Json
foreach ($lib in $assets.libraries.PSObject.Properties) {
    if ($lib.Value.type -ne 'package') { continue }
    foreach ($folder in $assets.packageFolders.PSObject.Properties.Name) {
        $package = Join-Path $folder $lib.Value.path
        if (-not (Test-Path -LiteralPath $package)) { continue }
        foreach ($notice in Get-ChildItem -LiteralPath $package -File | Where-Object { $_.Name -match '^(license|notice|third.?party)' }) {
            $prefix = $lib.Name -replace '[^a-zA-Z0-9._-]', '_'
            Copy-Item -LiteralPath $notice.FullName -Destination (Join-Path $licenseDir "$prefix-$($notice.Name)")
        }
        break
    }
}
Smoke '--smoke-test-runtime'
if (-not $SkipUiSmoke) { Smoke '--smoke-test-ui' } else { Write-Warning 'WPF smoke test skipped explicitly; validate on an interactive Windows desktop before release.' }
@('Steam Mod Guardian portable package',"Version: $version",'Extract the entire ZIP and run Steam Mod Guardian.exe. No installer or .NET runtime installation required.',"UI smoke test skipped: $SkipUiSmoke",'This is not an antivirus or sandbox. Read README and SECURITY.md.') | Set-Content -LiteralPath (Join-Path $publish 'START-HERE.txt') -Encoding UTF8
Compress-Archive -LiteralPath $publish -DestinationPath $zip -CompressionLevel Optimal
$sha = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$sha  $name.zip" | Set-Content -LiteralPath "$zip.sha256" -Encoding ascii
Write-Host "Portable ZIP: $zip"
Write-Host "SHA256: $sha"
