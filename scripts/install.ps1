# Sindarin native library installer for Windows
# Downloads versioned binaries from S3 to ./libs/windows
# Name and version are read from sn.yaml in the package root
# Caches archives in ~/.sn-cache/downloads/ to avoid re-downloading

$ErrorActionPreference = "Stop"

$S3_BUCKET = "cryosharp-sindarin-pkg-binaries"
$S3_REGION = "eu-west-2"
$INSTALL_DIR = Join-Path (Get-Location) "libs\windows"

function Write-Status {
    param(
        [string]$Message,
        [string]$Type = "Info"
    )

    $color = switch ($Type) {
        "Info"    { "Cyan" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        default   { "White" }
    }

    Write-Host $Message -ForegroundColor $color
}

function Get-Architecture {
    if ($env:SN_LIBS_ARCH) {
        return $env:SN_LIBS_ARCH
    }

    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64"   { return "x64" }
        "Arm64" { return "arm64" }
        default { throw "Unsupported architecture: $arch" }
    }
}

function Read-YamlField {
    param([string]$Field)

    $yamlPath = Join-Path (Get-Location) "sn.yaml"
    if (-not (Test-Path $yamlPath)) {
        Write-Status "sn.yaml not found" -Type "Error"
        exit 1
    }

    $line = Get-Content $yamlPath | Where-Object { $_ -match "^${Field}:\s*(.+)$" } | Select-Object -First 1
    if (-not $line) {
        Write-Status "Failed to read '$Field' from sn.yaml" -Type "Error"
        exit 1
    }

    return ($line -replace "^${Field}:\s*", "").Trim()
}

function Install-SindarinLibs {
    param(
        [string]$PkgName,
        [string]$Version,
        [string]$Arch
    )

    $archiveName = "$PkgName-v$Version-windows-$Arch.zip"
    $downloadUrl = "https://$S3_BUCKET.s3.$S3_REGION.amazonaws.com/$PkgName/v$Version/$archiveName"

    $cacheDir = Join-Path (Join-Path $env:USERPROFILE ".sn-cache") "downloads"
    $cachedZip = Join-Path $cacheDir $archiveName

    if (Test-Path $cachedZip) {
        Write-Status "Using cached $archiveName"
    }
    else {
        Write-Status "Downloading $PkgName v$Version for windows-$Arch..."

        if (-not (Test-Path $cacheDir)) {
            New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
        }

        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $cachedZip -UseBasicParsing
        }
        catch {
            Write-Status "Download failed: $_" -Type "Error"
            if (Test-Path $cachedZip) {
                Remove-Item -Force $cachedZip -ErrorAction SilentlyContinue
            }
            exit 1
        }
    }

    $tempDir = Join-Path $env:TEMP "$PkgName-install"

    if (Test-Path $tempDir) {
        Remove-Item -Recurse -Force $tempDir
    }
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    try {
        Write-Status "Extracting to $INSTALL_DIR..."

        if (Test-Path $INSTALL_DIR) {
            Remove-Item -Recurse -Force $INSTALL_DIR
        }
        New-Item -ItemType Directory -Path $INSTALL_DIR | Out-Null

        $extractDir = Join-Path $tempDir "extracted"
        Expand-Archive -Path $cachedZip -DestinationPath $extractDir -Force

        $contents = Get-ChildItem -Path $extractDir
        if ($contents.Count -eq 1 -and $contents[0].PSIsContainer) {
            $innerDir = $contents[0].FullName
            Get-ChildItem -Path $innerDir | Move-Item -Destination $INSTALL_DIR
        }
        else {
            Get-ChildItem -Path $extractDir | Move-Item -Destination $INSTALL_DIR
        }

        Write-Status "Successfully installed $PkgName v$Version to $INSTALL_DIR" -Type "Success"
    }
    catch {
        Write-Status "Installation failed: $_" -Type "Error"
        exit 1
    }
    finally {
        if (Test-Path $tempDir) {
            Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
        }
    }
}

$pkgName = Read-YamlField -Field "name"
$version = Read-YamlField -Field "version"

Write-Status "$pkgName - native library installer" -Type "Info"
Write-Status "========================================" -Type "Info"

$arch = Get-Architecture
Write-Status "Detected: windows ($arch)" -Type "Info"
Write-Status "Package version: v$version" -Type "Info"

Install-SindarinLibs -PkgName $pkgName -Version $version -Arch $arch

Write-Status ""
Write-Status "Installation complete!" -Type "Success"
