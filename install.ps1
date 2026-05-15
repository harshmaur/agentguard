# Audr install script for Windows.
#
# Usage (PowerShell):
#   iwr https://raw.githubusercontent.com/harshmaur/audr/main/install.ps1 -UseBasicParsing | iex
#   iwr https://raw.githubusercontent.com/harshmaur/audr/main/install.ps1 -UseBasicParsing | iex
#   # or with a pinned version:
#   $env:AUDR_VERSION="v0.6.0"; iwr https://raw.githubusercontent.com/harshmaur/audr/main/install.ps1 -UseBasicParsing | iex
#
# Steps:
#   1. Detect architecture (amd64 / arm64).
#   2. Resolve target version (latest from GitHub Releases unless pinned).
#   3. Download the matching release ZIP from GitHub Releases.
#   4. Verify the SHA-256 against the published SHA256SUMS file.
#   5. Extract audr.exe to %LOCALAPPDATA%\audr\ and add it to user PATH.
#   6. Unblock the binary (removes the Zone.Identifier ADS that triggers
#      SmartScreen on first run).
#
# After install you can re-verify any downloaded ZIP with
# `audr verify <zip>`, and confirm what is compiled into the binary on
# a given machine with `audr self-audit`.
#
# About the SmartScreen warning on first run
# -------------------------------------------
# v1.1 Windows binaries are not Authenticode-signed. The first time you
# run audr.exe Windows may show "Windows protected your PC — unknown
# publisher". This installer Unblock-Files the binary so SmartScreen
# treats it as locally-trusted on subsequent runs, but you may still
# need to click "More info → Run anyway" on the very first launch.
#
# The trust anchor is the cosign-signed SHA-256 hash this installer
# verifies against the published SHA256SUMS file — not an Authenticode
# certificate. Verify the hash; the binary is what it claims to be.
#
# An Authenticode-signed Windows build is on the roadmap (TODOS.md
# TODO 5). It depends on design-partner demand justifying the EV cert
# spend.

$ErrorActionPreference = "Stop"

# --- config knobs ---
$Repo        = "harshmaur/audr"
$InstallDir  = if ($env:AUDR_INSTALL_DIR) { $env:AUDR_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "audr" }
$Version     = if ($env:AUDR_VERSION)     { $env:AUDR_VERSION }     else { "latest" }

# --- detect architecture ---
# $env:PROCESSOR_ARCHITECTURE is set in every Windows shell. AMD64 is
# the modern x64 value; ARM64 is the Windows-on-ARM machines (Snapdragon
# X, Surface Pro X). x86 (32-bit) is unsupported.
switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { $arch = "amd64" }
    "ARM64" { $arch = "arm64" }
    default {
        Write-Error "audr: unsupported architecture '$($env:PROCESSOR_ARCHITECTURE)'. amd64 and arm64 are supported."
        exit 1
    }
}

# --- resolve version ---
# Hit the GitHub Releases API only when a specific version isn't pinned.
# Anonymous calls are rate-limited but a single resolve is well within
# the budget — no auth-token plumbing needed in v1.1.
if ($Version -eq "latest") {
    Write-Host "audr: resolving latest version..."
    try {
        $latest = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        $Version = $latest.tag_name
    } catch {
        Write-Error "audr: failed to resolve latest version. If you're rate-limited, pin a specific version with `$env:AUDR_VERSION=v0.6.0` and retry."
        exit 1
    }
}

$artifact   = "audr-$Version-windows-$arch.zip"
$base       = "https://github.com/$Repo/releases/download/$Version"
$tmp        = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "audr-install-$(Get-Random)")

try {
    Write-Host "audr: installing $Version for windows/$arch..."

    # --- download ZIP + checksums file ---
    # The release pipeline emits a ZIP per platform plus a single
    # SHA256SUMS file covering every artifact in that release.
    $artifactPath = Join-Path $tmp $artifact
    $sumsPath     = Join-Path $tmp "SHA256SUMS"

    Write-Host "audr: downloading $artifact..."
    Invoke-WebRequest "$base/$artifact"     -UseBasicParsing -OutFile $artifactPath
    Invoke-WebRequest "$base/SHA256SUMS"    -UseBasicParsing -OutFile $sumsPath

    # --- SHA-256 verify ---
    # This IS the trust anchor for the Windows install path. We don't
    # have Authenticode in v1.1, so the published SHA256SUMS — which
    # IS cosign-signed at release time — is what gates the install.
    Write-Host "audr: verifying SHA-256..."
    $actual = (Get-FileHash -Algorithm SHA256 $artifactPath).Hash.ToLower()

    # Read SHA256SUMS, find the line ending in our artifact name. The
    # file format mirrors `shasum -a 256` output:
    #   <64-char-hex>  <filename>
    $expected = $null
    foreach ($line in Get-Content $sumsPath) {
        $parts = $line -split "\s+", 2
        if ($parts.Count -ne 2) { continue }
        if ($parts[1].Trim().TrimStart("*") -eq $artifact) {
            $expected = $parts[0].ToLower()
            break
        }
    }
    if (-not $expected) {
        Write-Error "audr: artifact $artifact not present in SHA256SUMS. The release may be incomplete — try a different version."
        exit 1
    }
    if ($actual -ne $expected) {
        Write-Error "audr: CHECKSUM MISMATCH (expected $expected, got $actual) — refusing to install. Either the download is corrupted or the artifact has been tampered with."
        exit 1
    }
    Write-Host "audr: SHA-256 OK"

    # --- extract ---
    # The Windows ZIP wraps the binary in a versioned directory
    # mirroring the tarball layout used by install.sh:
    #   audr-vX.Y.Z-windows-arch/audr.exe
    Write-Host "audr: extracting to $InstallDir..."
    Expand-Archive -Path $artifactPath -DestinationPath $tmp -Force

    $unwrapped = Join-Path $tmp "audr-$Version-windows-$arch"
    $binary    = Join-Path $unwrapped "audr.exe"
    if (-not (Test-Path $binary)) {
        Write-Error "audr: expected binary at $binary not found after extract. The release artifact layout may have changed."
        exit 1
    }

    # Ensure the install directory exists; create it idempotently.
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir | Out-Null
    }
    $target = Join-Path $InstallDir "audr.exe"

    # If audr is already running (daemon mode), the existing audr.exe
    # is in use and Copy-Item will fail with "the process cannot access
    # the file because it is being used by another process." Try a
    # quick `audr daemon stop` to release the lock; if that doesn't
    # work the user gets a clear error.
    if (Test-Path $target) {
        try {
            & $target daemon stop 2>$null | Out-Null
        } catch {
            # daemon stop failed — maybe daemon not installed. Continue
            # and let Copy-Item surface the real error if any.
        }
    }
    Copy-Item -Path $binary -Destination $target -Force

    # --- unblock (remove Zone.Identifier ADS) ---
    # Windows attaches a Zone.Identifier alternate-data-stream to any
    # file downloaded from the internet. SmartScreen reads it to
    # decide whether to warn on first launch. Unblock-File removes
    # the stream so subsequent launches don't re-prompt.
    #
    # Note: the FIRST launch may still hit SmartScreen because the
    # binary isn't Authenticode-signed. After "Run anyway" + Unblock-File,
    # subsequent runs are silent.
    Unblock-File -Path $target

    # --- add to user PATH ---
    # User-scope PATH so we don't require admin. Idempotent: only
    # append when not already present.
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$InstallDir*") {
        $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Host "audr: added $InstallDir to user PATH (open a new terminal to pick it up)"
    }

    # --- success message ---
    Write-Host ""
    Write-Host "audr: installed $Version → $target"
    Write-Host ""
    Write-Host "audr: about the SmartScreen warning on first run"
    Write-Host "      Windows may show 'Windows protected your PC' the first time you"
    Write-Host "      run audr.exe. Click 'More info' → 'Run anyway'. This warning is"
    Write-Host "      expected for v1.1's unsigned Windows builds and does not indicate"
    Write-Host "      a security issue. The SHA-256 you just verified is the trust"
    Write-Host "      anchor; the binary is what it claims to be."
    Write-Host ""
    Write-Host "audr: try it now (open a new terminal first so PATH picks up):"
    Write-Host "  audr scan `$env:USERPROFILE     # one-shot scan, writes HTML report"
    Write-Host ""
    Write-Host "audr: or run the always-on dashboard:"
    Write-Host "  audr daemon install            # register as a per-user Scheduled Task"
    Write-Host "  audr daemon start              # launch in the background"
    Write-Host "  audr open                      # opens the dashboard in your browser"
    Write-Host ""
    Write-Host "audr: full coverage needs the OSV-Scanner sidecar (optional):"
    Write-Host "  audr update-scanners --yes     # installs osv-scanner for dep CVEs"
    Write-Host "  audr doctor                    # check current scanner status"
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
