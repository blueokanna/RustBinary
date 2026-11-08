[CmdletBinding()]
param(
    [ValidateSet('decode_arbitrary_bytes', 'decode_compact_arbitrary', 'decode_structured_roundtrip', 'decode_cbor_arbitrary', 'decode_frames_arbitrary')]
    [string[]]$Targets = @('decode_arbitrary_bytes', 'decode_compact_arbitrary', 'decode_structured_roundtrip', 'decode_cbor_arbitrary', 'decode_frames_arbitrary'),
    [ValidateRange(1, 86400)][int]$Seconds = 120,
    [ValidateRange(1, 2147483647)][int]$Seed = 101,
    [ValidateRange(1, 1048576)][int]$MaxLength = 8192
)

$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$originalPath = $env:PATH
$results = @()
Push-Location $workspace
try {
    $localTools = Join-Path $workspace 'target/fuzz-tools/bin'
    $env:PATH = "$localTools;$env:PATH"
    if (-not (Get-Command cargo-fuzz -ErrorAction SilentlyContinue)) {
        throw 'Install cargo-fuzz: cargo install cargo-fuzz --locked --root target/fuzz-tools'
    }

    if ($env:OS -eq 'Windows_NT') {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio C++ Build Tools are required.' }
        $installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if (-not $installation) { throw 'No Visual Studio installation with x64 C++ tools was found.' }
        $toolsets = Get-ChildItem -LiteralPath (Join-Path $installation 'VC\Tools\MSVC') -Directory |
            Sort-Object { [version]$_.Name } -Descending
        $msvcBin = $null
        foreach ($toolset in $toolsets) {
            $candidate = Join-Path $toolset.FullName 'bin\Hostx64\x64'
            if (Test-Path -LiteralPath (Join-Path $candidate 'clang_rt.asan_dynamic-x86_64.dll')) {
                $msvcBin = $candidate
                break
            }
        }
        if (-not $msvcBin) { throw 'Install the C++ AddressSanitizer component in Visual Studio Installer.' }
        $env:PATH = "$msvcBin;$env:PATH"
    }

    $rustVersion = & rustup run nightly rustc --version
    if ($LASTEXITCODE -ne 0) { throw 'Install nightly: rustup toolchain install nightly --profile minimal' }
    $fuzzVersion = & cargo fuzz --version
    if ($LASTEXITCODE -ne 0) { throw 'cargo-fuzz could not start.' }
    $outputDirectory = Join-Path $workspace ('target/fuzz-results/' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

    foreach ($target in $Targets) {
        $log = Join-Path $outputDirectory "$target.log"
        Write-Host "Fuzzing $target ($Seconds seconds, seed $Seed)"
        $ErrorActionPreference = 'Continue'
        & cargo +nightly fuzz run $target --sanitizer address -- "-max_total_time=$Seconds" "-max_len=$MaxLength" "-seed=$Seed" *> $log
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        $summary = @(Select-String -LiteralPath $log -Pattern '^Done .* runs in .*second', 'DONE.*cov:' | ForEach-Object { $_.Line })
        $results += [ordered]@{ target = $target; exitCode = $code; seconds = $Seconds; seed = $Seed; maxLength = $MaxLength; summary = $summary; log = $log }
        [ordered]@{ rust = $rustVersion; cargoFuzz = $fuzzVersion; sanitizer = 'address'; results = $results } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outputDirectory 'report.json') -Encoding UTF8
        if ($code -ne 0) { throw "Fuzzing failed for $target. See $log and fuzz/artifacts/$target." }
        if (-not $summary) { throw "No completed libFuzzer run found in $log." }
        Write-Host ($summary -join [Environment]::NewLine)
    }
    Write-Host "Report: $outputDirectory\report.json"
}
finally {
    $env:PATH = $originalPath
    Pop-Location
}
