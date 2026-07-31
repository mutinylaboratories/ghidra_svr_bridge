# gen-ui-stub-def.ps1 — (re)generate plugin/cmake/binaryninjaui_stub.def
#
# The Windows CI build has no Binary Ninja install, so it cannot link against
# the real binaryninjaui.lib. Instead it builds a stub import library from a
# .def file listing exactly the UI symbols the plugin references. This script
# derives that list from the linker itself: it configures a stub-mode build
# (-DBN_FORCE_STUB_LINK=ON), lets the link fail, harvests the "unresolved
# external symbol" names, appends them to the .def, and repeats until the
# link succeeds.
#
# Run from a VS x64 developer shell (needs cl/link/lib and cmake on PATH):
#   powershell -File plugin\tools\gen-ui-stub-def.ps1
#
# Re-run whenever the plugin starts using new binaryninjaui symbols (the CI
# Windows link failing with LNK2019 on ?...@UIContext@@-style names is the
# tell). Pass -GhidraHome to avoid the configure-time Ghidra download.
param(
    [string]$GhidraHome = 'C:/ghidra_12.0.4_PUBLIC',
    [string]$BuildDir   = ''
)
$ErrorActionPreference = 'Stop'

$pluginDir = (Resolve-Path "$PSScriptRoot\..").Path
if (-not $BuildDir) { $BuildDir = Join-Path $pluginDir 'build-stub' }
$defPath = Join-Path $pluginDir 'cmake\binaryninjaui_stub.def'

# Start from an empty export list so stale symbols get pruned.
Set-Content -Path $defPath -Value "LIBRARY binaryninjaui`r`nEXPORTS"

cmake -B $BuildDir -S $pluginDir `
    -DBN_FORCE_STUB_LINK=ON `
    -DCMAKE_BUILD_TYPE=Release `
    -DGHIDRA_HOME="$GhidraHome"
if ($LASTEXITCODE -ne 0) { throw 'configure failed' }

$symbols = New-Object System.Collections.Generic.SortedSet[string]

for ($pass = 1; $pass -le 12; $pass++) {
    Write-Host "--- link pass $pass ($($symbols.Count) symbols so far) ---"
    $out = cmake --build $BuildDir --target binja-ghidra --config Release 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Link succeeded. $($symbols.Count) UI symbols written to $defPath"
        exit 0
    }

    # LNK2019/LNK2001 report the mangled name in parentheses right after
    # "unresolved external symbol"; take only that one (the same line may
    # also carry the mangled CALLER after "referenced in function", which
    # must not be harvested). A dllimport reference carries an __imp_
    # prefix that must NOT appear in the .def.
    #
    # Symbols OWNED by a Qt class (mangled owner right after the name, e.g.
    # ?staticMetaObject@QTimer@@…) must NOT go in the def: the real
    # binaryninjaui.dll does not export them (they resolve from the Qt
    # import libraries on a clean link). The owner check is anchored and
    # case-sensitive — UI symbols like ?qt_metacall@SidebarWidget@@…
    # mention Qt types only in their ARGUMENT lists and belong in the def.
    $found = 0
    foreach ($line in ($out -split "`r?`n")) {
        if ($line -notmatch 'unresolved external symbol') { continue }
        $m = [regex]::Match($line, 'unresolved external symbol.*?\((?:__imp_)?(\?[^)\s]+)\)')
        if (-not $m.Success) { continue }
        $sym = $m.Groups[1].Value
        if ($sym -cmatch '^\?\w+@Q[A-Z][A-Za-z0-9_]*@@') { continue }
        if ($symbols.Add($sym)) { $found++ }
    }
    if ($found -eq 0) {
        Write-Host $out
        throw 'link failed but no new unresolved UI symbols were found — see output above'
    }
    Write-Host "harvested $found new unresolved symbols"

    $lines = @('LIBRARY binaryninjaui', 'EXPORTS')
    foreach ($s in $symbols) {
        # Mangled data symbols (static members / globals) encode a digit right
        # after the '@@' terminator and need the DATA keyword in a .def.
        if ($s -match '@@\d') { $lines += "    $s DATA" }
        else                  { $lines += "    $s" }
    }
    Set-Content -Path $defPath -Value ($lines -join "`r`n")
}
throw 'did not converge after 12 passes'
