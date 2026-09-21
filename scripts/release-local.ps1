param(
    [switch]$SkipBuild,
    [switch]$SkipPackage,
    [string]$Tag = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

$PyScript = Join-Path $ScriptDir "release_local.py"

$ArgsList = @()
if ($SkipBuild) { $ArgsList += "--skip-build" }
if ($SkipPackage) { $ArgsList += "--skip-package" }
if ($Tag -ne "") { $ArgsList += "--tag", $Tag }

python $PyScript @ArgsList
