param(
    [string]$Directory = (Join-Path (Split-Path $PSScriptRoot -Parent) "third_party"),
    [string]$Output = (Join-Path (Split-Path $PSScriptRoot -Parent) "logs\third-party-verify.json")
)

$ErrorActionPreference = "Stop"

$expected = @{
    "ghidra_12.2_PUBLIC_20261016.zip" = "2C2CD776DB3C1F6A097BA418922378AC3649CADD5E844A6F5F088AE628A7BE67"
    "jadx-1.5.6.zip" = "545EA2BE9C242511BC145755CF4BDA2485ADE42966E096F8B4D3DA2A230E8974"
    "nuclei_3.11.1_linux_amd64.zip" = "EA63D4AE232808CD7C6BC00D0142428E231FAB59DAE01042246097D195835AB6"
    "httpx_1.12.0_linux_amd64.zip" = "9D8439E8B6C9AA7D1E2314817A392E00D5178DA3AF5652F7475F88868F418F76"
    "katana_1.8.0_linux_amd64.zip" = "CB027AE99D0757061B70C07A15C7A80F62C5A535AB52C4A329F80C4B0A7309D2"
    "x86_64-linux-feroxbuster.tar.gz" = "3AB2CEFDB03AF090BCF11C4B82BD85A7E8A2B4439237AC06993568EADE28EE96"
    "chisel_1.12.0_linux_amd64.gz" = "F3F180F1D93AA72CCE4E6386F98CC06569A0146FBD65EB4423CF83E6434BCFE6"
    "ligolo-ng_agent_0.9.2_linux_amd64.tar.gz" = "714534917A4A58812669619667CC57DFAD03D34D0DE5B0D7C468D76819F84111"
    "ligolo-ng_proxy_0.9.2_linux_amd64.tar.gz" = "6C683C403502D366276595197749E620C975908DAE7314C21079EC8EBEE4E5D0"
    "gef-809864d00442f9993298e33fd9cd282d687d2f45.zip" = "6B7E8580609C9CDCF5362452A16FB0376FA633FA214DFBC53DD6A0E857412040"
    "pwndbg-9760ac8f1346d142857cffc933995cd6fca34dff.zip" = "2FB79F3810EE80A4DE45CB486D887B6731A39A088663E294D5CB9D05D1161ED3"
}

$items = @()
foreach ($name in $expected.Keys | Sort-Object) {
    $path = Join-Path $Directory $name
    $exists = Test-Path -LiteralPath $path
    $actual = if ($exists) {
        (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash
    } else {
        $null
    }
    $items += [pscustomobject]@{
        file = $name
        exists = $exists
        expected_sha256 = $expected[$name]
        actual_sha256 = $actual
        matches = $exists -and ($actual -eq $expected[$name])
    }
}

$result = [pscustomobject]@{
    directory = (Resolve-Path -LiteralPath $Directory).Path
    all_match = @($items | Where-Object { -not $_.matches }).Count -eq 0
    files = $items
}

New-Item -ItemType Directory -Path (Split-Path $Output -Parent) -Force | Out-Null
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Output -Encoding UTF8
$result | Select-Object directory,all_match | Format-List
$items | Select-Object file,exists,matches | Format-Table -AutoSize

if (-not $result.all_match) {
    exit 1
}
