# UBLP SP1 Circuit — ELF Derleme
# Çalıştır: pwsh sp1-circuit/build.ps1 (UBLP kök dizininden)
#
# Gereksinimler:
#   1. Rust kurulu (rustup.rs)
#   2. SP1 toolchain: cargo install sp1 veya rustup toolchain install succinct
#   3. Succinct RISC-V target:
#      rustup target add riscv32im-succinct-zkvm-elf --toolchain succinct

param(
    [switch]$Release = $true
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

Write-Host "[SP1 Build] RISC-V target kontrol ediliyor..."
rustup target add riscv32im-succinct-zkvm-elf --toolchain succinct 2>$null

Write-Host "[SP1 Build] Circuit derleniyor (cargo prove build)..."
cargo prove build

if ($LASTEXITCODE -eq 0) {
    $elfPath = Join-Path $scriptDir "elf\ublp-verifier"
    if (Test-Path $elfPath) {
        $size = (Get-Item $elfPath).Length / 1KB
        Write-Host "[SP1 Build] ✓ ELF hazır: $elfPath ($([math]::Round($size, 1)) KB)"
        Write-Host "[SP1 Build] SP1_ELF_PATH ortam değişkenine gerek yok — varsayılan yol kullanılır."
    } else {
        Write-Warning "[SP1 Build] ELF dosyası beklenen konumda yok: $elfPath"
        Write-Warning "cargo prove build çıktısını kontrol edin."
    }
} else {
    Write-Error "[SP1 Build] ✗ Derleme başarısız."
    exit 1
}
