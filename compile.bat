@echo off
echo [*] Setting RUSTFLAGS...

set RUSTFLAGS=-C target-cpu=native -C opt-level=3 -C codegen-units=1 -C panic=abort -C target-feature=+crt-static


echo [*] Building with cargo release profile...
cargo build --release

IF ERRORLEVEL 1 (
    echo [!] Build failed.
    pause
    exit /b
)

echo [*] Build successful!
echo [*] Output binary:
echo     target\release\pokio_miner.exe
pause
