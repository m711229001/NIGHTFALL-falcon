@echo off
REM Falcon MAG Framework - AI-Enhanced Scan

if "%~1"=="" (
    echo Usage: scan.bat TARGET_URL [IMAGE_TAG]
    echo Example: scan.bat https://example.com
    echo Example: scan.bat https://example.com v2
    exit /b 1
)

set TARGET=%~1
set IMAGE=%~2
if "%IMAGE%"=="" set IMAGE=v3

echo ═══════════════════════════════════════════
echo   🦅 Falcon MAG Framework - AI Scan
echo ═══════════════════════════════════════════
echo   Target: %TARGET%
echo   Image:  falcon-mag-framework:%IMAGE%
echo   AI:     Enabled (DeepSeek)
echo ═══════════════════════════════════════════
echo.

docker run --rm ^
    -v "%cd%/output:/app/output" ^
    -e "DEEPSEEK_API_KEY=%DEEPSEEK_API_KEY%" ^
    falcon-mag-framework:%IMAGE% scan "%TARGET%" --all

echo.
echo Reports saved in: %cd%\output
echo.