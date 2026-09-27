@echo off
rem Downloads a portable GCC toolchain (w64devkit) into .\tools.
rem Nothing is installed system-wide and PATH is not modified.
setlocal
set "ROOT=%~dp0"
set "TOOLS=%ROOT%tools"
set "VER=2.10.0"
set "URL=https://github.com/skeeto/w64devkit/releases/download/v%VER%/w64devkit-x64-%VER%.7z.exe"

if exist "%TOOLS%\w64devkit\bin\g++.exe" (
    echo Toolchain already present in "%TOOLS%\w64devkit".
    exit /b 0
)

if not exist "%TOOLS%" mkdir "%TOOLS%"
echo Downloading w64devkit %VER% ...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol='Tls12'; Invoke-WebRequest -Uri '%URL%' -OutFile '%TOOLS%\w64devkit.7z.exe'"
if errorlevel 1 ( echo Download failed. & exit /b 1 )

echo Extracting ...
"%TOOLS%\w64devkit.7z.exe" -o"%TOOLS%" -y >nul
if errorlevel 1 ( echo Extraction failed. & exit /b 1 )
del "%TOOLS%\w64devkit.7z.exe"

echo Done. Run build.bat to compile.
